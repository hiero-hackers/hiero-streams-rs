//! `sentinel` — continuous verification of the live mainnet preview
//! block stream. Each run resumes at the state file's last verified
//! block, fetches everything newer (capped), and holds every block to:
//!
//! 1. **gapless numbering** — a missing object is a failure;
//! 2. **root-chain continuity** — the footer's previous-root claim must
//!    equal the recomputed root of the prior block, including the seam
//!    with the previous run's final block;
//! 3. **hinTS threshold signatures** — enforced automatically the
//!    moment blocks carry TSS proofs (today's preview is the 48-byte
//!    pre-TSS placeholder: inapplicable, not failing);
//! 4. **format stability** — any proof-layout drift, or a ledger-ID
//!    publication appearing, fails LOUDLY: those are the cutover
//!    moments this command exists to catch. After reacting (see
//!    docs/MIGRATION.md §6-7), update the state file and re-run.
//!
//! State advances through the last verified block even on a loud
//! failure — verified work is never repeated; unverified work is.
//!
//! GCS is requester-pays (`--project` or `GCS_USER_PROJECT`); auth from
//! `$GCS_OAUTH_TOKEN` or `gcloud`. `--local-dir` is the offline test
//! mode (numeric `.blk.gz` names), used by this module's own tests.

use hiero_streams::extract_proof_material;
use serde_json::json;
use std::process::ExitCode;

const OBJECTS: &str = "https://storage.googleapis.com/storage/v1/b/hedera-mainnet-streams/o";
const PREFIX: &str = "block-preview/mainnet/0/0";
const DEFAULT_MAX_BLOCKS: u64 = 25_000;
/// Parallel object fetches per batch (the etl threading pattern).
const FETCH_BATCH: u64 = 32;

type Error = Box<dyn std::error::Error>;

/// The state file's fields, hand-mapped over `serde_json::Value` —
/// nine fields do not justify a serde-derive dependency (the crate's
/// frugality policy; serde_json is already here).
struct State {
    comment: String,
    initialized: bool,
    last_block: Option<u64>,
    last_root: Option<String>,
    proof_path: Option<String>,
    signature_bytes: Option<usize>,
    verified_total: Option<u64>,
    since: Option<String>,
    checked: Option<String>,
}

impl State {
    fn load(path: &str) -> Result<Self, Error> {
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path)?)?;
        Ok(State {
            comment: v["_comment"].as_str().unwrap_or_default().to_string(),
            initialized: v["initialized"].as_bool().unwrap_or(false),
            last_block: v["lastBlock"].as_u64(),
            last_root: v["lastRoot"].as_str().map(String::from),
            proof_path: v["proofPath"].as_str().map(String::from),
            signature_bytes: v["signatureBytes"].as_u64().map(|n| n as usize),
            verified_total: v["verifiedTotal"].as_u64(),
            since: v["since"].as_str().map(String::from),
            checked: v["checked"].as_str().map(String::from),
        })
    }

    fn save(&self, path: &str) -> Result<(), Error> {
        let v = json!({
            "_comment": self.comment,
            "initialized": self.initialized,
            "lastBlock": self.last_block,
            "lastRoot": self.last_root,
            "proofPath": self.proof_path,
            "signatureBytes": self.signature_bytes,
            "verifiedTotal": self.verified_total,
            "since": self.since,
            "checked": self.checked,
        });
        std::fs::write(path, serde_json::to_string_pretty(&v)? + "\n")?;
        Ok(())
    }
}

/// Where blocks come from: the live bucket, or a directory of numeric
/// `.blk.gz` files for offline tests.
enum Source {
    Gcs { project: String, token: String },
    Local(String),
}

impl Source {
    fn exists(&self, n: u64) -> Result<bool, Error> {
        match self {
            Source::Local(dir) => Ok(std::path::Path::new(&format!("{dir}/{n}.blk.gz")).exists()),
            Source::Gcs { project, token } => {
                // Metadata GET (no alt=media): cheap existence probe.
                match ureq::get(&object_url(n, project, false))
                    .set("Authorization", &format!("Bearer {token}"))
                    .call()
                {
                    Ok(_) => Ok(true),
                    Err(ureq::Error::Status(404, _)) => Ok(false),
                    Err(e) => Err(format!("probe for block {n} failed: {e}").into()),
                }
            }
        }
    }

    /// String errors so fetches can run on worker threads (the etl
    /// pattern — `Box<dyn Error>` is not `Send`).
    fn fetch(&self, n: u64) -> Result<Vec<u8>, String> {
        match self {
            Source::Local(dir) => std::fs::read(format!("{dir}/{n}.blk.gz"))
                .map_err(|e| format!("gap: block {n} missing from {dir} ({e})")),
            Source::Gcs { project, token } => {
                let response = ureq::get(&object_url(n, project, true))
                    .set("Authorization", &format!("Bearer {token}"))
                    .call()
                    .map_err(|e| format!("gap: fetching block {n} failed ({e})"))?;
                let mut bytes = Vec::new();
                std::io::Read::read_to_end(&mut response.into_reader(), &mut bytes)
                    .map_err(|e| format!("gap: reading block {n} failed ({e})"))?;
                Ok(bytes)
            }
        }
    }

    /// Newest available block: local = max numeric name; GCS = expanding
    /// probe + binary search from `floor` (never a bucket listing — a
    /// handful of existence probes instead of paging millions of names).
    fn newest(&self, floor: u64) -> Result<u64, Error> {
        match self {
            Source::Local(dir) => std::fs::read_dir(dir)?
                .filter_map(|e| e.ok()?.file_name().into_string().ok())
                .filter_map(|name| name.strip_suffix(".blk.gz")?.parse::<u64>().ok())
                .max()
                .ok_or_else(|| "no .blk.gz files in --local-dir".into()),
            Source::Gcs { .. } => {
                if !self.exists(floor)? {
                    return Err(format!(
                        "block {floor} (search floor) is missing from the bucket — \
                         retention passed us, or the layout moved"
                    )
                    .into());
                }
                let (mut lo, mut step) = (floor, 1024u64);
                let mut hi = lo + step;
                while self.exists(hi)? {
                    lo = hi;
                    step *= 4;
                    hi = lo + step;
                }
                while hi - lo > 1 {
                    let mid = lo + (hi - lo) / 2;
                    if self.exists(mid)? {
                        lo = mid;
                    } else {
                        hi = mid;
                    }
                }
                Ok(lo)
            }
        }
    }
}

fn object_url(n: u64, project: &str, media: bool) -> String {
    // Only `/` needs escaping in these fixed-alphabet names.
    let object = format!("{PREFIX}/{n:036}.blk.gz").replace('/', "%2F");
    let alt = if media { "alt=media&" } else { "" };
    format!("{OBJECTS}/{object}?{alt}userProject={project}")
}

fn token() -> Result<String, Error> {
    if let Ok(t) = std::env::var("GCS_OAUTH_TOKEN") {
        return Ok(t);
    }
    let out = std::process::Command::new("gcloud")
        .args(["auth", "print-access-token"])
        .output()?;
    if !out.status.success() {
        return Err("gcloud auth print-access-token failed (set GCS_OAUTH_TOKEN?)".into());
    }
    Ok(String::from_utf8(out.stdout)?.trim().to_string())
}

/// UTC now as (YYYY-MM-DD, full timestamp) via the crate's own day
/// math — no date dependency for two strings.
fn utc_now() -> (String, String) {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock before 1970")
        .as_secs();
    let day = hiero_streams::day_of(&format!("{secs}.000000000"));
    let (h, m, s) = (secs / 3600 % 24, secs / 60 % 60, secs % 60);
    (day.clone(), format!("{day}T{h:02}:{m:02}:{s:02}Z"))
}

pub fn run(args: &[String]) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let state_path =
        super::flag(args, "--state").unwrap_or_else(|| "docs/sentinel-state.json".to_string());
    let max_blocks: u64 = super::flag(args, "--max-blocks")
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MAX_BLOCKS);
    let init_block: Option<u64> = super::flag(args, "--init-block").and_then(|v| v.parse().ok());

    let source = match super::flag(args, "--local-dir") {
        Some(dir) => Source::Local(dir),
        None => {
            let project = super::flag(args, "--project")
                .or_else(|| std::env::var("GCS_USER_PROJECT").ok())
                .ok_or("GCS is requester-pays: pass --project or set GCS_USER_PROJECT")?;
            Source::Gcs {
                project,
                token: token()?,
            }
        }
    };

    let mut state = State::load(&state_path)?;

    // ── window ───────────────────────────────────────────────────────
    // `floor` is a block known to exist (the search anchor); `from` is
    // the first block to verify. Kept separate so --init-block 0 never
    // computes "init minus one" (u64).
    let (floor, from) = if state.initialized {
        let last = state
            .last_block
            .ok_or("initialized state has no lastBlock")?;
        (last, last + 1)
    } else {
        let init =
            init_block.ok_or("first run needs --init-block (see workflow_dispatch input)")?;
        (init, init)
    };
    let newest = source.newest(floor)?;
    if newest < from {
        eprintln!("caught up at {} (newest={newest})", from - 1);
        return Ok(ExitCode::SUCCESS);
    }
    let mut to = newest;
    if to - from + 1 > max_blocks {
        to = from + max_blocks - 1;
        eprintln!(
            "warning: sentinel is {} blocks behind; verifying {from}..{to} this run \
             (no blocks skipped — the remainder is next run's window)",
            newest - from + 1
        );
    }
    eprintln!(
        "verifying blocks {from}..{to} ({} blocks, newest={newest})",
        to - from + 1
    );

    // ── verify, batch-fetching in parallel, checking in order ────────
    let mut verified: u64 = 0;
    let mut outcome: Result<(), Error> = Ok(());
    'outer: for batch_start in (from..=to).step_by(FETCH_BATCH as usize) {
        let batch_end = (batch_start + FETCH_BATCH - 1).min(to);
        let fetched: Vec<Result<Vec<u8>, String>> = std::thread::scope(|s| {
            (batch_start..=batch_end)
                .map(|n| {
                    let source = &source;
                    s.spawn(move || source.fetch(n))
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|h| h.join().expect("fetch worker panicked"))
                .collect()
        });
        for (offset, bytes) in fetched.into_iter().enumerate() {
            let n = batch_start + offset as u64;
            // A fetch error (gap) and a check error both stop the run,
            // but never skip the state persist below.
            let check = match bytes {
                Ok(bytes) => check_block(n, &bytes, &mut state),
                Err(e) => Err(e.into()),
            };
            if let Err(e) = check {
                outcome = Err(e);
                break 'outer;
            }
            verified += 1;
        }
    }

    // ── persist — verified work survives a loud failure ──────────────
    let (today, now) = utc_now();
    if verified > 0 {
        state.initialized = true;
        state.verified_total = Some(state.verified_total.unwrap_or(0) + verified);
        state.since.get_or_insert(today);
    }
    state.checked = Some(now);
    state.save(&state_path)?;

    outcome?;
    eprintln!(
        "verified {verified} block(s): {from}..{} · chain ✓ · proofPath={}({}B) · total since {}: {}",
        from + verified - 1,
        state.proof_path.as_deref().unwrap_or("?"),
        state.signature_bytes.unwrap_or(0),
        state.since.as_deref().unwrap_or("?"),
        state.verified_total.unwrap_or(0),
    );
    Ok(ExitCode::SUCCESS)
}

/// Hold one block to the four sentinel invariants, advancing `state`
/// through it when it passes.
fn check_block(n: u64, bytes: &[u8], state: &mut State) -> Result<(), Error> {
    let material = extract_proof_material(bytes).map_err(|e| format!("block {n}: {e}"))?;
    if material.block_number != n {
        return Err(format!(
            "sequence break: object named {n} carries block number {}",
            material.block_number
        )
        .into());
    }
    let root = hex::encode(material.block_root);
    let prev_claim = hex::encode(&material.previous_block_root);
    if let Some(prev_root) = &state.last_root {
        if &prev_claim != prev_root {
            return Err(format!(
                "root-chain break at block {n}: footer claims {prev_claim}, \
                 recomputed prior root is {prev_root}"
            )
            .into());
        }
    }

    let (path, is_tss) = match material.layout.path {
        hiero_streams::ProofPath::AggregateSchnorr => ("aggregateSchnorr", true),
        hiero_streams::ProofPath::WrapsCompressedProof => ("wraps", true),
        _ => ("unknown", false),
    };
    let sig_bytes = material.layout.hints_verification_key.len()
        + material.layout.hints_signature.len()
        + material.layout.suffix.len();
    if let Some(known) = &state.proof_path {
        if known != path {
            return Err(format!(
                "PROOF FORMAT CHANGED at block {n}: {known} → {path} ({} → {sig_bytes} \
                 signature bytes). If this is the TSS cutover, react per \
                 docs/MIGRATION.md §6-7, update the state file, and re-run.",
                state.signature_bytes.unwrap_or(0)
            )
            .into());
        }
    }
    if let Some(known) = state.signature_bytes {
        if known != sig_bytes {
            return Err(format!(
                "SIGNATURE LAYOUT CHANGED at block {n}: {known} → {sig_bytes} bytes. \
                 React per docs/MIGRATION.md §6-7, update the state file, and re-run."
            )
            .into());
        }
    }
    if material.bootstrap.is_some() {
        return Err(format!(
            "LEDGER-ID PUBLICATION FOUND in block {n} — the bootstrap anchor for full \
             proof verification. Vendor this block, wire it as --bootstrap, update the \
             state file."
        )
        .into());
    }

    if is_tss {
        #[cfg(feature = "block-proofs")]
        {
            let passed = hiero_streams::verify_hints(&material.layout, &material.block_root)
                .map(|h| h.all_passed())
                .unwrap_or(false);
            if !passed {
                return Err(format!(
                    "hinTS threshold signature INVALID at block {n} — a TSS proof that \
                     does not verify is the loudest possible alarm"
                )
                .into());
            }
        }
        #[cfg(not(feature = "block-proofs"))]
        return Err(format!(
            "block {n} carries a TSS proof but this binary was built without \
             `--features block-proofs` — rebuild so the sentinel verifies it"
        )
        .into());
    }

    state.last_block = Some(n);
    state.last_root = Some(root);
    state.proof_path = Some(path.to_string());
    state.signature_bytes = Some(sig_bytes);
    Ok(())
}

// The suite exercises TSS fixtures end to end, so it needs the proof
// stack: `cargo test --features block-proofs` (CI's third config).
// Under the default build a TSS block correctly fails loudly instead.
#[cfg(all(test, feature = "block-proofs"))]
mod tests {
    use super::*;

    fn fixture_dir(tag: &str, blocks: &[u64]) -> String {
        let dir = std::env::temp_dir().join(format!("sentinel-test-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for n in blocks {
            std::fs::copy(
                format!(
                    "{}/tests/fixtures/tss/{n}.blk.gz",
                    env!("CARGO_MANIFEST_DIR")
                ),
                dir.join(format!("{n}.blk.gz")),
            )
            .unwrap();
        }
        dir.to_str().unwrap().to_string()
    }

    fn fresh_state(dir: &str) -> String {
        let path = format!("{dir}/state.json");
        std::fs::copy(
            format!("{}/docs/sentinel-state.json", env!("CARGO_MANIFEST_DIR")),
            &path,
        )
        .unwrap();
        path
    }

    fn run_sentinel(dir: &str, state: &str, extra: &[&str]) -> Result<ExitCode, Error> {
        let mut args: Vec<String> = vec![
            "--local-dir".into(),
            dir.into(),
            "--state".into(),
            state.into(),
        ];
        args.extend(extra.iter().map(|s| s.to_string()));
        run(&args)
    }

    fn state_of(path: &str) -> State {
        State::load(path).unwrap()
    }

    #[test]
    fn verifies_a_window_then_reports_caught_up() {
        let dir = fixture_dir("ok", &[1, 2, 3, 4]);
        let state_path = fresh_state(&dir);
        run_sentinel(&dir, &state_path, &["--init-block", "1"]).expect("first run verifies");
        let state = state_of(&state_path);
        assert_eq!(state.last_block, Some(4));
        assert_eq!(state.verified_total, Some(4));
        assert_eq!(state.proof_path.as_deref(), Some("aggregateSchnorr"));
        assert_eq!(state.signature_bytes, Some(2920));
        // Second run: nothing new, state untouched.
        run_sentinel(&dir, &state_path, &[]).expect("caught up");
        assert_eq!(state_of(&state_path).verified_total, Some(4));
    }

    #[test]
    fn a_numbering_gap_fails_without_advancing_past_it() {
        let dir = fixture_dir("gap", &[1, 2, 4]);
        let state_path = fresh_state(&dir);
        let err = run_sentinel(&dir, &state_path, &["--init-block", "1"])
            .expect_err("gap must fail")
            .to_string();
        assert!(err.contains("gap"), "{err}");
        // Blocks 1-2 stay verified; the gap is next run's first problem.
        assert_eq!(state_of(&state_path).last_block, Some(2));
    }

    #[test]
    fn a_bootstrap_publication_is_announced_loudly() {
        // tss block 0 carries the ledger-ID publication.
        let dir = fixture_dir("bootstrap", &[0, 1]);
        let state_path = fresh_state(&dir);
        let err = run_sentinel(&dir, &state_path, &["--init-block", "0"])
            .expect_err("publication must fail loudly")
            .to_string();
        assert!(err.contains("LEDGER-ID PUBLICATION"), "{err}");
    }

    #[test]
    fn proof_format_drift_is_announced_loudly() {
        let dir = fixture_dir("drift", &[1, 2]);
        let state_path = fresh_state(&dir);
        // Pretend the chain has been on the pre-TSS placeholder — the
        // schnorr fixtures then read as a format change.
        let mut state = state_of(&state_path);
        state.initialized = true;
        state.last_block = Some(0);
        state.proof_path = Some("unknown".into());
        state.signature_bytes = Some(48);
        state.save(&state_path).unwrap();
        let err = run_sentinel(&dir, &state_path, &[])
            .expect_err("drift must fail loudly")
            .to_string();
        assert!(err.contains("PROOF FORMAT CHANGED"), "{err}");
    }
}
