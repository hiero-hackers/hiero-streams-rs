//! The command-line tool — the library packaged as a distributable
//! trust utility. This module is the CLI's whole implementation
//! (dispatch, the `cmd_*` handlers, and the argument helpers); `main.rs`
//! is just a thin entry point that calls [`run`]. Everything here is
//! bin-only and separate from the library crate.
//!
//! Argument parsing is hand-rolled to keep the dependency surface of a
//! verification tool minimal.

// The networked commands — quarantined behind `fetch`.
#[cfg(feature = "fetch")]
mod attest;
#[cfg(feature = "etl")]
mod etl;
#[cfg(feature = "fetch")]
mod sentinel;

use hiero_streams::{
    parse_address_book, parse_record_file, parse_signature_file, record_file_hash,
    verify_node_signature,
};
use serde_json::json;
use std::process::ExitCode;

/// Dispatch a parsed argument vector to the matching command; unknown or
/// incomplete invocations print usage. Errors are printed and mapped to a
/// failure exit code — exit codes are the tool's contract.
pub fn run(args: Vec<String>) -> ExitCode {
    let result = match (args.first().map(String::as_str), args.get(1)) {
        (Some("parse"), Some(path)) => cmd_parse(path),
        (Some("verify"), Some(_)) => cmd_verify(&args[1..]),
        (Some("block-activity"), Some(_)) => cmd_block_activity(&args[1..]),
        (Some("chain-info"), Some(_)) => cmd_chain_info(&args[1..]),
        #[cfg(feature = "fetch")]
        (Some("attest"), Some(_)) => attest::run(&args[1..]),
        #[cfg(feature = "fetch")]
        (Some("sentinel"), _) => sentinel::run(&args[1..]),
        #[cfg(feature = "etl")]
        (Some("etl"), Some(_)) => etl::run(&args[1..]),
        _ => return usage(),
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn usage() -> ExitCode {
    eprintln!(
        "usage:\n  hiero-streams parse <file.rcd[.gz] | file.blk[.gz]>\n  hiero-streams verify <file.rcd[.gz]> <file.rcd_sig> \\\n      (--address-book <book.bin> --node <0.0.N> | --public-key <hexDER>)\n  hiero-streams verify <file.blk[.gz]> [--bootstrap <genesis.blk[.gz]>]\n  hiero-streams block-activity <file.blk[.gz]>...\n  hiero-streams chain-info <file.blk[.gz]>... [--check-hints]\n  hiero-streams attest <file.rcd[.gz]> --project <gcp-project>\n  hiero-streams sentinel [--project <gcp-project>] [--init-block N] \\\n      [--state <file>] [--max-blocks N] [--local-dir <dir>]\n  hiero-streams etl --dir <in> --out <dataset> [--transfers] [--verify-chain] [--threads N]"
    );
    ExitCode::from(2)
}

/// `--name value` lookup over the raw arg list. Crate-visible so the
/// `attest` and `etl` submodules share it.
pub(crate) fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

fn cmd_parse(path: &str) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path)?;
    let value = match hiero_streams::detect_format(&bytes)? {
        hiero_streams::Format::BlockStream => {
            let block = hiero_streams::parse_block(&bytes)?;
            hiero_streams::block_to_json_value(&block)
        }
        _ => hiero_streams::record_file_to_json_value(&parse_record_file(&bytes)?),
    };
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(ExitCode::SUCCESS)
}

fn cmd_verify(args: &[String]) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let Some(stream_path) = args.first() else {
        return Ok(usage());
    };
    let stream_bytes = std::fs::read(stream_path)?;
    // Era dispatch, same as `parse`: block streams carry their proof
    // in-band (no signature file, nothing to fetch — that model stays
    // v6-only), record files verify against a node's .rcd_sig.
    if matches!(
        hiero_streams::detect_format(&stream_bytes)?,
        hiero_streams::Format::BlockStream
    ) {
        #[cfg(feature = "block-proofs")]
        return cmd_verify_block(&stream_bytes, args);
        #[cfg(not(feature = "block-proofs"))]
        return Err(
            "this is a block-stream file; its proof is verified in-band — \
                    rebuild with `--features block-proofs`"
                .into(),
        );
    }
    let Some(sig_path) = args.get(1) else {
        return Ok(usage());
    };
    let public_key = match flag(args, "--public-key") {
        Some(key) => key,
        None => {
            let (Some(book_path), Some(node)) =
                (flag(args, "--address-book"), flag(args, "--node"))
            else {
                return Ok(usage());
            };
            let book = parse_address_book(&std::fs::read(book_path)?)?;
            match book.get(&node) {
                Some(key) => key.clone(),
                None => {
                    eprintln!("node {node} not present in the address book");
                    return Ok(ExitCode::FAILURE);
                }
            }
        }
    };

    let hash = record_file_hash(&stream_bytes)?;
    let sig = parse_signature_file(&std::fs::read(sig_path)?)?;
    let hash_matches_claim = sig.file_hash == hash;
    let valid = verify_node_signature(&hash, &sig.file_signature, &public_key)?;

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "fileHash": hex::encode(hash),
            "hashMatchesSignatureFileClaim": hash_matches_claim,
            "signatureValid": valid,
            "note": if valid {
                "this node signed exactly these bytes; network attestation \
                 requires >= 1/3 of the address book (fetch more nodes' \
                 .rcd_sig files)"
            } else {
                "signature INVALID for the locally computed hash"
            },
        }))?
    );
    Ok(if valid {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// `chain-info` — the continuity view of block files, one JSON line
/// each: block number, recomputed root, the footer's previous-root
/// claim, the proof layout, and whether the block carries the
/// ledger-ID publication. `--check-hints` additionally verifies the
/// hinTS threshold signature against the proof's own carried key
/// (no bootstrap needed) and fails the exit code if a TSS block's
/// signature does not verify. Blocks on a pre-TSS/unknown layout are
/// reported (`proofPath`, `signatureBytes`) but NOT counted as hints
/// failures — inapplicable is not failed; the layout fields are the
/// drift tripwire that announces TSS's arrival. This is the sentinel's
/// primitive: piped per-file output for scripted monitoring.
fn cmd_chain_info(args: &[String]) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let check_hints = args.iter().any(|a| a == "--check-hints");
    #[cfg(not(feature = "block-proofs"))]
    if check_hints {
        return Err("--check-hints verifies the hinTS threshold signature — \
                    rebuild with `--features block-proofs`"
            .into());
    }
    let files: Vec<&String> = args.iter().filter(|a| !a.starts_with("--")).collect();
    if files.is_empty() {
        return Ok(usage());
    }
    // Only ever mutated on the block-proofs hints path.
    #[cfg_attr(not(feature = "block-proofs"), allow(unused_mut))]
    let mut all_ok = true;
    for path in files {
        let bytes = std::fs::read(path)?;
        let material =
            hiero_streams::extract_proof_material(&bytes).map_err(|e| format!("{path}: {e}"))?;
        let is_tss = matches!(
            material.layout.path,
            hiero_streams::ProofPath::AggregateSchnorr
                | hiero_streams::ProofPath::WrapsCompressedProof
        );
        let proof_path = match material.layout.path {
            hiero_streams::ProofPath::AggregateSchnorr => "aggregateSchnorr",
            hiero_streams::ProofPath::WrapsCompressedProof => "wraps",
            _ => "unknown",
        };
        let signature_bytes = material.layout.hints_verification_key.len()
            + material.layout.hints_signature.len()
            + material.layout.suffix.len();
        #[cfg_attr(not(feature = "block-proofs"), allow(unused_mut))]
        let mut line = json!({
            "file": path,
            "blockNumber": material.block_number.to_string(),
            "blockRoot": hex::encode(material.block_root),
            "previousBlockRoot": hex::encode(&material.previous_block_root),
            "proofPath": proof_path,
            "signatureBytes": signature_bytes,
            "hasBootstrap": material.bootstrap.is_some(),
        });
        #[cfg(feature = "block-proofs")]
        if check_hints && is_tss {
            let passed = hiero_streams::verify_hints(&material.layout, &material.block_root)
                .map(|h| h.all_passed())
                .unwrap_or(false);
            all_ok &= passed;
            line["hintsAllPassed"] = json!(passed);
        }
        #[cfg(not(feature = "block-proofs"))]
        let _ = is_tss;
        println!("{line}");
    }
    Ok(if all_ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// Per-block node liveness from gossip-event creators. One JSON object
/// per file (an array when given several files, e.g. a shell glob).
fn cmd_block_activity(paths: &[String]) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let mut reports = Vec::with_capacity(paths.len());
    for path in paths {
        let bytes = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
        if !matches!(
            hiero_streams::detect_format(&bytes)?,
            hiero_streams::Format::BlockStream
        ) {
            return Err(format!("{path}: not a block-stream file").into());
        }
        let activity = hiero_streams::block_activity(&bytes).map_err(|e| format!("{path}: {e}"))?;
        reports.push(json!({
            "blockNumber": activity.block_number,
            "rounds": activity.rounds,
            "totalEvents": activity.total_events(),
            "activeNodeCount": activity.events_by_node.len(),
            "eventsByNode": activity
                .events_by_node
                .iter()
                .map(|(node, events)| (node.to_string(), serde_json::Value::from(*events)))
                .collect::<serde_json::Map<_, _>>(),
        }));
    }
    let value = if reports.len() == 1 {
        reports.remove(0)
    } else {
        serde_json::Value::Array(reports)
    };
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(ExitCode::SUCCESS)
}

/// Block-era `verify`: everything needed is in the file (and, for
/// non-genesis blocks, the genesis file passed via `--bootstrap`).
/// Output mirrors the per-check shape of the differential golden
/// reports; exits 0 only when every applicable check passed.
#[cfg(feature = "block-proofs")]
fn cmd_verify_block(
    stream_bytes: &[u8],
    args: &[String],
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    use hiero_streams::{extract_proof_material, resolve_bootstrap, verify_block_proof};

    let material = extract_proof_material(stream_bytes)?;
    let genesis_bytes = match flag(args, "--bootstrap") {
        Some(path) => Some(std::fs::read(&path).map_err(|e| format!("{path}: {e}"))?),
        None => None,
    };
    let bootstrap = resolve_bootstrap(
        &material,
        genesis_bytes.as_deref(),
        "pass --bootstrap <genesis.blk[.gz]>",
    )?;

    let verification = verify_block_proof(&material, &bootstrap)?;
    let valid = verification.valid();
    println!(
        "{}",
        serde_json::to_string_pretty(&hiero_streams::block_proof_to_json_value(
            &material,
            &bootstrap.ledger_id,
            &verification,
        ))?
    );
    Ok(if valid {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}
