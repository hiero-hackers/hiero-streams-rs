# hiero-streams (Rust)

Parse and cryptographically verify Hedera **record stream files** — the
signed consensus output every mainnet node publishes — **both eras**:
v6 record files (mid-2022 onward) and HIP-1056 block streams. A
dependency-light, no-GC Rust crate and a zero-runtime CLI.

**Why trust another parser? The network is the reference.** Correctness
here is not "our tests pass" — every claim is anchored to something the
network itself signed or an independent implementation computed:

- **The network attests the parse.** For v6, the consensus nodes'
  signed metadata hashes reproduce from this parser's *own extracted
  fields* — if the parse were wrong, the RSA signatures wouldn't
  verify. (`verify`, `attest`, and the offline tests all run this.)
- **Window-exhaustive mirror differential.** Every transaction in every
  committed mainnet fixture window is compared field-for-field against
  the mirror node's independent decoding of the same files — this
  caught a real post-release response code (527) the vendored protos
  didn't know yet.
- **Check-for-check proof-path agreement — across independent crypto
  stacks.** Block-era proof verification (hinTS BLS threshold,
  aggregate Schnorr, WRAPS Groth16+KZG) is differentially tested
  against
  [`hiero-block-verifier-js`](https://github.com/hiero-hackers/hiero-block-verifier-js)
  over `hiero-block-node` fixtures — every individual check, not just
  the verdict, must agree (`tests/block_proof_differential.rs`). The
  divergence is deliberate: the JS verifier is built on pure-JS
  `@noble/curves`, this crate on arkworks — two unrelated curve
  implementations in two languages deriving identical pairings,
  transcripts, and verdicts over the same bytes. Agreement between
  shared-dependency implementations would prove far less.
- **Continuity is proven, not assumed.** The v6 running-hash chain and
  the block-era root chain (recomputed merkle root == next footer's
  claim) are asserted across every consecutive fixture pair and during
  every `etl --verify-chain` run.
- **Committed snapshots pin the output contract** so the canonical JSON
  shape cannot drift silently.

The CLI:

```
hiero-streams etl --dir downloaded/ --out data --transfers --verify-chain
    # threaded backfill: record files → day-partitioned Parquet with a
    # stable, contract-tested schema.
    # --verify-chain asserts the running-hash chain within and across
    # day boundaries as it transforms — the backfill is provably
    # gapless and un-reordered by construction, or it exits non-zero
    # naming the exact file where the chain breaks
hiero-streams parse file.rcd.gz          # or file.blk.gz — format auto-detected
hiero-streams verify file.rcd.gz file.rcd_sig \
    --address-book book.bin --node 0.0.3    # exit 0 only when valid
hiero-streams verify file.blk.gz --bootstrap genesis.blk.gz
    # block era (build with --features block-proofs): verifies the
    # in-band proof — recomputed merkle root, hinTS threshold
    # signature, Schnorr/WRAPS suffix — no signature file to fetch.
    # --bootstrap is the genesis block carrying the ledger-ID
    # publication; genesis verifies with no flag
hiero-streams block-activity file.blk.gz
    # per-block node liveness: which consensus nodes authored gossip
    # events in the block — a signal the record era never exposed
hiero-streams attest file.rcd.gz --project <gcp-project>
    # fetches every node's signature + the live address book;
    # exit 0 only when >= 1/3 of the network signed these bytes
```

```rust
use hiero_streams::{parse_record_file, verify_record_file, parse_address_book};

let file = parse_record_file(&bytes)?; // .rcd.gz or .rcd, as-is
for tx in &file.transactions {
    // consensus_timestamp, payer, tx_type, result, charged_fee_tinybar,
    // transfers (every HBAR leg), token_transfers
}

let book = parse_address_book(&address_book_bytes)?;
let result = verify_record_file(&bytes, &signatures, &book)?;
result.attested; // >= 1/3 of the address book signed this exact file
```

## Who this is for

The record streams are the network's **raw, signed output** — mirror
nodes, explorers, and dashboards are all *derived* from them. Reach
for this crate when you need that ground truth directly:

- **Indexers & analytics at bulk-history scale.** The public mirror
  REST API serves ~100 rows per page behind rate limits; the streams
  are the firehose. Parse a full mainnet day (~43k files, ~300k
  transactions) in under a second and feed your own store — no API
  keys, no rate limits, no intermediary.
- **Auditors, exchanges, custodians.** "Prove this transaction
  happened" should not mean "an API said so." `verify_record_file`
  turns a record file + signature files + the address book into a
  cryptographic attestation that ≥ ⅓ of the network signed these
  exact bytes. The CLI makes that a single static binary an auditor
  can run with zero runtime installed — for both eras: `verify` checks
  a block stream's in-band proof the same way it checks a record
  file's node signature.
- **Checking derived data against ground truth.** Mirror nodes can be
  wrong (we have found real discrepancies). When a balance, fee total,
  or supply figure looks off, the streams are what you reconcile
  against.
- **The block-stream future, already here.** Hedera is cutting over
  from record files to block streams (HIP-1056); at the network's
  10k-TPS design target, a no-GC parser stops being a nicety. This
  crate already parses and proof-verifies the new format behind the
  same era-detecting API, validated against the mainnet preview.
- **The check on the block-node era itself.** HIP-1081 introduces a
  new class of intermediaries — independent (including commercial)
  block-node operators — and its trust model says consumers should
  trust *proofs*, not node reputation. That sentence only means
  something if independent proof verifiers exist: today there are
  exactly two, `hiero-block-verifier-js` and this crate, and they are
  differentially tested against each other. More hands between the
  network and you strengthens the case for verifying, not weakens it.
  And the v6 era never migrates: four years of history exist only as
  record files (even served as HIP-1193 wrapped blocks, the payload is
  v6 bytes) — auditing it requires a maintained v6 verifier, forever.

**Not the right tool** for ordinary application reads — use the mirror
REST API or a typed client for "get this account's balance." This is
infrastructure for infrastructure-builders.

## Why Rust?

1. **Throughput where it matters — measured honestly.** A full real
   mainnet day (2026-07-10, node 0.0.3: 43,140 record files, 307,991
   transactions; files preloaded, so this measures parsing, not disk;
   8-core machine, best of 5 runs):

   | Configuration | Full day | Throughput |
   | --- | --- | --- |
   | Rust, single thread | 2.61 s | 118k tx/s |
   | **Rust, 8 threads** | **0.37 s** | **834k tx/s** |
   | Rust via Node binding (JSON round-trip) | 6.31 s | 49k tx/s |

   A full day of consensus output — data that took 24 hours to
   produce — parses in about **a third of a second**. The structural
   edge is **parallelism** (7× here, near-linear on 8 cores — decisive
   for a multi-year backfill), no GC for long-running tails, and
   headroom for block-stream-era files carrying orders of magnitude
   more transactions each. The Node binding exists for
   **identical-output portability**, not speed — its JSON crossing
   costs more than the parse itself (reproduce with `cargo run
   --release --example parse_dir -- <dir>`).
2. **A zero-runtime distributable.** `hiero-streams verify` is a
   single static binary.
3. **One implementation, many languages.** Rust exposes C FFI, so
   Python/Go/JVM bindings can wrap this one audited core.
4. **Provably memory-safe on untrusted input.** The library is
   `#![forbid(unsafe_code)]` — a compile error for any `unsafe`
   anywhere in the crate, generated protobuf code included. For a tool
   whose whole job is decoding attacker-controlled bytes, "the
   parse/verify core contains no memory-unsafety" is a guarantee the
   compiler enforces, not a claim in a README.

## Integrating into your project

**From Rust** — use the crate directly (git dependency until the
crates.io release):

```toml
[dependencies]
hiero-streams = { git = "https://github.com/hiero-hackers/hiero-streams-rs" }
```

**From any other language** — shell out to the CLI; the contract is
JSON on stdout and the exit code. No library linkage needed:

```js
// Node.js
import { execFileSync } from "node:child_process";
const parsed = JSON.parse(
    execFileSync("hiero-streams", ["parse", "file.rcd.gz"]),
);
```

```python
# Python
import json, subprocess
r = subprocess.run(["hiero-streams", "verify", rcd, sig,
                    "--address-book", book, "--node", "0.0.3"],
                   capture_output=True, text=True)
attested_by_node = r.returncode == 0
verdict = json.loads(r.stdout)
```

The JSON shapes are stable — pinned by committed snapshot tests — so
consumers can build against them without tracking this crate's
internals.

**Native Node binding** — `bindings/node` (napi-rs) exposes
`parseRecordFileJson`, `parseBlockJson`, `verifyBlockProofJson`,
`recordFileHashHex`, and `verifyNodeSignature`, returning exactly the
golden-shape JSON every other surface produces — the binding's test
asserts its block-proof output is identical to the CLI's, both built
from one library serializer. Use it for one-audited-core portability;
for raw speed use the library natively (see the table above). PyO3 and
WASM remain on the roadmap.

## Requirements & Google Cloud setup

The library and offline verification need only **Rust 1.82+** (the
`rust-version` in `Cargo.toml`, enforced by CI) and **protoc**
(`brew install protobuf`). Anything touching the public
stream buckets (`attest`, downloads for `etl`) additionally needs a
Google Cloud project, because the buckets are **requester-pays** —
Google bills *your* project for reads; that is how the raw data stays
public without Hedera funding unbounded egress.

One-time setup (~10 minutes):

1. [console.cloud.google.com](https://console.cloud.google.com) → sign
   in → **New project** (any name; note the *project ID*).
2. **Billing** → attach a payment method. New accounts get ~$300 free
   credits, which comfortably cover everything in the cost table
   below.
3. Install and authenticate the CLI:

   ```
   brew install --cask google-cloud-sdk
   gcloud auth login
   gcloud config set project YOUR_PROJECT_ID
   ```

That's all — `attest` shells out to `gcloud auth print-access-token`
(or set `GCS_OAUTH_TOKEN`), and downloads use
`gcloud storage cp --billing-project=YOUR_PROJECT_ID`.

## Cost & time model — measured, with an honest era caveat

Two drivers scale differently, and conflating them is how estimates go
wrong (ours included, twice):

- **File count is constant**: one file per ~2 s, 43,200/day, ~64 M for
  the v6 era — *regardless of traffic*. This drives GET-operation cost
  (~$0.0004/1,000 → **~$26 for the whole v6 era**) and the
  latency-bound floor of download time.
- **File size scales with transactions**: measured ~600 bytes per
  transaction compressed. This drives egress (~$0.12/GB → **~$0.07 per
  million transactions**) and the bandwidth-bound part of download
  time.

Our measured anchor (mainnet hour 2026-07-04T00: 1,800 files, 8 MB,
3.8 tx/s) is a **quiet-era floor**. The v6 era includes the
2022–2024 high-TPS period (atma.io and other HCS-heavy applications
pushed sustained hundreds-to-thousands of tx/s), whose days are
10–100× larger than today's. Cost therefore depends on *total
transactions*, not days: at tens of billions of v6-era transactions,
expect **roughly 10–30 TB and $1,200–3,600 of egress** for the full
era — plus the fixed ~$26 of ops. Bounded windows stay cheap: a
modern day ~$0.04, a month ~$1; a 2023 peak day up to a few dollars.

**Time estimates** (measured on this machine, one process; the
quiet-era numbers are from a real 7-consecutive-day run, 2026-07-05 →
07-11, 302,211 files):

| Step | Measured | Extrapolation |
| --- | --- | --- |
| Download, quiet day (43,200 files, ~0.2 GB) | ~220 files/s sustained (latency-bound; 3–3.5 min/day over 7 straight days) | ~3.5 min |
| Download, heavy 2023 day (43,200 files, tens of GB) | bandwidth-bound | ~30–60 min at 30 MB/s |
| Download, full v6 era | both regimes | **~4 days–2 weeks** single machine (≈3.5-day latency floor at 220 files/s + the bandwidth-bound heavy era); parallelize by date range to cut linearly |
| Parse/transform (`etl`), per day | full week in 32.6 s → 4.7 s/day, disk reads + Parquet writes included | **~2 h of file overhead for the era's 64 M files**, plus parse time on heavy days (parse core sustains 834k tx/s) |

Parsing is never the bottleneck; the wall-clock cost of a full
backfill is download, and the dollar cost is egress on the heavy era.
GET-ops and quiet-era egress are rounding errors. Fetching signature
files from all ~29 nodes multiplies the op count ×29 — attest
selectively, don't attest-per-file during a backfill.

Expect some nodes to be missing from the buckets: attestation needs
only ⅓ of the address book, and individual nodes can go dark for
extended periods while still listed (observed on mainnet: one node
silent for months, making 28/29 the healthy baseline). The network's
canonical daily activity record is the end-of-day payout from account
0.0.802 — a node absent from that transfer list was inactive the
previous day:

```
/api/v1/transactions?transactiontype=CRYPTOTRANSFER&result=success&type=debit&account.id=0.0.802
```

## Backfill pipeline

`hiero-streams etl` is the fast path for bulk history: download record
files (`gcloud storage cp`, parallel + resumable), then run the
threaded pipeline. On a full mainnet **week** (2026-07-05 → 07-11:
302,211 files, 3,259,764 transactions) it transforms in **33 s** on the
same 8-core machine — disk reads included — with `--verify-chain`
proving the entire week gapless and un-reordered: the running-hash
chain holds within every day *and across all six midnight boundaries*.
The dataset reconciles exactly: an independent re-parse of all 302k
files matches the Parquet dataset's per-day row counts and
`sum(fee_tinybar)` to the tinybar (week total 81,138.9769 ℏ). Query the
result from a laptop:

```sql
SELECT day, type, sum(fee_tinybar) / 1e8 AS fees_hbar
FROM read_parquet('data/transactions/*/*.parquet', hive_partitioning=1)
GROUP BY ALL ORDER BY day, fees_hbar DESC;
```

## Why trust it: the network is the reference

Correctness is anchored to the network itself — its signatures and its
own independent decoder — not to this crate agreeing with itself:

- **The consensus nodes cryptographically attest the parse of every
  file-level field.** The signed metadata hash in each `.rcd_sig`
  covers version, HAPI version, both running hashes, and the block
  number — all fields this parser extracts. The test suite recomputes
  that hash from *parsed* fields and verifies it under the signing
  node's real RSA key: if the parse of those fields were wrong, the
  network's own signature would reject it.
- **The mirror node — the network team's own implementation — agrees
  field-for-field.** `tests/record_mirror_differential.rs` parses committed
  mainnet record files and asserts set-equality of transactions plus
  per-transaction agreement on type, payer, result, fee, and complete
  transfer lists against mirror-node data fetched for exactly that
  consensus window (fixtures committed; the test runs offline). Because
  record files are the network's complete output, this is an exhaustive
  window comparison, not spot checks.
- **The chain proves extraction at scale**: 1,800 consecutive mainnet
  files (13,587 transactions) chain-verify with zero breaks — every
  file's parsed running hashes and block number reconciling against its
  neighbors' (parsed in ~0.5 s).
- **Signature verification is tested with real signed fixtures** (from
  the hiero-mirror-node repo) and the address book that actually signed
  them: the signing node's key verifies, sibling keys reject, and a
  single flipped byte fails.
- Committed **output snapshots** pin the exact canonical-JSON shape for
  the signed fixtures (`tests/record_snapshot.rs`), so refactors cannot
  silently change what consumers receive.

The empirically-settled format facts are preserved bit-for-bit: the
signed hash domain is the **entire uncompressed file** (version header
included), and the RSA-3072 signature (SHA384withRSA) is over the
48-byte hash itself.

### v6 signature format reference

Documented here because it is specified nowhere else: HIP-435 defines
`SignatureFile.metadata_signature` but not the bytes the metadata hash
covers — the layout lives only in `SignatureWriterV6.writeSignatureFile`
(hiero-consensus-node). The preimage is the big-endian concatenation

```
int32(recordFileVersion = 6) | int32(hapi major) | int32(minor)
| int32(patch) | startObjectRunningHash.hash (48 raw bytes)
| endObjectRunningHash.hash (48 raw bytes) | int64(blockNumber)
```

hashed with SHA-384 and signed SHA384withRSA like the file signature.
Confirmed against real mainnet `.rcd_sig` files: the reconstructed
digest verifies under the signing node's RSA-3072 key (and any field
omitted, reordered, or byte-swapped fails). This matters for cheap
historical audits: metadata signatures let you verify chain continuity
(running hashes + block numbers) from ~1 KB sig files instead of
downloading the full record files — roughly a 300× data reduction over
the v6 era.

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — how the crate works: data
  flow, module map, every dependency and why, the trust model, and what
  depends on this repo (the published JSON contract, Parquet schema parity).
- [`docs/MIGRATION.md`](docs/MIGRATION.md) — the HIP-1056 block migration:
  what changes and what provably doesn't, the proof-verification port plan
  (with `hiero-block-verifier-js` as the reference implementation), tripwires
  to watch, and the cutover checklist.
- [`docs/CODE-TOUR.md`](docs/CODE-TOUR.md) — how to dig into the source:
  the module map, byte-trace paths, the design decisions you'd otherwise
  trip over, which test pins which contract, and recipes for common
  changes.
- [`ROADMAP.md`](ROADMAP.md) — what's next, what was deliberately
  deferred, and the spikes behind the bigger dependency decisions.

## Scope and roadmap

- **v6 record files** (mainnet mid-2022 onward); earlier v2/v5 formats
  are rejected loudly.
- **Block streams (HIP-1056)** — parsing shipped, validated against the
  mainnet preview. **Proof verification shipped** behind the
  off-by-default `block-proofs` feature: all three in-band proof paths
  (aggregate Schnorr on BabyJubjub, hinTS BLS threshold on BLS12-381,
  WRAPS Groth16+KZG on BN254) plus block-merkle-root recomputation,
  differentially tested check-for-check against
  [`hiero-block-verifier-js`](https://github.com/hiero-hackers/hiero-block-verifier-js)
  over fixtures from `hiero-block-node`. **ETL shipped**: `etl`
  era-detects its input and writes the same Parquet dataset contract
  from `.blk.gz` files, with `--verify-chain` asserting block-number
  gaplessness and root-chain continuity. GA labeling waits on the
  HIP-1193 cutover formalizing (wrapped record blocks — proposed in
  HIP PR #1427 — bridge the transition).
- Full v6 verification: file + metadata signatures, ⅓-of-address-book
  attestation (with the `attest` fetcher), and the running-hash chain
  across consecutive files.
- No I/O in the library: callers bring bytes (bucket clients, files),
  the crate parses and verifies. High-throughput backfill/ETL binaries
  are candidates for a companion crate.

## Examples

Runnable illustrations under `examples/` (`cargo run --release
--example <name> [-- args]`):

| Example | Shows | Needs |
| --- | --- | --- |
| `verify_offline` | full v6 verification (hash, file + metadata signatures) against bundled genuinely-signed fixtures | nothing |
| `verify_block` | block-era in-band proof (merkle root, hinTS, Schnorr + WRAPS) against bundled fixtures — `--features block-proofs` | nothing |
| `parse_one` | one file → readable transaction lines | nothing (bundled fixture) |
| `chain_check -- <dir>` | running-hash chain over a directory — proves a sequence is gapless and un-reordered | downloaded files |
| `fee_report -- <dir>` | mini analytics: top fee payers + fees by type | downloaded files |
| `parse_dir -- <dir>` | throughput benchmark, sequential vs threaded | downloaded files |

Sanity anchor: on the bulk corpus, `chain_check` verified all 1,800
files chain-intact (blocks 97200914..=97202713) and `fee_report`'s
total matches the Parquet dataset's `sum(fee_tinybar)` exactly.

## Layout

```
proto/, proto-hapi/  vendored protobuf definitions (record era / block era)
build.rs          prost codegen (two compile units, one per proto tree)
src/record/       v6 record files: parsing + trust (signatures, chain, attestation)
src/block/        HIP-1056 block streams: parsing + in-band proof verification
src/transaction.rs  the shared output vocabulary both eras produce
src/cli/          the CLI (bin-only): parse / verify / block-activity / attest / etl
examples/         runnable illustrations (see Examples)
bindings/node/    the N-API binding
tests/            the contract pins — snapshots, differentials, real-crypto
tests/fixtures/   real signed stream files from dev-net, mainnet, and test networks
```

The golden files are committed snapshots of the parser's canonical
output for the fixtures. Regenerate one only on an *intentional* output
change (`hiero-streams parse <fixture>`), and review the diff as the
contract change it is. New fixtures are validated against mirror-node
data for their consensus window (see `tests/record_mirror_differential.rs`)
before their snapshots are committed.

## Contributing & security

- **[`CONTRIBUTING.md`](CONTRIBUTING.md)** — how to build, the test
  matrix, coding conventions, and the PR/DCO process.
- **[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)** — Contributor Covenant 2.1.
- **[`SECURITY.md`](SECURITY.md)** — how to report a vulnerability
  privately. This crate verifies untrusted input, so parsing panics and
  verification-soundness issues are both in scope.

## License

Apache-2.0 — see [`LICENSE`](LICENSE). Not affiliated with or endorsed
by Hedera, Hashgraph, the Hiero project, or LF Decentralized Trust.
