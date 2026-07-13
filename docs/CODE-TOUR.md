# Code Tour — how to dig into this codebase

A working map for reading and changing the source (~3,700 lines of
hand-written Rust). ARCHITECTURE.md explains what the crate is; this
document is for navigating it: where things live, the design decisions
you'll trip over if you don't know them, which test pins which
contract, and recipes for the changes people actually make.

## The 60-second map

```
build.rs                 two prost compile units from vendored protos (rcd/, hapi/)
src/
  lib.rs                 the public facade: flat re-exports (the stable API), Error,
                         inflate() gzip chokepoint, and detect_format (the era router)
  transaction.rs         shared vocabulary both eras produce: ParsedTransaction, legs, day_of
  json.rs                the canonical JSON shapes — the published contract
  record/                the record-stream era (v6)
    mod.rs                 parse_record_file → ParsedTransaction
    verify.rs              v6 trust: RSA signatures, address book, running-hash chain
  block/                 the block-stream era (HIP-1056)
    mod.rs                 parse_block → the same ParsedTransaction; block_activity
    wire.rs                shallow protobuf scan of a Block            (always on)
    merkle.rs              streaming block-merkle-tree hasher          (always on)
    material.rs            extraction: root, layout, bootstrap, continuity  (always on)
    proof/               block-proof verification                     (feature: block-proofs)
      mod.rs               verify_block_proof glue
      poseidon.rs          Poseidon/BN254 canonical config
      schnorr.rs           aggregate Schnorr on BabyJubjub
      hints.rs             hinTS BLS threshold, ten checks
      wraps.rs             WRAPS Groth16+KZG decider proof
  main.rs                thin entry point → cli::run
  cli/                   the CLI, kept separate from the library (bin-only)
    mod.rs                 dispatch + parse/verify/block-activity handlers
    attest.rs              networked: v6 multi-node attestation        (feature: fetch)
    sentinel.rs            networked: continuous preview-stream verification
                           (state: docs/sentinel-state.json, schedule:
                           .github/workflows/sentinel.yml)             (feature: fetch)
    etl/                 threaded backfill → day-partitioned Parquet    (feature: etl)
      mod.rs                 arg parsing + era dispatch (+ integration tests)
      parquet.rs             the Parquet sink (schemas + writers)
      record.rs              the v6 pipeline
      block.rs               the block pipeline
bindings/node/           napi-rs binding, JSON-over-FFI
fuzz/                    cargo-fuzz targets (detached workspace)
tests/                   the contract pins — see "what guards what" below
```

The crate-root flat re-exports in `lib.rs` are the **stable public API**
(`hiero_streams::verify_block_proof`, `parse_record_file`, …) — and the
*only* public paths: the module tree above is private, so it can keep
reorganizing as the project grows without a breaking release.

First commands (protoc required — `brew install protobuf`):

```
cargo test                                  # default features (fetch, etl)
cargo test --features block-proofs --release  # + proof crypto (pairings want release)
cargo test --no-default-features            # the pure-library configuration
cargo clippy --all-targets -- -D warnings   # CI runs all three configurations
```

## Three byte-trace paths

The fastest way to understand the crate is to follow bytes through it.

**1. The parse path.** `detect_format` (lib.rs — the era router) reads the first four
bytes: big-endian i32 `6` → v6 record file; leading `0x0a` (the protobuf
tag for "field 1, length-delimited") → block stream. Then either
`parse_record_file` (inflate → version header → prost decode → map into
output structs) or `parse_block` (inflate → `Block` decode → the
pairing state machine: a user transaction is a `SignedTransaction` item
whose outcome arrives as the *next* `TransactionResult` item; node
state-signature transactions never get a result and are silently
superseded). Both eras produce the same `ParsedTransaction`, which is
why everything downstream — `json.rs`, the ETL, the binding — is
era-blind.

**2. The v6 trust path** (record/verify.rs). `record_file_hash` = SHA-384 over
the whole uncompressed file, version header included — the exact bytes
nodes sign (established empirically; don't "clean it up").
`parse_signature_file` unwraps a `.rcd_sig` (one version byte, then
protobuf). `verify_node_signature` checks one node's RSA-3072 signature
— note the outcome split: a malformed *signature* is `Ok(false)`, a
malformed *key* is `Err`; invalid proof and invalid input are different
things, and that convention holds crate-wide. `verify_record_file`
aggregates: attested when `valid.len() * 3 >= node_count` (integer
math, no floats). `verify_running_hash_chain` walks `files.windows(2)`
— each file's start hash must equal its predecessor's end hash.

**3. The block trust path** (block/). `extract_proof_material`
(in `block/material.rs`) re-scans the raw wire bytes — NOT the typed decode —
because the block merkle tree's leaves are the *exact serialized bytes*
of each item and a prost re-encode isn't guaranteed byte-identical. The
mechanics are two small modules it orchestrates: `wire.rs` (the shallow
protobuf scan that slices out each item's bytes) and `merkle.rs` (the
streaming binary-counter tree hasher). It splits the packed
`block_signature` (hinTS VK 1096 B ‖ hinTS signature 1632 B ‖ scheme
suffix: 192 B Schnorr or 704 B WRAPS), folds the block root, and pulls
the bootstrap publication if the block carries one (genesis only).
`verify_block_proof` then always checks the hinTS threshold signature
over the recomputed root, plus the suffix scheme: Schnorr (the address
book endorses the hinTS key; message = ledger ID ‖ Poseidon(VK)) or
WRAPS (a folding-scheme decider proof of the whole rotation history).
Continuity is separate and proof-free: `block_chain_info` +
"recomputed root == next footer's claim".

## Design decisions you'll trip over

- **Two prost compile units** (build.rs): the record-era and block-era
  proto trees both declare a package named `proto`, so they compile to
  separate out-dirs (`rcd/`, `hapi/`) and are spliced in behind two
  `mod generated` blocks in lib.rs. Generated code never leaks past
  those modules.
- **`oneof_case_name` uses `Debug` formatting** (record/mod.rs, mirrored
  in block/mod.rs): transaction-type names are derived from the oneof
  variant's Debug output rather than a ~70-arm match that would rot
  when HAPI adds types. A prost upgrade that changes Debug format is
  caught by `oneof_case_name_known_variants` in lib.rs, and a
  cross-era parity test keeps the two copies from drifting.
- **record / block parser duplication is deliberate.** Same helper names,
  same output type, different wire era. Don't unify them; the parity
  tests are the shared spine.
- **JSON big integers are strings** (json.rs): `blockNumber`, fees,
  amounts exceed JS `Number` safety. Never "fix" them into numbers —
  the snapshot tests will catch you, and so will every JS consumer.
- **hints.rs byte conventions are intentionally weird**: BLS12-381
  material is ZCash-style big-endian (NOT arkworks canonical LE), and
  the Fiat-Shamir transcript uses ark-ff 0.4's non-RFC
  `expand_message_xmd` (z_pad = 48-byte output length, not the 64-byte
  SHA-256 block). Both are hand-implemented and must match the
  consensus node byte-for-byte; the differential tests pin them. This
  is also why arkworks is pinned to 0.4 (see Cargo.toml comment).
- **`resolve_bootstrap` takes a hint string** so the CLI and the Node
  binding share the logic but each error names that surface's fix.
- **Dependency frugality is a policy, not an accident**: hand-rolled
  date math (`day_of`), percent-encoding, and CLI arg parsing all exist
  because the dependency would be bigger than the code. Match that bar
  before adding a crate.
- **The library does no I/O, ever.** Only the `fetch`-gated
  `cli::attest` command touches the network. That boundary is what makes the
  migration analysis in MIGRATION.md hold.

## What guards what — the test map

| If you change… | …this fails |
|---|---|
| parse output for any v6 field | `tests/record_snapshot.rs` (committed `golden-v6.json` snapshot) and `tests/record_mirror_differential.rs` (field-for-field vs the mirror node's decode of the same mainnet files) |
| block parse output | `tests/block_parse.rs` + the cross-era parity tests in lib.rs |
| JSON shape | the snapshot tests + the binding's `test.mjs` (JS-side equality) |
| proof verification, any check | `tests/block_proof_differential.rs` — check-for-check equality with `hiero-block-verifier-js` via `tests/fixtures/tss/js-verifier-golden.json`, plus tamper tests that must fail at the *exact* expected check |
| merkle/continuity logic | `tests/block_chain.rs` (real consecutive blocks 0–4) |
| v6 crypto | `tests/record_verify.rs` — genuinely-signed fixtures, real RSA keys |
| Parquet schema | `parquet_schemas_are_stable` in `cli/etl/parquet.rs` (the dataset contract) plus the gap/mixed-era tests in `cli/etl/mod.rs` |
| panic-freedom on garbage | `tests/robustness.rs` + the no-panic test in `block_proof_differential.rs`; deeper coverage via `cargo fuzz` (five targets, seeded from fixtures) |

Fixture provenance: `tests/fixtures/v6/` (dev-net, genuinely signed),
`mainnet/` (real mainnet window + committed mirror-node responses),
`block-preview/` (live mainnet HIP-1056 preview), `tss/` (consensus-node
test-network blocks from `hiero-block-node`, with the JS verifier's
golden reports).

## Recipes

**Add a field to `ParsedTransaction`** (the full-pipeline change):
thread it from `TransactionBody`/`TransactionResult` in *both*
`record`'s `parse_item` and `block`'s `transaction_from`, add it to
`json.rs::transaction_value`, run `cargo test` — the snapshot tests
fail, regenerate `golden-v6.json` per its README note, re-run. If the
mirror differential can check the field, extend
`tests/record_mirror_differential.rs` too.

**Update the vendored protos**: replace files under `proto/`
(record era) or `proto-hapi/` (block era, record the source commit in
`VENDOR_COMMIT`), `cargo build` regenerates. Then run the full test
matrix — the 527 response-code incident (an enum newer than the
vendored protos, caught by the mirror differential, handled by the
fallback chain in `record`'s `response_code_name`) is the cautionary
tale for skipping this.

**Add a CLI subcommand**: a `cmd_*` function in `cli/mod.rs`, an arm in
`run()`'s dispatch match, a line in `usage()`, and the README quick
start. Exit codes are the API — `SUCCESS` only when the answer is
"verified/valid".

**Touch proof verification**: read the reference first —
`hiero-block-verifier-js` (the differential partner) and the consensus
node's `hedera-cryptography` (the algorithms' source of truth). Any
change must keep every golden check green; if the wire format itself
moves (watch PR #1474 via `watch-cutover.yml`), regenerate the golden
reports with that repo's `npm run verify:all -- --json` and re-vendor
fixtures.

**Rebuild the Node binding** after changing `#[napi]` functions: `npx
napi build --platform --release` in `bindings/node` — the `--platform`
flag is what regenerates `index.js`'s export list (a stale one once
silently dropped an export; `test.mjs` now guards the full surface).
Generated `index.js`/`index.d.ts`/`*.node` are gitignored on purpose.

## Gotchas

- Pairings are slow in debug builds — run proof tests with `--release`.
- `fuzz/` is a detached cargo workspace (cargo-fuzz convention): it
  doesn't build with the main workspace, and needs nightly to *run*.
- MSRV is 1.82 (`rust-version` in Cargo.toml, enforced by CI's msrv job
  and clippy's `incompatible_msrv` lint).
- `cargo doc` builds with `-D warnings` in CI and doctest is off —
  doc comments are checked for link validity but never executed.
- The genesis block's footer carries a non-empty pre-genesis
  previous-root constant — the root chain contract starts at the first
  block *pair* (see `tests/block_chain.rs`).
- ETL partition semantics differ by era on purpose: v6 rows land in the
  partition of the *file* that carried them (files are named by date);
  block-era rows land in the partition of their own consensus day
  (block files are named by number). Documented in `cli/etl/record.rs`
  and `cli/etl/block.rs`.
