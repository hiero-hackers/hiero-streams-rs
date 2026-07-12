# Roadmap

Everything buildable locally has shipped; the repo is in **watch mode** —
remaining work is gated on external events, not code. (Delivered: v6 parsing
with differential proof; full verification — file + metadata signatures,
running-hash chain, live multi-node attestation; the CLI; the Node binding;
the threaded Parquet ETL with `--verify-chain`; and block-stream parsing
validated against the mainnet preview.)

## 1 · Block streams (HIP-1056) — parsing ✅, proofs ✅, rest is cutover-gated

`parse_block` shipped against the live mainnet preview (`block-preview/`),
transactions validated field-for-field against mirror REST.

**Proof verification shipped** (2026-07) behind the off-by-default
`block-proofs` feature: block-merkle-root recomputation plus all three
in-band proof paths — aggregate Schnorr on BabyJubjub, hinTS BLS threshold
on BLS12-381 (all ten checks), WRAPS Groth16+KZG on BN254 — differentially
tested check-for-check against the sibling
[`hiero-block-verifier-js`](https://github.com/hiero-hackers/hiero-block-verifier-js)
over `hiero-block-node` fixtures (`tests/fixtures/tss/`, golden
expectations committed). The crate bet went as spiked: **arkworks** — the
"minimal" alternative (blstrs + halo2curves) cost the same dependency count
(84 vs 85 crates), built 3× slower, and couldn't cover BabyJubjub/BN254
Groth16, while much of the wire format *is* arkworks `CanonicalSerialize`
(WRAPS deserialization is a derive; the hinTS material needed hand-rolled
ZCash-convention point I/O and ark-ff 0.4's quirky Fiat-Shamir expander,
both pinned by the differential tests). Entry point:
`proofs::verify_block_proof`.

**CLI wiring shipped**: `verify` is era-transparent — `.blk[.gz]` inputs
route to the in-band proof (with `--bootstrap <genesis>` supplying the
ledger-ID publication for non-genesis blocks); the per-node `attest`
fetch model stays v6-only because blocks arrive pre-signed.

**Block-era ETL shipped**: `etl` era-detects its input directory —
`.blk[.gz]` files parse to the same Parquet dataset contract, with
`--verify-chain` asserting block-number gaplessness plus
recomputed-root == footer-claim continuity (the block-era analogue of
the v6 running-hash chain; validated over consecutive
`hiero-block-node` fixtures and the mainnet preview block). Rows
partition by their own consensus day, since block file names carry no
date.

**`block-activity` shipped**: per-block node liveness from gossip-event
creators (`hiero-streams block-activity <file.blk.gz>...`), a signal the
record era never exposed. Counts pinned by test against the mainnet
preview block that agreed exactly with the 0.0.802 payout list
(28 nodes active, same absentee).

Remaining for GA:

- Re-validation of parsing, proofs, and ETL when the preview format freezes
  (PR #1474 tripwire).

**Tripwires** (all verified open/live 2026-07-11): mirror-node epics
[#13574](https://github.com/hiero-ledger/hiero-mirror-node/issues/13574)
(Block Node Cutover Testing) and
[#13346](https://github.com/hiero-ledger/hiero-mirror-node/issues/13346)
(WRB Cutover Support); `hiero-block-node` releases (v0.38.0, frequent); the
`block-preview/` bucket layout; proof-format revisions — HIP-1056's block
items/proofs have an open update PR
([hiero-improvement-proposals#1474](https://github.com/hiero-ledger/hiero-improvement-proposals/pull/1474)),
and hinTS is specified by HIP-1200. The cutover itself is governed by
HIP-1193 (Approved). Full what-changes / what-doesn't analysis and the
cutover checklist live in [`docs/MIGRATION.md`](docs/MIGRATION.md).
These signals are watched automatically:
[`watch-cutover.yml`](.github/workflows/watch-cutover.yml) diffs them
twice weekly against [`docs/watch-state.json`](docs/watch-state.json) and
fails the run when anything moves.

## 2 · Publish (decision-gated)

Kept local by choice. When that flips: `cargo publish` (metadata in place,
dry-run green) and the npm binding. Lead with the
differential-correctness story; it is the answer to "why trust another
community parser".

## 3 · Full-era backfill (budget-gated)

A costed decision, not code: ~10–30 TB / ~$1,200–3,600 egress, days of
download, ~2 h of transform via `etl --verify-chain`. Do it when something
consumes the output — the hiero-analytics sampled→exact swap is the natural
demand driver. Unaffected by the block cutover: the v6 era is immutable
history either way.

## Deferred until demand exists

- **Structured-object binding API** — JSON-over-FFI is portability, not speed
  (measured); a non-JSON N-API surface only if in-process JS performance ever
  matters.
- **PyO3 bindings** — Python users are served by the Parquet datasets and the
  CLI subprocess contract.

## Non-goals

- A Rust mirror node (the bottleneck is Postgres, not language).
- A write-side SDK (hiero-sdk-rust exists).
- HTTP clients inside the library — callers bring bytes; only opt-in
  features/binaries do I/O.
