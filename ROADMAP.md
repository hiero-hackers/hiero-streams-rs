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
fails the run when anything moves. And the stream itself can be watched
empirically: [`sentinel.yml`](.github/workflows/sentinel.yml)
(built + live-validated 2026-07-12, currently DORMANT — manual trigger
only until its schedule is uncommented and secrets added) verifies
every new mainnet preview block — gapless numbering,
root-chain continuity across runs, hinTS signatures automatically the
moment blocks carry TSS proofs (today's preview is still the 48-byte
pre-TSS placeholder) — and fails LOUDLY on proof-format drift or a
ledger-ID publication appearing, i.e. on the cutover moments
themselves ([`docs/sentinel-state.json`](docs/sentinel-state.json) is
the advancing record).

## 2 · Publish (decision-gated)

Kept local by choice. When that flips: `cargo publish` (metadata in place,
dry-run green) and the npm binding. Lead with the
differential-correctness story; it is the answer to "why trust another
community parser".

## 3 · Full-era backfill (budget-gated)

A costed decision, not code: ~10–30 TB / ~$1,200–3,600 egress, ~4 days–2
weeks of download, hours of transform via `etl --verify-chain` (measured:
a quiet-era week fetches in 23 min and transforms, chain-verified, in 33 s). Do it when something
consumes the output — the hiero-analytics sampled→exact swap is the natural
demand driver. Unaffected by the block cutover: the v6 era is immutable
history either way.

## 4 · Block-node era intake (GA-gated)

Where this crate sits in the HIP-1081 world, stated once: a Block Node
verifies proofs on *ingest* and serves data; this crate verifies proofs
on the *consumer side* so nobody has to trust a block node's
reputation — the same trust kernel, pointed the other way (HIP-1081's
own model: "trust data integrity through proofs rather than node
reputation"). The GCS `block-preview/` bucket is explicitly interim;
when block nodes GA, bytes arrive by subscription instead.

- **`subscribe` feature — a `BlockStreamSubscribeService` gRPC client.**
  The pull side of HIP-1081, designed for consumers like this crate
  (the CN-facing `BlockStreamPublishService` is an operator surface,
  not ours). Gated like `fetch` (tonic/prost, bin-only), it becomes the
  second way bytes reach the same `parse_block`/`verify_block_proof`
  path — the library API does not move. Gate: block-node GA + the
  PR #1474 format freeze, both already tripwired by `watch-cutover.yml`.

**Measured (2026-07-12), for the daemon's founding argument** — verify-only
(ingest merkle recompute + full TSS proof verification) over the same
`CN_0_73_TSS_WRAPS` fixtures, same machine, warmup + 30 timed iterations
per block; Java side = `hiero-block-node`'s own `BlockHasher` +
`TSSVerifier` path (`TSS.verifyTSS`), invoked exactly as its
`TSSVerifierTest` does:

| Path | Rust (this crate) | Java (`hiero-block-node`) | ratio |
|---|---|---|---|
| Schnorr blocks 1–4 | 24.0 ms/block | 31.9 ms/block | 1.33× |
| WRAPS block 467 | 40.9 ms/block | 43.4 ms/block | 1.06× |
| **Max RSS** | **7.4 MiB** | **375 MiB** (4 GiB heap ceiling) | **~50×** |

Honest reading: throughput is near parity because the workload is
pairing-dominated and both sides run native crypto — the gap widens
exactly where work leaves the pairings (Schnorr blocks: 1.33×). Both
are far faster than the ~2 s block cadence, so throughput decides
nothing. And for a standalone daemon on a real server, RAM barely
does either — disk and egress dominate an archive node's bill.
**What the 7.4 MiB actually buys is portability of verification**:
the same kernel fits a 128 MB serverless function, embeds in-process
via C FFI/N-API in services written in other languages, compiles to
WASM for browser/wallet verification, and runs as a per-pod sidecar
at zero marginal density cost — deployment classes where a JVM
verifier isn't more expensive but *absent*. The daemon's own case is
deployment simplicity (single static binary, GC-free tails) plus
fitting the smallest hosting tiers. 

- **`hiero-streams-archive` — a separate repo, deliberately.** A lean
  Rust daemon doing *subscribe → verify (this crate) → persist
  canonical blocks*: HIP-1081's "Archive" tier (complete history, no
  consumer APIs) is the smallest useful block-node shape, and its hard
  part — proof verification — is already shipped here. Storage,
  retention, and uptime are a service lifecycle and stay out of this
  library (the no-I/O boundary is load-bearing); the split mirrors
  hiero-sync ↔ hiero-analytics. Could later grow re-serving
  (`BlockStreamSubscribeService` server) toward Tier-2. Draft the repo
  when the subscribe client lands; build it when something needs the
  archive.

## Deferred until demand exists

- **Structured-object binding API** — JSON-over-FFI is portability, not speed
  (measured); a non-JSON N-API surface only if in-process JS performance ever
  matters.
- **PyO3 bindings** — Python users are served by the Parquet datasets and the
  CLI subprocess contract.
- **WASM verifier** — arkworks compiles to `wasm32`, so browser/wallet-side
  block-proof verification ("this page cryptographically verified the block
  it shows you") is a weekend-scale build reusing the crate nearly verbatim,
  and a capability no JVM implementation can offer. High narrative value;
  build it when there is a surface to demo it on.

## Non-goals

- **Being a block node.** No stream intake service, no state
  management, no serving APIs in this repo — the archive daemon that
  wants those consumes this crate from its own repo (§4).
- A Rust mirror node (the bottleneck is Postgres, not language).
- A write-side SDK (hiero-sdk-rust exists).
- HTTP clients inside the library — callers bring bytes; only opt-in
  features/binaries do I/O.
