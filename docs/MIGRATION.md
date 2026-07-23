# The HIP-1056 Migration — What Changes, What Doesn't, What To Do

The network is migrating its published output from v6 record files to block
streams (HIP-1056), with the cutover governed by HIP-1193 (Approved) and
in-band proofs replacing sidecar signatures (hinTS threshold signatures are
specified by HIP-1200; WRAPS and the genesis Schnorr path are defined in
HIP-1056 and the hedera-cryptography implementation). This document is the
technical companion to ROADMAP.md: what the migration actually touches in
this codebase, in the sibling repos, and in what order to react. See
ARCHITECTURE.md for the current-state picture.

## Contents
1. The two eras side by side
2. What does NOT change (most things)
3. What changes: inputs, proofs, distribution
4. The proof port — hiero-block-verifier-js is the reference
5. Ecosystem impact map (which sibling repos care)
6. Tripwires to watch
7. Decision checklist at cutover

## 1. The two eras side by side

| | v6 record era (mid-2022 → cutover) | Block era (HIP-1056) |
|---|---|---|
| File | `.rcd.gz`, 4-byte version header | `.blk.gz`, raw protobuf `Block`, no header |
| Cadence / naming | ~2s files, consensus-timestamp names, per-node dirs | numbered blocks (numbering already diverges from record-file counts: 104.4M vs 97.4M) |
| Signatures | sidecar `.rcd_sig` per node (SHA-384 + RSA-3072) | **in-band** proof per block |
| Trust threshold | ≥ ⅓ of address book (verifier collects N signatures) | strictly > ⅔ of network weight, pre-aggregated (verifier checks ONE proof) |
| Address book needed | yes (trust root) | no — proof is self-contained against the ledger ID |
| Chain continuity | running-hash chain across files | merkle structure + block-to-block linkage |
| Status here | fully shipped, snapshot-pinned + mirror-differential | parsing, proof verification, and ETL shipped (preview-validated) |

Transitional wrinkle: **wrapped record blocks (WRBs)** — record-era data
re-published in block wrapping during cutover (proposed in HIP PR #1427,
"Historical Record File Wrapping for Block Stream Cutover", not yet a
numbered HIP; tracked by mirror-node epic #13346). Expect a window where
both formats describe the same consensus output.

## 2. What does NOT change

- **v6 history.** Every record file ever published is immutable. The v6 parser,
  verifier, and any backfill stay correct forever. The
  full-era backfill (ROADMAP §3) is v6 data regardless of when it runs.
  Even where history is served as HIP-1193 wrapped record blocks, the
  wrapped payload is still v6 record-file bytes — verifying it still
  means v6 verification, so the `record/` half of this crate is
  permanent, not transitional.
- **The reason to exist.** The migration replaces *distribution*
  (bucket → block nodes), not *verification*. It also adds a new
  intermediary class — independent and commercial block-node operators
  (HIP-1081 Tier 1/2) — whose output is exactly what "trust proofs,
  not reputation" needs an independent verifier for. Post-cutover this
  crate's role narrows and sharpens: the consumer-side trust kernel
  (one of two independent proof implementations), the permanent v6
  auditor, and the Rust implementation of the proof stack for anyone
  building block-node-adjacent infrastructure (ROADMAP §4).
- **The library API.** `detect_format` already routes both eras to
  transaction-shaped output; callers feeding bytes blindly keep working. The
  no-I/O core means a change in *where* bytes come from cannot break the crate.
- **The Parquet schema.** Era-independent by design; block-era ETL appends to
  the same dataset shape.
- **The canonical JSON contract** for existing v6 corpus cases.
- **Plane A of the wider architecture** (hiero-sync, hiero-analytics,
  enterprise-js): they consume the mirror node's REST API, which is stable
  through the migration — the open cutover epics are about the mirror node's
  own ingestion, not its API.

## 3. What changes

1. **Input format** — done: `parse_block` shipped, preview-validated
   field-for-field against mirror REST.
2. **Proof model** — done: block verification is **proof-first** — one
   in-band proof per block (`proofs::verify_block_proof`; CLI `verify`
   routes `.blk` inputs to it). The per-node signature-collection design
   (`attest` fetching `.rcd_sig` from ~29 bucket directories) does not
   carry over; its fetch-many model applies only to the v6 era.
3. **Distribution** — likely shifts from the GCS bucket to block nodes
   (`hiero-ledger/hiero-block-node`) serving blocks and proofs; the HIP-679
   bucket layout is sunsetting. Only the opt-in `fetch` feature and CLI care.
   The planned intake is a `BlockStreamSubscribeService` gRPC client —
   HIP-1081's pull side, designed for consumers like this crate (the
   CN-facing publish service is an operator surface, not ours). Scoped as
   the `subscribe` feature in ROADMAP §4, gated on block-node GA.
4. **ETL** — done: `etl` era-detects `.blk.gz` inputs; `--verify-chain`
   asserts block-number gaplessness and recomputed-root == footer-claim
   continuity.

## 4. The proof port — hiero-block-verifier-js is the reference

The sibling repo **`hiero-hackers/hiero-block-verifier-js`** already implements
full HIP-1056 proof verification — all three paths, including the hinTS
scheme HIP-1200 specifies — in pure TypeScript (`@noble/curves` only),
validated against fixtures vendored from the block-node repo
(`CN_0_73_TSS_WRAPS`):

- **Schnorr** aggregate signatures (BabyJubjub over BN254) — genesis /
  pre-settled blocks
- **WRAPS** Nova IVC proofs (Groth16 + KZG on BN254)
- **hinTS** BLS threshold signatures (10 pairing checks, BLS12-381)
- SHA-384 merkle block-root recomputation; bootstrap extraction from block 0

Consequences for this repo:

- Rust block-proof verification is a **port, not research**: algorithms and
  test vectors exist. This recreates the v6 pattern exactly — a TS reference
  and a Rust implementation certified against a shared corpus
  (differential correctness is this project's whole credibility story).
- Crate implications: the three paths need BN254/BabyJubjub, Groth16+KZG, and
  BLS12-381 pairing support — evaluate `arkworks` vs `blstrs`+friends against
  the dependency-light policy before starting; this is the one place the
  "small dependency tree" identity will be tested.
- Use the same fixtures (vendor the `CN_0_73_TSS_WRAPS` corpus with a pinned
  source commit, like the proto vendor notes) and add cross-implementation
  fixture runs to CI before the corpus v2 formalizes them.
- Until the port lands, a pragmatic interim exists: compose at the CLI level
  (Rust parses/ETLs, the JS verifier proves) — but the single-static-binary
  auditor story requires the port eventually.

## 5. Ecosystem impact map

| Repo | Impact | Action |
|---|---|---|
| `hiero-streams-rs` (this) | proofs, ETL, fetch backend | §3–4 above; ROADMAP §4 (`subscribe` client, archive-daemon repo) |
| `hiero-block-verifier-js` | none — it IS the block-era reference | keep fixtures current with block-node releases |

## 6. Tripwires to watch

- `hiero-ledger/hiero-mirror-node` epics **#13574** (Block Node Cutover
  Testing) and **#13346** (WRB Cutover Support) — both open as of 2026-07-11;
  their closure is the cutover signal.
- `hiero-ledger/hiero-block-node` releases — the proof-serving API and fixture
  corpus source (v0.38.0 as of 2026-07-11, releasing frequently).
- The `block-preview/` bucket path — format or naming changes indicate the
  preview is converging on GA.
- Proof-format revisions — HIP-1056's block items/proofs update PR
  (hiero-improvement-proposals#1474) was closed as stagnant on 2026-07-23
  without merging (watch for a reopen), and hinTS (HIP-1200) could revise;
  either changes the port's target.

**These are automated.**
[`.github/workflows/watch-cutover.yml`](../.github/workflows/watch-cutover.yml)
runs twice weekly and fails the run (which notifies the repo owner) when any
of five GitHub-pollable signals moves versus the acknowledged state in
[`docs/watch-state.json`](watch-state.json): both epics, the block-node
release tag, PR #1474's **state and head commit** (an amendment moves the
proof format even while the PR stays open), and the **last commit to
`HIP/hip-1200.md`** (a hinTS spec revision). After reacting to a change,
update `watch-state.json` and commit. The migration won't be discovered by
accident.

The one signal it can't poll is the **`block-preview/` bucket** — it is
requester-pays (no GitHub-token access) and churns every block, so a
token-only diff is infeasible. Check its top-level *structure* (not the
per-block files) manually when a release or epic moves:

```sh
gcloud storage ls "gs://hedera-mainnet-streams/block-preview/mainnet/" \
    --billing-project=YOUR_PROJECT
```

A new prefix, a renamed path, or a changed naming pattern is the signal that
the preview is converging on GA — re-vendor fixtures and re-run the proof
differential when it shifts.

## 7. Decision checklist at cutover

- [ ] Port the three proof paths to Rust against the JS reference + fixtures
- [ ] Re-validate `parse_block` on GA-format blocks (preview formats can shift)
- [ ] ETL: `.blk.gz` inputs + proof-verified continuity
- [ ] `verify`/`attest` CLI: proof-first block path; document that the v6 flags
      remain for historical files forever
- [ ] Fetch: block-node backend beside the bucket backend (`fetch` feature only)
- [ ] Conformance corpus v2, both implementations certified
- [ ] Update ARCHITECTURE.md §2/§5 and the README's era caveat
