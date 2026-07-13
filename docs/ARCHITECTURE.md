# Architecture

How hiero-streams works, what it depends on, and what depends on it. The README
sells the crate; this document explains it — read this when returning to the
project after months away.

## Contents
1. The one-paragraph mental model
2. Data flow
3. Module map
4. Dependencies — data, protos, crates, features
5. The trust model
6. Where this sits in the wider ecosystem

## 1. The mental model

Hedera's consensus nodes publish their signed output as files in a public GCS
bucket. This crate turns those bytes into typed transactions (`parse`), proves the
network vouched for them (`verify`/`attest`), and bulk-transforms them into
day-partitioned Parquet (`etl`). The core library **never performs I/O** — callers
bring bytes; only the opt-in CLI features fetch anything. That boundary is
load-bearing: it is why future changes in *where* files come from (see
MIGRATION.md) cannot break the library.

## 2. Data flow

```
 gs://hedera-mainnet-streams/                 (Hedera-operated, requester-pays)
   recordstreams/record0.0.3/*.rcd.gz  ── v6 era (mid-2022 → cutover)
   block-preview/mainnet/**/*.blk.gz   ── HIP-1056 era (preview)
        │  bytes (caller-fetched, or CLI `fetch` feature)
        ▼
  detect_format ──► record/ (v6)   /  block/ (HIP-1056)
        │  ParsedRecordFile / ParsedBlock — transaction-shaped, era-independent
        ├──► json.rs      canonical JSON (the published contract)
        ├──► record/verify.rs   v6: signatures + running-hash chain + attestation
        ├──► block/proof/ block era: in-band proof — merkle root, hinTS,
        │                 Schnorr/WRAPS (crypto behind `block-proofs`)
        └──► cli/etl/    threaded backfill → Parquet (transactions/, transfers/)
```

Format detection is by leading bytes: v6 files start with a 4-byte version int;
block files are a raw protobuf `Block` message (no header), so detection
distinguishes "protobuf field tag" from "version int".

## 3. Module map

| Module | Responsibility |
|---|---|
| `transaction.rs` | shared output vocabulary both eras produce: `ParsedTransaction`, transfer legs, `day_of` |
| `record/` | v6 record files: gunzip, header, per-transaction records (`mod.rs`); trust — signatures, chain, attestation (`verify.rs`) |
| `block/` | HIP-1056 block streams (preview-validated) — same output shape; `block_activity`; plus `wire`/`merkle`/`material` (block reading) and `proof/` (verification) |
| `block/proof/` | block-era proof crypto (behind `block-proofs`): hinTS / Schnorr / WRAPS verification over the material `block/` extracts |
| `json.rs` | canonical JSON output — the exact schema the snapshot tests pin |
| `main.rs` | thin entry point → `cli::run` |
| `cli/` | the CLI, separate from the library (bin-only): dispatch + command handlers (`mod.rs`), `attest` (networked), `etl/` (backfill: `parquet` sink + `record`/`block` pipelines) |
| `lib.rs` | public re-exports + the two generated-proto compile units |
| `bindings/node` | N-API binding, JSON-over-FFI (portability, not speed — measured) |

Two **separate prost compile units** (deliberate — different provenance and
churn): `generated::proto` from `proto/` (record-era HAPI protos, flattened
`services_*.proto` files) and `generated_hapi::...block::stream` from
`proto-hapi/` (block-stream protos vendored from hiero-consensus-node, source
commit pinned).

## 4. Dependencies

**Data (external, Hedera-operated):**
- The GCS bucket `hedera-mainnet-streams` — record files under
  `recordstreams/record{node}/`, preview blocks under `block-preview/mainnet/`.
  Requester-pays: your GCP project is billed for egress. The CLI's bucket access
  goes through the JSON API (`storage.googleapis.com/storage/v1/b/...`,
  `cli/attest.rs`).
- The mirror node REST API (`mainnet.mirrornode.hedera.com`) — used by `attest`
  to fetch the live address book, and historically to validate parser output.
  The *library* needs neither: `verify_record_file` takes address-book bytes.

**Vendored protos:** `proto/` (record era) and `proto-hapi/` (block era, commit
pinned in the vendor note). These are copies, not submodules — updates are
deliberate, reviewed events.

**Crates (core, always compiled):** `prost` (protobuf), `flate2` (gzip),
`sha2` (SHA-384), `rsa` (RSA-3072 signature verification), `hex`,
`thiserror`, `serde_json`.

**Feature flags:**

| Feature | Adds | Pulls in | Used by |
|---|---|---|---|
| `fetch` (default) | network I/O | `ureq` | `attest` CLI only |
| `etl` (default) | Parquet backfill | `parquet` (zstd) | `etl` CLI only |
| `block-proofs` (off) | block-proof crypto | arkworks 0.4 (`ark-bn254`, `ark-ed-on-bn254`, `ark-bls12-381`, `ark-ec/ff/serialize`, `ark-crypto-primitives` sponge), `blake2` | `verify` on `.blk` inputs; Node binding |
| *(none)* | pure parse/verify library | — | embedders |

Why arkworks (and why pinned to 0.4): much of the proof wire format *is*
arkworks `CanonicalSerialize`, and the consensus nodes' Fiat-Shamir
transcript depends on ark-ff 0.4's `expand_message_xmd` behavior — see
`ROADMAP.md` §1 for the spike numbers and `src/block/proof/hints.rs` for the
two deliberate byte-convention quirks. The feature is off by default so
the plain parse/verify build keeps the dependency-light profile above.

## 5. The trust model

The v6 chain of trust, outside-in:

1. **File signature** — each node publishes `.rcd_sig` beside its copy of the
   record file: SHA-384 of the file bytes, signed with the node's RSA-3072 key.
2. **Address book** — maps node account IDs to their public keys; fetched live
   (attest) or supplied offline (verify). This is the trust root.
3. **Attestation threshold** — `attested == true` only when **≥ ⅓ of the
   address book** signed these exact bytes (Hedera's aBFT boundary: ⅓ honest
   weight cannot be simulated by an attacker).
4. **Running-hash chain** — every file embeds the previous file's hash; the ETL's
   `--verify-chain` asserts the chain within and across day boundaries, making a
   backfill provably gapless and un-reordered, or failing loudly with the exact
   file where it breaks.

The block era replaces 1–3 with in-band proofs, and this crate implements
them (`verify_block_proof`): blocks arrive pre-signed by strictly
more than ⅔ of network weight (a hinTS BLS threshold signature over the
locally recomputed block merkle root), anchored to the ledger ID published
in the genesis block — whose address book endorses the hinTS key via an
aggregate Schnorr signature (early blocks) or a WRAPS Groth16+KZG proof of
the whole rotation history (settled blocks). One proof per block,
verifiable from a single source; continuity comes from the root chain
(each footer claims the previous block's recomputed root). See MIGRATION.md
for the cutover analysis.


## 6. Where this sits in the ecosystem

This crate is a *client-side reader* of the network's output. Upstream of it:
`hiero-consensus-node` (produces the streams and defines the protos) and, in the
block era, `hiero-ledger/hiero-block-node` (the new distribution/persistence node
that will serve blocks and proofs). A block node verifies proofs on *ingest*;
this crate verifies the same proofs on the *consumer side* — the same trust
kernel, pointed the other way, which is what makes HIP-1081's
"trust proofs, not node reputation" checkable at all. Downstream: everything
derived — including mirror nodes, which is precisely why this exists: to check
derived data against ground truth without trusting the intermediary.
