# Fixture provenance

Every fixture here is real network output — nothing is synthesized —
because the tests' credibility rests on what the bytes are and where
they came from. Treat additions the same way: record the source.

| Path | What it is | Source |
|---|---|---|
| `v6/` | v6 record files + `.rcd_sig` signature files, **genuinely signed** | dev-net fixtures from the `hiero-mirror-node` repo |
| `test-v6-sidecar-4n.bin` | the address book that actually signed `v6/` (nodes 0.0.3–0.0.6) | same dev-net |
| `mainnet/` | a real mainnet consensus window + the mirror node's decode of it (committed REST responses) | `hedera-mainnet-streams` bucket / `mainnet.mirrornode.hedera.com` |
| `block-preview/` | HIP-1056 block files | the live mainnet `block-preview/` bucket prefix |
| `tss/` | consecutive blocks 0–4 and block 467 with in-band TSS proofs, plus `js-verifier-golden.json` (the JS reference verifier's check-for-check reports) | `CN_0_73_TSS_WRAPS` test-network fixtures vendored from `hiero-block-node`; golden reports from `hiero-block-verifier-js` (`npm run verify:all -- --json`) |
| `golden-v6.json` | the committed snapshot of the parser's canonical JSON for the `v6/` fixtures | this crate's own `parse` output |

`golden-v6.json` is a contract pin: regenerate it only on an
*intentional* output change (`hiero-streams parse <fixture>`), and
review the diff as the API change it is. New fixtures must be validated
against mirror-node data for their consensus window (see
`tests/record_mirror_differential.rs`) before their snapshots are
committed.
