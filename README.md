# hiero-streams (Rust)

Parse and cryptographically verify Hedera **record stream files** — the
signed consensus output every mainnet node publishes — in a
dependency-light, no-GC Rust crate. Block streams (HIP-1056) are the
planned second format behind the same API, timed for the network's
cutover.

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

## Why trust it: differential correctness

This crate is **tested against a reference implementation, not just
against itself**:

- The `.proto` definitions under `proto/` are vendored verbatim from
  `@hashgraph/proto@2.25.0` — the same definitions the reference
  TypeScript parser ([hiero-recordstreams]) compiles, so both
  implementations are version-locked by construction.
- The differential test parses real mainnet record files and asserts
  **field-for-field equality** with a golden dump from the TypeScript
  reference — which is itself validated byte-exact against mainnet: a
  full day (43,200 files, 408,228 transactions) reconciled to the
  tinybar against the mirror node REST API.
- Signature verification is tested with **real signed fixtures** (from
  the hiero-mirror-node repo) and the address book that actually signed
  them: the signing node's key verifies, sibling keys reject, and a
  single flipped byte fails.

The empirically-settled format facts are preserved bit-for-bit: the
signed hash domain is the **entire uncompressed file** (version header
included), and the RSA-3072 signature (SHA384withRSA) is over the
48-byte hash itself.

[hiero-recordstreams]: ../hiero-recordstreams

## Scope and roadmap

- **v6 record files** (mainnet mid-2022 onward); earlier v2/v5 formats
  are rejected loudly.
- **Block streams (HIP-1056 / wrapped record blocks HIP-1427)** — the
  successor format, next on the roadmap as the network cutover lands.
- File signature verification (hash + RSA + ⅓-of-address-book
  threshold); the v6 metadata signature and running-hash chain are not
  yet checked.
- No I/O in the library: callers bring bytes (bucket clients, files),
  the crate parses and verifies. High-throughput backfill/ETL binaries
  are candidates for a companion crate.

## Layout

```
proto/            vendored @hashgraph/proto@2.25.0 definitions (174 files)
build.rs          prost codegen (single wrapper across proto packages)
src/parse.rs      v6 record file → typed transactions
src/verify.rs     .rcd_sig parsing, RSA verification, address book, attestation
tests/differential.rs   field-for-field vs the TS reference golden dump
tests/verify_test.rs    real-crypto tests with genuinely signed fixtures
tests/fixtures/   real record files + the dev-net address book that signed them
```

Regenerate `tests/fixtures/golden-v6.json` with the golden-dump script
in the hiero-recordstreams repo whenever fixtures change.

## License

Apache-2.0. Not affiliated with or endorsed by Hedera, Hashgraph, the
Hiero project, or LF Decentralized Trust.
