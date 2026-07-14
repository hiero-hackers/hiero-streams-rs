// SPDX-License-Identifier: Apache-2.0
#![no_main]
//! Fuzzes the full block-proof **verification** path, not just extraction:
//! `extract_proof_material → resolve_bootstrap → verify_block_proof`. The sibling
//! `parse_proof` target stops at extraction, so it never reaches the arkworks
//! deserialization + pairing crypto — which is exactly where malformed proofs can
//! panic. A clean `Err` is expected; only a panic/hang/OOM is a finding.
use hiero_streams::{extract_proof_material, resolve_bootstrap, verify_block_proof, ProofPath};
use libfuzzer_sys::fuzz_target;

// Baked genesis so non-genesis inputs can resolve a bootstrap and reach the
// deeper verification code instead of stopping at "no ledger id".
static GENESIS: &[u8] = include_bytes!("../../tests/fixtures/tss/0.blk.gz");

fuzz_target!(|data: &[u8]| {
    let material = match extract_proof_material(data) {
        Ok(m) => m,
        Err(_) => return,
    };
    if matches!(material.layout.path, ProofPath::Unknown) {
        return; // pre-TSS placeholder: nothing to verify
    }
    let bootstrap = match resolve_bootstrap(&material, Some(GENESIS), "genesis") {
        Ok(b) => b,
        Err(_) => return,
    };
    let _ = verify_block_proof(&material, &bootstrap);
});
