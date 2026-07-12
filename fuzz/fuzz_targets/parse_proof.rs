#![no_main]

use libfuzzer_sys::fuzz_target;

// Proof-material extraction runs the shallow wire scan, the merkle
// fold, and typed decodes over attacker-controlled bytes — must never
// panic. (Proof *verification* is exercised by the differential tests;
// its inputs are length-gated slices of what this target parses.)
fuzz_target!(|data: &[u8]| {
    let _ = hiero_streams::proofs::extract_proof_material(data);
});
