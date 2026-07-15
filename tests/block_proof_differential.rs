//! Differential test of block-proof verification against the JS
//! reference implementation.
//!
//! `tests/fixtures/tss/js-verifier-golden.json` holds the output of
//! hiero-block-verifier-js over the CN_0_73_TSS_WRAPS fixtures vendored
//! from hiero-block-node. Every extracted layout, recomputed block
//! root, and verification verdict must match it.

#![cfg(feature = "block-proofs")]

use hiero_streams::{
    extract_proof_material, verify_block_proof, verify_hints, verify_schnorr, verify_wraps,
    Bootstrap, ProofPath,
};
use serde_json::Value;
use sha2::{Digest, Sha384};
use std::fs;
use std::path::Path;

fn fixtures_dir() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/tss"))
}

fn golden_reports() -> Vec<Value> {
    let golden: Value = serde_json::from_slice(
        &fs::read(fixtures_dir().join("js-verifier-golden.json")).expect("golden file"),
    )
    .expect("golden json");
    golden["reports"]
        .as_array()
        .expect("reports array")
        .iter()
        .filter(|r| r["vendored"].as_bool() == Some(true))
        .cloned()
        .collect()
}

fn sha384_hex(bytes: &[u8]) -> String {
    hex::encode(Sha384::digest(bytes))
}

/// The genesis block's bootstrap publication, which later blocks verify
/// against (the JS verifier carries it forward the same way).
fn genesis_bootstrap() -> Bootstrap {
    let bytes = fs::read(fixtures_dir().join("0.blk.gz")).expect("genesis fixture");
    extract_proof_material(&bytes)
        .expect("genesis material")
        .bootstrap
        .expect("genesis bootstrap")
}

#[test]
fn proof_material_matches_js_verifier() {
    let reports = golden_reports();
    assert!(!reports.is_empty(), "no vendored golden reports");
    let bootstrap = genesis_bootstrap();

    for report in &reports {
        let fixture = report["fixture"].as_str().unwrap();
        let bytes = fs::read(fixtures_dir().join(fixture)).expect(fixture);
        let material = extract_proof_material(&bytes).expect(fixture);

        assert_eq!(
            material.block_number.to_string(),
            report["blockNumber"].as_str().unwrap(),
            "{fixture}: block number"
        );
        assert_eq!(
            hex::encode(material.block_root),
            report["blockRootHex"].as_str().unwrap(),
            "{fixture}: block merkle root"
        );

        let layout = &material.layout;
        let expected = &report["proofLayout"];
        let expected_path = match expected["suffixKind"].as_str().unwrap() {
            "aggregate-schnorr" => ProofPath::AggregateSchnorr,
            "wraps-compressed-proof" => ProofPath::WrapsCompressedProof,
            _ => ProofPath::Unknown,
        };
        assert_eq!(layout.path, expected_path, "{fixture}: proof path");
        assert_eq!(
            layout.hints_verification_key.len()
                + layout.hints_signature.len()
                + layout.suffix.len(),
            expected["totalLength"].as_u64().unwrap() as usize,
            "{fixture}: packed signature length"
        );
        assert_eq!(
            sha384_hex(&layout.hints_verification_key),
            expected["hintsVerificationKeySha384"].as_str().unwrap(),
            "{fixture}: hints VK bytes"
        );
        assert_eq!(
            sha384_hex(&layout.hints_signature),
            expected["hintsSignatureSha384"].as_str().unwrap(),
            "{fixture}: hints signature bytes"
        );
        assert_eq!(
            sha384_hex(&layout.suffix),
            expected["suffixSha384"].as_str().unwrap(),
            "{fixture}: suffix bytes"
        );

        // Bootstrap: published in the genesis block only; every golden
        // report records the same carried-forward ledger ID.
        assert_eq!(
            hex::encode(&bootstrap.ledger_id),
            report["bootstrapLedgerIdHex"].as_str().unwrap(),
            "{fixture}: ledger ID"
        );
        assert_eq!(
            bootstrap.node_contributions.len() as u64,
            report["bootstrapContributionCount"].as_u64().unwrap(),
            "{fixture}: contribution count"
        );
        if fixture == "0.blk.gz" {
            assert!(material.bootstrap.is_some(), "genesis carries bootstrap");
        } else {
            assert!(
                material.bootstrap.is_none(),
                "{fixture}: only genesis carries the publication"
            );
        }
    }
}

#[test]
fn schnorr_verification_matches_js_verifier() {
    let bootstrap = genesis_bootstrap();

    for report in &golden_reports() {
        let fixture = report["fixture"].as_str().unwrap();
        let expected = &report["schnorrVerification"];
        let bytes = fs::read(fixtures_dir().join(fixture)).expect(fixture);
        let material = extract_proof_material(&bytes).expect(fixture);

        match expected["status"].as_str().unwrap() {
            "verified" => {
                let outcome = verify_schnorr(&material.layout, &bootstrap).expect(fixture);
                assert!(outcome.valid, "{fixture}: Schnorr must verify");
                assert_eq!(
                    outcome.signer_count as u64,
                    expected["signerCount"].as_u64().unwrap(),
                    "{fixture}: signer count"
                );
                assert_eq!(
                    outcome.total_nodes as u64,
                    expected["totalNodes"].as_u64().unwrap(),
                    "{fixture}: total nodes"
                );
            }
            "skipped" => {
                assert!(
                    verify_schnorr(&material.layout, &bootstrap).is_err(),
                    "{fixture}: non-Schnorr path must be a structural error"
                );
            }
            other => panic!("{fixture}: unexpected golden Schnorr status {other}"),
        }
    }
}

#[test]
fn hints_verification_matches_js_verifier() {
    for report in &golden_reports() {
        let fixture = report["fixture"].as_str().unwrap();
        let expected = &report["hintsVerification"];
        assert_eq!(
            expected["status"].as_str().unwrap(),
            "verified",
            "{fixture}: golden hinTS status"
        );
        let bytes = fs::read(fixtures_dir().join(fixture)).expect(fixture);
        let material = extract_proof_material(&bytes).expect(fixture);
        let checks = verify_hints(&material.layout, &material.block_root).expect(fixture);
        assert!(checks.all_passed(), "{fixture}: hinTS checks: {checks:?}");
        // Field-for-field agreement with the JS checks object
        let golden_checks = &expected["checks"];
        for (name, ours) in [
            ("thresholdMet", checks.threshold_met),
            ("blsSignatureValid", checks.bls_signature_valid),
            ("mergedKzgValid", checks.merged_kzg_valid),
            ("parsumKzgValid", checks.parsum_kzg_valid),
            ("bSkIdentityValid", checks.b_sk_identity_valid),
            ("parsumAccumulationValid", checks.parsum_accumulation_valid),
            ("parsumConstraintValid", checks.parsum_constraint_valid),
            (
                "bitmapWellFormednessValid",
                checks.bitmap_well_formedness_valid,
            ),
            ("bitmapConstraintValid", checks.bitmap_constraint_valid),
            ("degreeCheckValid", checks.degree_check_valid),
        ] {
            assert_eq!(
                Some(ours),
                golden_checks[name].as_bool(),
                "{fixture}: hinTS check {name}"
            );
        }
    }
}

#[test]
fn wraps_verification_matches_js_verifier() {
    let bootstrap = genesis_bootstrap();

    for report in &golden_reports() {
        let fixture = report["fixture"].as_str().unwrap();
        let expected = &report["wrapsVerification"];
        let bytes = fs::read(fixtures_dir().join(fixture)).expect(fixture);
        let material = extract_proof_material(&bytes).expect(fixture);

        match expected["status"].as_str().unwrap() {
            "verified" => {
                let checks = verify_wraps(&material.layout, &bootstrap).expect(fixture);
                assert!(checks.all_passed(), "{fixture}: WRAPS checks: {checks:?}");
                let golden_checks = &expected["checks"];
                for (name, ours) in [
                    ("ledgerIdMatch", checks.ledger_id_match),
                    ("hintsVkHashMatch", checks.hints_vk_hash_match),
                    ("iterationGuard", checks.iteration_guard),
                    ("uCmEIsZero", checks.u_cm_e_is_zero),
                    ("groth16Valid", checks.groth16_valid),
                    ("kzg0Valid", checks.kzg0_valid),
                    ("kzg1Valid", checks.kzg1_valid),
                ] {
                    assert_eq!(
                        Some(ours),
                        golden_checks[name].as_bool(),
                        "{fixture}: WRAPS check {name}"
                    );
                }
            }
            "skipped" => {
                assert!(
                    verify_wraps(&material.layout, &bootstrap).is_err(),
                    "{fixture}: non-WRAPS path must be a structural error"
                );
            }
            other => panic!("{fixture}: unexpected golden WRAPS status {other}"),
        }
    }
}

/// A WRAPS proof bound to a different ledger must fail the state
/// consistency check (and only that check — the SNARK itself is
/// untouched).
#[test]
fn wraps_rejects_tampered_ledger_id() {
    let mut bootstrap = genesis_bootstrap();
    bootstrap.ledger_id[0] ^= 0x01;
    let bytes = fs::read(fixtures_dir().join("467.blk.gz")).expect("wraps fixture");
    let material = extract_proof_material(&bytes).expect("wraps material");
    let checks = verify_wraps(&material.layout, &bootstrap).expect("well-formed inputs");
    assert!(!checks.ledger_id_match, "tampered ledger ID must not match");
    assert!(checks.groth16_valid, "the proof itself is untouched");
    assert!(!checks.all_passed());
}

/// Regression for a single-byte corruption of the WRAPS suffix panicking
/// instead of returning `Err` (arkworks 0.4.2's `[T; N]` deserialization
/// unwraps on malformed elements — see `wraps.rs`'s `deserialize_fixed_array`).
/// Strided rather than exhaustive: each corrupted byte that still
/// deserializes runs the full Groth16 + KZG pairing check, which is slow
/// in an unoptimized test build, and a stride of 16 still lands on the
/// leading byte of every field in the suffix's array-typed tail.
#[test]
fn wraps_never_panics_on_corrupt_suffix_byte() {
    let bootstrap = genesis_bootstrap();
    let bytes = fs::read(fixtures_dir().join("467.blk.gz")).expect("wraps fixture");
    let material = extract_proof_material(&bytes).expect("wraps material");

    for position in (0..material.layout.suffix.len()).step_by(16) {
        let mut layout = material.layout.clone();
        layout.suffix[position] ^= 0xFF;
        let _ = verify_wraps(&layout, &bootstrap);
    }
}

/// Same regression, but corrupting both fixed-size array fields at once
/// (`kzg_proofs` at suffix offset 448 and `kzg_challenges` at offset
/// 640 — see the byte-layout comment above `deserialize_fixed_array` in
/// wraps.rs). A single-field corruption already can't panic after the
/// fix, but nothing guarantees the two fields are deserialized
/// independently, so this pins that a simultaneous double corruption
/// is equally safe.
#[test]
fn wraps_never_panics_on_corrupt_suffix_both_array_fields() {
    let bootstrap = genesis_bootstrap();
    let bytes = fs::read(fixtures_dir().join("467.blk.gz")).expect("wraps fixture");
    let material = extract_proof_material(&bytes).expect("wraps material");

    for byte_in_field in 0..64usize {
        let mut layout = material.layout.clone();
        layout.suffix[448 + byte_in_field] ^= 0xFF; // kzg_proofs
        layout.suffix[640 + (byte_in_field % 64)] ^= 0xFF; // kzg_challenges
        let _ = verify_wraps(&layout, &bootstrap);
    }
}

/// A forged huge length prefix on one of the WRAPS proof's internal
/// `Vec<Fr>`/`Vec<G1Affine>` fields (arkworks encodes these with an
/// 8-byte LE length, no cap) must not hang or exhaust memory — it
/// should fail fast once the reader runs out of the suffix's fixed 704
/// bytes. `z_0`'s length prefix sits at suffix offset 32 (see the
/// byte-layout comment above `deserialize_fixed_array` in wraps.rs).
#[test]
fn wraps_rejects_forged_huge_vector_length_without_hanging() {
    let bootstrap = genesis_bootstrap();
    let bytes = fs::read(fixtures_dir().join("467.blk.gz")).expect("wraps fixture");
    let material = extract_proof_material(&bytes).expect("wraps material");

    let mut layout = material.layout.clone();
    layout.suffix[32..40].copy_from_slice(&u64::MAX.to_le_bytes());

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(verify_wraps(&layout, &bootstrap));
    });
    let result = rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("verify_wraps hung on a forged huge vector length");
    assert!(result.is_err(), "forged length must not parse as valid");
}

/// A threshold signature over a different message must fail exactly at
/// the BLS pairing check.
#[test]
fn hints_rejects_tampered_block_root() {
    let bytes = fs::read(fixtures_dir().join("0.blk.gz")).expect("genesis fixture");
    let material = extract_proof_material(&bytes).expect("genesis material");
    let mut tampered_root = material.block_root;
    tampered_root[0] ^= 0x01;
    let checks = verify_hints(&material.layout, &tampered_root).expect("well-formed inputs");
    assert!(!checks.bls_signature_valid, "tampered root must fail BLS");
    assert!(!checks.all_passed());
}

/// A signature over a tampered message must fail: flip one ledger-ID
/// byte and re-verify.
#[test]
fn schnorr_rejects_tampered_ledger_id() {
    let mut bootstrap = genesis_bootstrap();
    bootstrap.ledger_id[0] ^= 0x01;
    let bytes = fs::read(fixtures_dir().join("0.blk.gz")).expect("genesis fixture");
    let material = extract_proof_material(&bytes).expect("genesis material");
    let outcome = verify_schnorr(&material.layout, &bootstrap).expect("well-formed inputs");
    assert!(!outcome.valid, "tampered ledger ID must not verify");
}

/// The end-to-end entry point verifies every vendored fixture.
#[test]
fn verify_block_proof_end_to_end() {
    let bootstrap = genesis_bootstrap();
    for report in &golden_reports() {
        let fixture = report["fixture"].as_str().unwrap();
        let bytes = fs::read(fixtures_dir().join(fixture)).expect(fixture);
        let material = extract_proof_material(&bytes).expect(fixture);
        let verification = verify_block_proof(&material, &bootstrap).expect(fixture);
        assert!(verification.valid(), "{fixture}: {verification:?}");
    }
}

/// Truncations and bit flips of proof-bearing blocks must produce
/// errors or clean check failures, never panics — the same guarantee
/// tests/robustness.rs pins for the always-on parsers.
#[test]
fn proof_material_never_panics_on_corrupt_input() {
    let compressed = fs::read(fixtures_dir().join("467.blk.gz")).expect("wraps fixture");
    let raw = {
        use std::io::Read;
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(&compressed[..])
            .read_to_end(&mut out)
            .expect("inflate");
        out
    };
    let bootstrap = genesis_bootstrap();

    for cut in (0..raw.len()).step_by(509) {
        if let Ok(material) = extract_proof_material(&raw[..cut]) {
            let _ = verify_block_proof(&material, &bootstrap);
        }
    }
    for position in (0..raw.len()).step_by(251) {
        let mut flipped = raw.clone();
        flipped[position] ^= 0x10;
        if let Ok(material) = extract_proof_material(&flipped) {
            let _ = verify_block_proof(&material, &bootstrap);
        }
    }
}
