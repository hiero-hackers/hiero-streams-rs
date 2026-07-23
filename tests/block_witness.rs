//! Merkle inclusion witnesses over real block fixtures.
//!
//! The correctness anchor is the network's own signatures, not "our
//! tests pass": a `BlockInclusionWitness` for a transaction must
//! recompute the exact `block_root` that [`extract_proof_material`]
//! derives from the whole block — the message the hinTS threshold
//! signature signs — and that root must pass `verify_block_proof`
//! against the resolved bootstrap.

use hiero_streams::{
    block_inclusion_witness, extract_proof_material, fold_witness, merkle_root,
    recompute_block_root, witness_for, Side,
};
use sha2::{Digest, Sha384};
use std::fs;
use std::path::Path;

fn fixtures_dir() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/tss"))
}

/// The tss fixtures that carry a `TssSignedBlockProof` (the same set the
/// differential test uses); each has a recomputable block root.
const FIXTURES: &[&str] = &["0.blk.gz", "1.blk.gz", "2.blk.gz", "3.blk.gz", "4.blk.gz"];

fn leaf_hash(i: u64) -> [u8; 48] {
    let mut h = Sha384::new();
    h.update([0x00]);
    h.update(i.to_be_bytes());
    h.finalize().into()
}

/// Generic MMR witness contract over the public API: for a spread of
/// leaf counts — including powers of two and their neighbours, where the
/// peak structure changes shape — every leaf's witness folds back to the
/// tree root.
#[test]
fn generic_witnesses_fold_to_the_root() {
    let counts = [
        1usize, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 100, 127, 128, 129,
    ];
    for &n in &counts {
        let leaves: Vec<[u8; 48]> = (0..n as u64).map(leaf_hash).collect();
        let root = merkle_root(&leaves);
        for i in 0..n {
            let w = witness_for(&leaves, i);
            assert_eq!(fold_witness(leaves[i], &w), root, "count {n}, index {i}");
        }
    }
}

/// Every signed transaction in every committed fixture block: its
/// inclusion witness recomputes the same `block_root` the full-block
/// extraction produces.
#[test]
fn block_witnesses_recompute_the_block_root() {
    for fixture in FIXTURES {
        let bytes = fs::read(fixtures_dir().join(fixture)).expect(fixture);
        let expected = extract_proof_material(&bytes).expect(fixture).block_root;

        let mut count = 0usize;
        while let Ok((tx_bytes, witness)) = block_inclusion_witness(&bytes, count) {
            assert_eq!(
                recompute_block_root(&tx_bytes, &witness),
                expected,
                "{fixture}: transaction {count} must recompute the block root"
            );
            count += 1;
        }
        assert!(
            count > 0,
            "{fixture}: expected at least one signed transaction"
        );
    }
}

/// Negative tests: a tampered leaf, a reordered sibling path, and a
/// wrong-orientation `Side` must each break the recomputed root.
#[test]
fn tampering_breaks_the_recomputed_root() {
    let fixture = "0.blk.gz";
    let bytes = fs::read(fixtures_dir().join(fixture)).expect(fixture);
    let expected = extract_proof_material(&bytes).expect(fixture).block_root;
    let (tx_bytes, witness) = block_inclusion_witness(&bytes, 0).expect("witness");

    // Sanity: the untouched witness recomputes the real root.
    assert_eq!(recompute_block_root(&tx_bytes, &witness), expected);

    // Tampered transaction bytes.
    let mut bad_tx = tx_bytes.clone();
    bad_tx[0] ^= 0x01;
    assert_ne!(recompute_block_root(&bad_tx, &witness), expected);

    // Reordered sibling path (only when the peak has depth ≥ 2).
    if witness.input_witness.siblings.len() >= 2 {
        let mut reordered = witness.clone();
        reordered.input_witness.siblings.swap(0, 1);
        assert_ne!(recompute_block_root(&tx_bytes, &reordered), expected);
    }

    // Wrong-orientation Side on the first sibling.
    if !witness.input_witness.siblings.is_empty() {
        let mut flipped = witness.clone();
        flipped.input_witness.siblings[0].0 = match flipped.input_witness.siblings[0].0 {
            Side::Left => Side::Right,
            Side::Right => Side::Left,
        };
        assert_ne!(recompute_block_root(&tx_bytes, &flipped), expected);
    }
}

/// The end-to-end contract: a witness-recomputed root is not just equal
/// to the extracted root, it is the message a valid proof signs. For
/// each fixture, recompute the root from one transaction's witness and
/// confirm the block's own proof verifies against the resolved
/// bootstrap over that same root.
#[cfg(feature = "block-proofs")]
#[test]
fn recomputed_root_carries_a_valid_proof() {
    use hiero_streams::{resolve_bootstrap, verify_block_proof};

    let genesis = fs::read(fixtures_dir().join("0.blk.gz")).expect("genesis");

    for fixture in FIXTURES {
        let bytes = fs::read(fixtures_dir().join(fixture)).expect(fixture);
        let material = extract_proof_material(&bytes).expect(fixture);
        let bootstrap =
            resolve_bootstrap(&material, Some(&genesis), "pass the genesis block").expect(fixture);

        let (tx_bytes, witness) = block_inclusion_witness(&bytes, 0).expect(fixture);
        assert_eq!(
            recompute_block_root(&tx_bytes, &witness),
            material.block_root,
            "{fixture}: witness root must equal the extracted root"
        );

        let verification = verify_block_proof(&material, &bootstrap).expect(fixture);
        assert!(
            verification.valid(),
            "{fixture}: the proof over the recomputed root must verify"
        );
    }
}
