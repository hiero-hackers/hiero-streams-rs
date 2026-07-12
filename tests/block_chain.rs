//! Block-to-block continuity over real block files: each block's
//! recomputed merkle root must equal the next block's footer claim.
//! Always-on (no feature gate) — continuity is a parsing-adjacent
//! integrity property, the block-era analogue of the v6 running-hash
//! chain test. Also pins `block_activity`, which reads the same
//! consensus-plumbing items.

use hiero_streams::block_activity;
use hiero_streams::block_chain_info;
use std::fs;
use std::path::Path;

fn fixtures_dir() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/tss"))
}

#[test]
fn consecutive_blocks_form_a_valid_root_chain() {
    let mut infos = Vec::new();
    for n in 0..=4u64 {
        let bytes = fs::read(fixtures_dir().join(format!("{n}.blk.gz"))).expect("fixture");
        let info = block_chain_info(&bytes).expect("chain info");
        assert_eq!(info.block_number, n, "header number matches file name");
        infos.push(info);
    }

    // The genesis footer still carries a 48-byte previous-root value (a
    // pre-genesis constant, not empty) — the chain contract starts at
    // the first block *pair*, which is also what the ETL enforces.
    for pair in infos.windows(2) {
        assert_eq!(
            pair[1].previous_block_root,
            pair[0].block_root.to_vec(),
            "block {}'s footer must claim block {}'s recomputed root",
            pair[1].block_number,
            pair[0].block_number
        );
    }
}

/// Pinned activity counts from a real mainnet preview block — the same
/// numbers that agreed exactly with the 0.0.802 staking payout list
/// (28 nodes active, same absentees).
#[test]
fn block_activity_matches_known_mainnet_preview_block() {
    let bytes = fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/block-preview/000000000000000000000000000104356004.blk.gz"
    ))
    .expect("preview fixture");
    let activity = block_activity(&bytes).expect("activity");

    assert_eq!(activity.block_number, 104356004);
    assert_eq!(activity.rounds, [253610156, 253610157, 253610158]);
    assert_eq!(activity.events_by_node.len(), 28, "28 nodes were live");
    assert_eq!(activity.total_events(), 1030);
    // spot-pin a few creators, including the busiest and the quietest
    assert_eq!(activity.events_by_node.get(&17), Some(&44));
    assert_eq!(activity.events_by_node.get(&7), Some(&27));
    assert!(
        !activity.events_by_node.contains_key(&2),
        "node 2 authored nothing in this block"
    );
}

/// The test-network genesis: three nodes, near-equal event counts.
#[test]
fn block_activity_over_genesis_fixture() {
    let bytes = fs::read(fixtures_dir().join("0.blk.gz")).expect("genesis fixture");
    let activity = block_activity(&bytes).expect("activity");
    assert_eq!(activity.block_number, 0);
    assert_eq!(
        activity.events_by_node.keys().copied().collect::<Vec<_>>(),
        [0, 1, 2],
        "the three bootstrap nodes"
    );
    assert_eq!(activity.total_events(), 181 + 180 + 179);
}
