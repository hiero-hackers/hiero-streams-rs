//! Snapshot regression: the committed golden file pins the exact
//! canonical-JSON output for the signed dev-net fixtures, so refactors
//! cannot silently change what consumers receive. Correctness itself is
//! grounded elsewhere (network-signed metadata hashes, the mirror-node
//! differential in `record_mirror_differential.rs`); this test guards shape
//! and value stability.
//!
//! To regenerate after an INTENTIONAL output change:
//! `cargo run -- parse <fixture>` per file and update golden-v6.json —
//! then treat the diff as the reviewable contract change it is.

mod common;
use common::fixture;
use hiero_streams::{parse_record_file, record_file_to_json_value};
use serde_json::Value;

/// Render the parse result via the library's own serializer, so this
/// asserts exactly what consumers receive.
fn to_golden_shape(bytes: &[u8]) -> Value {
    record_file_to_json_value(&parse_record_file(bytes).unwrap())
}

#[test]
fn output_matches_committed_snapshot() {
    let golden: Value =
        serde_json::from_slice(&fixture("golden-v6.json")).expect("golden fixture parses");
    let files = golden.as_object().expect("golden is an object");
    assert!(!files.is_empty());
    for (name, expected) in files {
        let actual = to_golden_shape(&fixture(&format!("v6/{name}")));
        assert_eq!(
            &actual, expected,
            "output diverges from the committed snapshot for {name}"
        );
    }
}

#[test]
fn rejects_non_v6_versions() {
    let mut bogus = vec![0u8; 8];
    bogus[3] = 5;
    let err = parse_record_file(&bogus).unwrap_err();
    assert!(err.to_string().contains("version 5"), "{err}");
    assert!(parse_record_file(&[0u8; 2]).is_err());
}

#[test]
fn accepts_pre_inflated_bytes() {
    use flate2::read::GzDecoder;
    use std::io::Read;
    let gz = fixture("v6/2022-07-13T08_46_08.041986003Z.rcd.gz");
    let mut inflated = Vec::new();
    GzDecoder::new(&gz[..]).read_to_end(&mut inflated).unwrap();
    assert_eq!(
        parse_record_file(&gz).unwrap(),
        parse_record_file(&inflated).unwrap(),
    );
}
