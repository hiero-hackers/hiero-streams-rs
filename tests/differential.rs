//! Differential test: this crate's output must match, field for field,
//! the golden dump from the reference TypeScript parser
//! (hiero-recordstreams), which is itself validated byte-exact against
//! mainnet via the mirror node REST API.
//!
//! Regenerate the golden file with the `golden-dump` script in the
//! hiero-recordstreams repo whenever the fixtures change.

use hiero_streams::parse_record_file;
use serde_json::{json, Value};
use std::fs;
use std::path::Path;

fn fixture(name: &str) -> Vec<u8> {
    fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("tests/fixtures/{name}"))).unwrap()
}

/// Render the Rust parse result in the golden dump's JSON shape.
fn to_golden_shape(bytes: &[u8]) -> Value {
    let file = parse_record_file(bytes).unwrap();
    json!({
        "version": file.version,
        "blockNumber": file.block_number.to_string(),
        "hapiVersion": file.hapi_version,
        "transactions": file.transactions.iter().map(|t| json!({
            "consensusTimestamp": t.consensus_timestamp,
            "day": t.day,
            "payer": t.payer,
            "type": t.tx_type,
            "resultCode": t.result_code,
            "result": t.result,
            "chargedFeeTinybar": t.charged_fee_tinybar.to_string(),
            "transfers": t.transfers.iter().map(|l| json!({
                "account": l.account,
                "amount": l.amount.to_string(),
            })).collect::<Vec<_>>(),
            "tokenTransfers": t.token_transfers.iter().map(|l| json!({
                "token": l.token,
                "account": l.account,
                "amount": l.amount.to_string(),
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
    })
}

#[test]
fn matches_typescript_reference_field_for_field() {
    let golden: Value =
        serde_json::from_slice(&fixture("golden-v6.json")).expect("golden fixture parses");
    let files = golden.as_object().expect("golden is an object");
    assert!(!files.is_empty());
    for (name, expected) in files {
        let actual = to_golden_shape(&fixture(&format!("v6/{name}")));
        assert_eq!(
            &actual, expected,
            "Rust output diverges from TS reference for {name}"
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
