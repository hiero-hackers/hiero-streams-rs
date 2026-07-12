//! Signature verification against real signed fixtures: the dev-net
//! record files from the hiero-mirror-node repo and the address book
//! that actually signed them (test-v6-sidecar-4n.bin, nodes 0.0.3–6).

mod common;
use common::fixture;
use hiero_streams::{
    parse_address_book, parse_signature_file, record_file_hash, verify_node_signature,
    verify_record_file, NodeSignature,
};

const RCD: &str = "v6/2022-07-13T08_46_11.304284003Z.rcd.gz";
const SIG: &str = "v6/2022-07-13T08_46_11.304284003Z.rcd_sig";
const BOOK: &str = "test-v6-sidecar-4n.bin";

#[test]
fn parses_a_real_signature_file() {
    let sig = parse_signature_file(&fixture(SIG)).unwrap();
    assert_eq!(sig.version, 6);
    assert_eq!(sig.file_hash.len(), 48); // SHA-384
    assert_eq!(sig.file_signature.len(), 384); // RSA-3072
    assert_eq!(sig.metadata_hash.as_ref().map(Vec::len), Some(48));
}

#[test]
fn computed_hash_matches_the_signing_nodes_claim() {
    let computed = record_file_hash(&fixture(RCD)).unwrap();
    let claimed = parse_signature_file(&fixture(SIG)).unwrap().file_hash;
    assert_eq!(&computed[..], &claimed[..]);
}

#[test]
fn parses_the_address_book() {
    let book = parse_address_book(&fixture(BOOK)).unwrap();
    let nodes: Vec<_> = book.keys().cloned().collect();
    assert_eq!(nodes, ["0.0.3", "0.0.4", "0.0.5", "0.0.6"]);
}

#[test]
fn node_3_signature_verifies_and_other_keys_reject() {
    let book = parse_address_book(&fixture(BOOK)).unwrap();
    let hash = record_file_hash(&fixture(RCD)).unwrap();
    let sig = parse_signature_file(&fixture(SIG)).unwrap();
    assert!(verify_node_signature(&hash, &sig.file_signature, &book["0.0.3"]).unwrap());
    assert!(!verify_node_signature(&hash, &sig.file_signature, &book["0.0.4"]).unwrap());
}

#[test]
fn verify_record_file_classifies_and_applies_threshold() {
    let book = parse_address_book(&fixture(BOOK)).unwrap();
    let result = verify_record_file(
        &fixture(RCD),
        &[
            NodeSignature {
                node: "0.0.3".into(),
                bytes: fixture(SIG),
            },
            NodeSignature {
                node: "0.0.4".into(),
                bytes: fixture(SIG), // wrong node's signature
            },
            NodeSignature {
                node: "0.0.99".into(), // not in the book
                bytes: fixture(SIG),
            },
        ],
        &book,
    )
    .unwrap();
    assert_eq!(result.valid, ["0.0.3"]);
    assert_eq!(result.invalid, ["0.0.4"]);
    assert_eq!(result.unknown, ["0.0.99"]);
    assert_eq!(result.node_count, 4);
    // 1 of 4 < 1/3 — a single node cannot attest for the network.
    assert!(!result.attested);
}

#[test]
fn tampered_record_file_fails_verification() {
    use flate2::read::GzDecoder;
    use std::io::Read;
    let mut inflated = Vec::new();
    GzDecoder::new(&fixture(RCD)[..])
        .read_to_end(&mut inflated)
        .unwrap();
    *inflated.last_mut().unwrap() ^= 0xff;
    let book = parse_address_book(&fixture(BOOK)).unwrap();
    let result = verify_record_file(
        &inflated,
        &[NodeSignature {
            node: "0.0.3".into(),
            bytes: fixture(SIG),
        }],
        &book,
    )
    .unwrap();
    assert!(result.valid.is_empty());
    assert_eq!(result.invalid, ["0.0.3"]);
}

// ── metadata + chain (phase-5 roadmap) ─────────────────────────────

const RCD_PREV: &str = "v6/2022-07-13T08_46_08.041986003Z.rcd.gz";

#[test]
fn metadata_hash_matches_the_signing_nodes_claim() {
    let computed = hiero_streams::record_file_metadata_hash(&fixture(RCD)).unwrap();
    let claimed = parse_signature_file(&fixture(SIG))
        .unwrap()
        .metadata_hash
        .unwrap();
    assert_eq!(&computed[..], &claimed[..]);
}

#[test]
fn metadata_signature_verifies_with_the_signing_key() {
    let book = parse_address_book(&fixture(BOOK)).unwrap();
    assert!(
        hiero_streams::verify_metadata_signature(&fixture(RCD), &fixture(SIG), &book["0.0.3"])
            .unwrap()
    );
    assert!(!hiero_streams::verify_metadata_signature(
        &fixture(RCD),
        &fixture(SIG),
        &book["0.0.4"]
    )
    .unwrap());
}

#[test]
fn consecutive_fixtures_form_a_valid_running_hash_chain() {
    let a = hiero_streams::parse_record_file(&fixture(RCD_PREV)).unwrap();
    let b = hiero_streams::parse_record_file(&fixture(RCD)).unwrap();
    assert_eq!(a.block_number + 1, b.block_number);
    hiero_streams::verify_running_hash_chain(&[a, b]).unwrap();
}

#[test]
fn chain_breaks_are_detected_and_located() {
    let a = hiero_streams::parse_record_file(&fixture(RCD_PREV)).unwrap();
    let mut b = hiero_streams::parse_record_file(&fixture(RCD)).unwrap();
    b.start_running_hash[0] ^= 0xff;
    let err = hiero_streams::verify_running_hash_chain(&[a.clone(), b]).unwrap_err();
    assert_eq!(err.index, 1);
    assert!(err.reason.contains("running hash"));

    let mut c = hiero_streams::parse_record_file(&fixture(RCD)).unwrap();
    c.block_number += 5; // gap
    let err = hiero_streams::verify_running_hash_chain(&[a, c]).unwrap_err();
    assert!(err.reason.contains("block number gap"));
}

#[test]
fn detect_format_identifies_v6_and_unknowns() {
    use hiero_streams::Format;
    assert_eq!(
        hiero_streams::detect_format(&fixture(RCD)).unwrap(),
        Format::RecordFileV6
    );
    let mut bogus = vec![0u8; 8];
    bogus[3] = 7;
    assert_eq!(
        hiero_streams::detect_format(&bogus).unwrap(),
        Format::Unknown(7)
    );
}
