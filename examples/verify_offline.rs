//! Full offline verification against the bundled, genuinely signed
//! fixtures — no network, no setup:
//!   cargo run --example verify_offline
use hiero_streams::*;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn main() {
    let rcd = fixture("v6/2022-07-13T08_46_11.304284003Z.rcd.gz");
    let sig = fixture("v6/2022-07-13T08_46_11.304284003Z.rcd_sig");
    let book = parse_address_book(&fixture("test-v6-sidecar-4n.bin")).unwrap();

    let hash = record_file_hash(&rcd).unwrap();
    let parsed_sig = parse_signature_file(&sig).unwrap();
    println!("file hash        : {}", hex::encode(hash));
    println!("hash matches sig : {}", parsed_sig.file_hash == hash);

    let key = &book["0.0.3"];
    println!(
        "file signature   : {}",
        verify_node_signature(&hash, &parsed_sig.file_signature, key).unwrap()
    );
    println!(
        "metadata sig     : {}",
        verify_metadata_signature(&rcd, &sig, key).unwrap()
    );
}
