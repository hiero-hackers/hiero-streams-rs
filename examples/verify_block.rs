//! Verify a block-stream block's in-band proof (HIP-1056) against the
//! bundled fixtures — no network, no setup:
//!   cargo run --features block-proofs --example verify_block
//!
//! Unlike the v6 era (fetch each node's signature, check ≥⅓ of the
//! address book), a block carries one self-contained proof: a hinTS
//! threshold signature over the block's recomputed merkle root, plus a
//! suffix (aggregate Schnorr for genesis/pre-settled blocks, WRAPS
//! Groth16+KZG once history settles). The ledger-ID publication that
//! anchors it all lives only in the genesis block, so a non-genesis
//! block is verified against the genesis block passed alongside it.

use hiero_streams::{extract_proof_material, resolve_bootstrap, verify_block_proof};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/tss/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn report(label: &str, block: &[u8], genesis: Option<&[u8]>) {
    let material = extract_proof_material(block).unwrap();
    // The genesis block carries its own bootstrap; later blocks reuse
    // the genesis one passed here.
    let bootstrap = resolve_bootstrap(&material, genesis, "pass the genesis block").unwrap();
    let verification = verify_block_proof(&material, &bootstrap).unwrap();

    println!("{label}");
    println!("  block number : {}", material.block_number);
    println!("  block root   : {}", hex::encode(material.block_root));
    println!("  proof path   : {:?}", material.layout.path);
    println!("  hinTS ok     : {}", verification.hints.all_passed());
    if let Some(s) = &verification.schnorr {
        println!(
            "  schnorr ok   : {} ({}/{} signers)",
            s.valid, s.signer_count, s.total_nodes
        );
    }
    if let Some(w) = &verification.wraps {
        println!("  wraps ok     : {}", w.all_passed());
    }
    println!("  VERIFIED     : {}\n", verification.valid());
}

fn main() {
    let genesis = fixture("0.blk.gz");
    // Genesis: carries its own ledger-ID publication, Schnorr suffix.
    report("genesis block (aggregate Schnorr)", &genesis, None);
    // A settled block: WRAPS proof, verified against the genesis bootstrap.
    report("block 467 (WRAPS)", &fixture("467.blk.gz"), Some(&genesis));
}
