//! Minimal parse: one record file → human-readable transaction lines.
//!   cargo run --example parse_one -- [file.rcd.gz]
//! (defaults to a bundled real-network fixture — runs with zero setup)
use hiero_streams::parse_record_file;

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/v6/2022-07-13T08_46_11.304284003Z.rcd.gz"
        )
        .to_string()
    });
    let file = parse_record_file(&std::fs::read(&path).unwrap()).unwrap();
    println!(
        "block {} · HAPI {} · {} transaction(s)",
        file.block_number,
        file.hapi_version,
        file.transactions.len()
    );
    for tx in &file.transactions {
        println!(
            "  {} {:<24} payer={:<10} fee={} tℏ {}",
            tx.consensus_timestamp, tx.tx_type, tx.payer, tx.charged_fee_tinybar, tx.result
        );
    }
}
