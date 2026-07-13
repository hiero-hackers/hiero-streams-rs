//! Mini analytics straight off the parser — top fee payers and
//! per-type fee totals for a directory of record files:
//!   cargo run --release --example fee_report -- <dir>
use hiero_streams::parse_record_file;
use std::collections::HashMap;

fn main() {
    let dir = std::env::args().nth(1).expect("usage: fee_report <dir>");
    let mut by_payer: HashMap<String, u64> = HashMap::new();
    let mut by_type: HashMap<String, u64> = HashMap::new();
    let mut total = 0u64;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "gz") {
            continue;
        }
        for tx in parse_record_file(&std::fs::read(path).unwrap())
            .unwrap()
            .transactions
        {
            *by_payer.entry(tx.payer).or_default() += tx.charged_fee_tinybar;
            *by_type.entry(tx.tx_type).or_default() += tx.charged_fee_tinybar;
            total += tx.charged_fee_tinybar;
        }
    }
    let hbar = |t: u64| t as f64 / 1e8;
    println!("total fees: {:.4} ℏ", hbar(total));
    let mut payers: Vec<_> = by_payer.into_iter().collect();
    payers.sort_by_key(|(_, v)| std::cmp::Reverse(*v));
    println!("top fee payers:");
    for (payer, fees) in payers.iter().take(10) {
        println!("  {payer:<12} {:.4} ℏ", hbar(*fees));
    }
    let mut types: Vec<_> = by_type.into_iter().collect();
    types.sort_by_key(|(_, v)| std::cmp::Reverse(*v));
    println!("fees by type:");
    for (t, fees) in types.iter().take(8) {
        println!("  {t:<28} {:.4} ℏ", hbar(*fees));
    }
}
