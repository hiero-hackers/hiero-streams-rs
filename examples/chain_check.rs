//! Prove a directory of record files is a gapless, un-reordered
//! sequence via the running-hash chain:
//!   cargo run --release --example chain_check -- <dir>
use hiero_streams::{parse_record_file, verify_running_hash_chain};

fn main() {
    let dir = std::env::args().nth(1).expect("usage: chain_check <dir>");
    let mut names: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| n.ends_with(".rcd.gz"))
        .collect();
    names.sort();
    let files: Vec<_> = names
        .iter()
        .map(|n| parse_record_file(&std::fs::read(format!("{dir}/{n}")).unwrap()).unwrap())
        .collect();
    match verify_running_hash_chain(&files) {
        Ok(()) => println!(
            "chain intact: {} files, blocks {}..={}, gapless and un-reordered",
            files.len(),
            files.first().map_or(0, |f| f.block_number),
            files.last().map_or(0, |f| f.block_number),
        ),
        Err(e) => println!(
            "CHAIN BREAK at file #{} ({}): {}",
            e.index, names[e.index], e.reason
        ),
    }
}
