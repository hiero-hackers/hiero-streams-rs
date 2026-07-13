//! Honest parse throughput measurement: native sequential vs threaded.
//!   cargo run --release --example parse_dir -- <dir>
use hiero_streams::parse_record_file;
use std::time::Instant;

fn main() {
    let dir = std::env::args().nth(1).expect("dir");
    let mut buffers = Vec::new();
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "gz") {
            buffers.push(std::fs::read(path).unwrap());
        }
    }
    // preloaded: measure parsing, not disk
    let t = Instant::now();
    let tx: usize = buffers
        .iter()
        .map(|b| parse_record_file(b).unwrap().transactions.len())
        .sum();
    let seq = t.elapsed();
    println!(
        "sequential: {} files, {tx} tx in {:?} ({:.0} tx/s)",
        buffers.len(),
        seq,
        tx as f64 / seq.as_secs_f64()
    );

    let threads = std::thread::available_parallelism().unwrap().get();
    let t = Instant::now();
    let chunk = buffers.len().div_ceil(threads);
    let tx: usize = std::thread::scope(|s| {
        buffers
            .chunks(chunk)
            .map(|c| {
                s.spawn(move || {
                    c.iter()
                        .map(|b| parse_record_file(b).unwrap().transactions.len())
                        .sum::<usize>()
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().unwrap())
            .sum()
    });
    let par = t.elapsed();
    println!(
        "threaded({threads}): {tx} tx in {:?} ({:.0} tx/s, {:.1}x over sequential)",
        par,
        tx as f64 / par.as_secs_f64(),
        seq.as_secs_f64() / par.as_secs_f64()
    );
}
