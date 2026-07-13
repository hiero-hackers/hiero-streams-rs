//! The block-era (HIP-1056) ETL pipeline. Differences from the v6 path,
//! stated deliberately:
//!
//! - **Ordering & continuity come from the block headers**, not file
//!   names: files are parsed in any order, sorted by header block number,
//!   and `--verify-chain` asserts numbers are gapless AND each footer's
//!   previous-root claim equals the previous block's recomputed merkle
//!   root (the block-era analogue of the v6 running-hash chain).
//! - **Rows land in the partition of their own consensus day** (block
//!   file names carry no date), so the partition key IS the row's day —
//!   stricter than the v6 file-carried partition semantics.
//! - The whole input set is parsed before writing (day grouping needs
//!   it). Preview-era corpora are small; revisit if backfilling months of
//!   GA blocks.

use super::parquet::write_day;
use hiero_streams::{block_chain_info, parse_block, BlockChainInfo, ParsedTransaction};
use std::collections::BTreeMap;
use std::fs;
use std::process::ExitCode;
use std::time::Instant;

/// Run the block backfill over `names` (already filtered to `.blk[.gz]`).
pub(super) fn run(
    dir: &str,
    out: &str,
    names: Vec<String>,
    with_transfers: bool,
    verify_chain: bool,
    threads: usize,
    t0: Instant,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    struct BlockFile {
        name: String,
        info: BlockChainInfo,
        transactions: Vec<ParsedTransaction>,
    }

    eprintln!("{} block file(s), {threads} threads", names.len());
    let chunk = names.len().div_ceil(threads).max(1);
    let mut blocks: Vec<BlockFile> = std::thread::scope(|s| {
        names
            .chunks(chunk)
            .map(|c| {
                s.spawn(move || {
                    c.iter()
                        .map(|name| {
                            let bytes = fs::read(format!("{dir}/{name}"))
                                .map_err(|e| format!("{name}: read failed: {e}"))?;
                            let parsed = parse_block(&bytes)
                                .map_err(|e| format!("{name}: parse failed: {e}"))?;
                            let info = block_chain_info(&bytes)
                                .map_err(|e| format!("{name}: chain info failed: {e}"))?;
                            Ok(BlockFile {
                                name: name.clone(),
                                info,
                                transactions: parsed.transactions,
                            })
                        })
                        .collect::<Result<Vec<_>, String>>()
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().expect("parse worker panicked"))
            .collect::<Result<Vec<_>, String>>()
            .map(|chunks| chunks.into_iter().flatten().collect::<Vec<_>>())
    })?;
    blocks.sort_by_key(|b| b.info.block_number);

    if verify_chain {
        for pair in blocks.windows(2) {
            let (prev, next) = (&pair[0], &pair[1]);
            // checked_add: block_number is attacker-controlled; a crafted
            // u64::MAX must not overflow (a panic) — treat it as a gap.
            if Some(next.info.block_number) != prev.info.block_number.checked_add(1) {
                return Err(format!(
                    "block gap: {} (block {}) is followed by {} (block {})",
                    prev.name, prev.info.block_number, next.name, next.info.block_number
                )
                .into());
            }
            if next.info.previous_block_root != prev.info.block_root {
                return Err(format!(
                    "chain break at {} (block {}): footer's previous-root claim does not \
                     match the recomputed root of {} (block {})",
                    next.name, next.info.block_number, prev.name, prev.info.block_number
                )
                .into());
            }
        }
    }

    let mut days: BTreeMap<String, Vec<ParsedTransaction>> = BTreeMap::new();
    for block in blocks {
        for tx in block.transactions {
            days.entry(tx.day.clone()).or_default().push(tx);
        }
    }

    let mut total_tx = 0usize;
    for (day, mut rows) in days {
        rows.sort_by(|a, b| a.consensus_timestamp.cmp(&b.consensus_timestamp));
        write_day(out, &day, &rows, with_transfers)?;
        total_tx += rows.len();
        eprintln!(
            "{day}: {} transactions{}",
            rows.len(),
            if verify_chain { " · chain ✓" } else { "" }
        );
    }
    eprintln!(
        "done: {total_tx} transactions across {} block file(s) in {:?}",
        names.len(),
        t0.elapsed()
    );
    Ok(ExitCode::SUCCESS)
}
