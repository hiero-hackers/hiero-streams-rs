//! The record-era (v6) ETL pipeline: day-grouped, threaded parse → Parquet.

use super::parquet::write_day;
use hiero_streams::{parse_record_file, verify_running_hash_chain, ParsedRecordFile};
use std::collections::BTreeMap;
use std::fs;
use std::process::ExitCode;
use std::time::Instant;

/// Run the v6 backfill over `names` (already filtered to `.rcd[.gz]` and
/// sorted). Files are grouped by the UTC day in their name prefix.
///
/// Partitioning semantics, stated deliberately: rows land in the
/// partition of the FILE that carried them. A file spanning midnight
/// (~2 s window) can therefore contribute rows whose consensus-timestamp
/// day is the next partition's date. Day-level aggregations over the
/// dataset should filter on the row's consensus_timestamp, not trust the
/// partition key as an exact day boundary.
pub(super) fn run(
    dir: &str,
    out: &str,
    names: Vec<String>,
    with_transfers: bool,
    verify_chain: bool,
    threads: usize,
    t0: Instant,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    // A stray file that doesn't follow the bucket's timestamp naming
    // fails cleanly by name instead of panicking the run.
    let mut days: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for name in names {
        let Some(day) = name.get(..10) else {
            return Err(format!("{name}: file name has no YYYY-MM-DD prefix").into());
        };
        days.entry(day.to_string()).or_default().push(name);
    }
    eprintln!("{} day(s), {threads} threads", days.len());

    let mut total_tx = 0usize;
    // last file of the previous day — chain continuity holds across
    // day boundaries too, so --verify-chain checks the seam as well
    let mut boundary: Option<ParsedRecordFile> = None;
    for (day, files) in &days {
        // threaded parse across the day's files; chunks are contiguous
        // ranges of the sorted list, so joining in chunk order
        // preserves file order (which chain verification requires).
        // A file that fails to read or parse aborts the run with a clean
        // error NAMING that file (the tool's contract) — never a panic.
        let chunk = files.len().div_ceil(threads);
        let parsed_files: Vec<ParsedRecordFile> = std::thread::scope(|s| {
            files
                .chunks(chunk)
                .map(|c| {
                    s.spawn(move || {
                        c.iter()
                            .map(|name| {
                                let bytes = fs::read(format!("{dir}/{name}"))
                                    .map_err(|e| format!("{name}: read failed: {e}"))?;
                                parse_record_file(&bytes)
                                    .map_err(|e| format!("{name}: parse failed: {e}"))
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

        if verify_chain {
            if let (Some(prev), Some(first)) = (&boundary, parsed_files.first()) {
                let pair = [prev.clone(), first.clone()];
                if let Err(e) = verify_running_hash_chain(&pair) {
                    return Err(format!(
                        "chain break at the {day} day boundary ({}): {}",
                        files[0], e.reason
                    )
                    .into());
                }
            }
            if let Err(e) = verify_running_hash_chain(&parsed_files) {
                return Err(format!(
                    "chain break within {day} at file {} ({}): {}",
                    e.index, files[e.index], e.reason
                )
                .into());
            }
            boundary = parsed_files.last().cloned();
        }

        let mut rows: Vec<_> = parsed_files
            .into_iter()
            .flat_map(|f| f.transactions)
            .collect();
        rows.sort_by(|a, b| a.consensus_timestamp.cmp(&b.consensus_timestamp));

        write_day(out, day, &rows, with_transfers)?;

        total_tx += rows.len();
        eprintln!(
            "{day}: {} files → {} transactions{}",
            files.len(),
            rows.len(),
            if verify_chain { " · chain ✓" } else { "" }
        );
    }
    eprintln!(
        "done: {total_tx} transactions across {} day(s) in {:?}",
        days.len(),
        t0.elapsed()
    );
    Ok(ExitCode::SUCCESS)
}
