//! `etl` — the native threaded backfill pipeline.
//!
//! A local directory of `.rcd.gz` OR `.blk.gz` files (the era is detected
//! from the extensions; mixing them is an error) → threaded parse →
//! Parquet, day-partitioned with identical schemas either way:
//!
//!   <out>/transactions/day=YYYY-MM-DD/data.parquet
//!       consensus_timestamp, payer, type, result, result_code, fee_tinybar
//!   <out>/transfers/day=YYYY-MM-DD/data.parquet      (--transfers)
//!       consensus_timestamp, account, amount, token (NULL = HBAR leg)
//!
//! `--verify-chain` is era-appropriate: the v6 running-hash chain for
//! record files; block-number gaplessness plus recomputed-root ==
//! footer-claim continuity for blocks.
//!
//! This entry point parses the arguments and dispatches to the era
//! pipeline ([`record`] or [`block`]); the Parquet sink they share is
//! [`parquet`].
//!
//! Download first (fast + resumable), then run this:
//!   gcloud storage cp "gs://hedera-mainnet-streams/recordstreams/record0.0.3/2026-07-*" dir/
//!   hiero-streams etl --dir dir --out data --transfers

mod block;
mod parquet;
mod record;

use std::fs;
use std::process::ExitCode;
use std::time::Instant;

pub fn run(args: &[String]) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let dir = super::flag(args, "--dir").ok_or("--dir <input dir> required")?;
    let out = super::flag(args, "--out").ok_or("--out <dataset dir> required")?;
    let with_transfers = args.iter().any(|a| a == "--transfers");
    let verify_chain = args.iter().any(|a| a == "--verify-chain");
    let threads: usize = super::flag(args, "--threads")
        .and_then(|t| t.parse().ok())
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(4, |n| n.get()));

    let t0 = Instant::now();
    let all_names: Vec<String> = fs::read_dir(&dir)?
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .collect();
    let mut names: Vec<String> = all_names
        .iter()
        .filter(|n| n.ends_with(".rcd.gz") || n.ends_with(".rcd"))
        .cloned()
        .collect();
    let mut block_names: Vec<String> = all_names
        .iter()
        .filter(|n| n.ends_with(".blk.gz") || n.ends_with(".blk"))
        .cloned()
        .collect();
    if !names.is_empty() && !block_names.is_empty() {
        return Err(
            "input directory mixes record files (.rcd) and block files (.blk) — \
                    run the eras separately"
                .into(),
        );
    }
    if !block_names.is_empty() {
        block_names.sort();
        return block::run(
            &dir,
            &out,
            block_names,
            with_transfers,
            verify_chain,
            threads,
            t0,
        );
    }
    names.sort();
    record::run(&dir, &out, names, with_transfers, verify_chain, threads, t0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> String {
        format!("{}/tests/fixtures/tss/{name}", env!("CARGO_MANIFEST_DIR"))
    }

    /// Fresh input/output dirs for one test; callers copy fixtures in.
    fn test_dirs(tag: &str) -> (String, String) {
        let base =
            std::env::temp_dir().join(format!("hiero-etl-test-{}-{tag}", std::process::id()));
        let input = base.join("in");
        let output = base.join("out");
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&input).expect("input dir");
        (
            input.to_str().expect("utf8 path").to_string(),
            output.to_str().expect("utf8 path").to_string(),
        )
    }

    fn etl_args(input: &str, output: &str) -> Vec<String> {
        [
            "--dir",
            input,
            "--out",
            output,
            "--transfers",
            "--verify-chain",
            "--threads",
            "2",
        ]
        .map(String::from)
        .to_vec()
    }

    #[test]
    fn block_etl_writes_partitions_and_verifies_chain() {
        let (input, output) = test_dirs("blocks-ok");
        for n in 0..=4 {
            let name = format!("{n}.blk.gz");
            fs::copy(fixture(&name), format!("{input}/{name}")).expect("copy fixture");
        }

        let code = run(&etl_args(&input, &output)).expect("block ETL runs");
        assert_eq!(code, ExitCode::SUCCESS);

        let day_dirs: Vec<String> = fs::read_dir(format!("{output}/transactions"))
            .expect("transactions dir")
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .collect();
        assert!(!day_dirs.is_empty(), "at least one day partition");
        for day_dir in &day_dirs {
            assert!(
                day_dir.starts_with("day="),
                "hive-style partition: {day_dir}"
            );
            let data = format!("{output}/transactions/{day_dir}/data.parquet");
            assert!(
                fs::metadata(&data).expect("partition file").len() > 0,
                "{data} is non-empty"
            );
        }
    }

    #[test]
    fn block_etl_rejects_a_gap_in_block_numbers() {
        let (input, output) = test_dirs("blocks-gap");
        for n in [0, 1, 3, 4] {
            let name = format!("{n}.blk.gz");
            fs::copy(fixture(&name), format!("{input}/{name}")).expect("copy fixture");
        }

        let err = run(&etl_args(&input, &output)).expect_err("gap must abort the run");
        let message = err.to_string();
        assert!(
            message.contains("block gap"),
            "names the failure: {message}"
        );
        assert!(
            message.contains("1.blk.gz") && message.contains("3.blk.gz"),
            "names both files at the gap: {message}"
        );
    }

    #[test]
    fn etl_rejects_mixed_era_input() {
        let (input, output) = test_dirs("mixed");
        fs::copy(fixture("0.blk.gz"), format!("{input}/0.blk.gz")).expect("copy block");
        let rcd = format!(
            "{}/tests/fixtures/v6/2022-07-13T08_46_08.041986003Z.rcd.gz",
            env!("CARGO_MANIFEST_DIR")
        );
        fs::copy(
            &rcd,
            format!("{input}/2022-07-13T08_46_08.041986003Z.rcd.gz"),
        )
        .expect("copy record");

        let err = run(&etl_args(&input, &output)).expect_err("mixed input must abort");
        assert!(err.to_string().contains("mixes record files"), "{err}");
    }
}
