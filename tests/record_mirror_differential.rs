//! Network-grounded differential: our parse of real MAINNET record files
//! against the mirror node's independent decoding of the same consensus
//! window — the network team's own implementation as the reference.
//!
//! The mirror fixtures were fetched once from
//! `mainnet.mirrornode.hedera.com/api/v1/transactions` for exactly the
//! consensus window each record file spans, then committed
//! (`tests/fixtures/mainnet/mirror-*.json`), so this test runs offline.
//! Because record files are the network's complete output, every
//! transaction the mirror reports in the window must appear in our parse
//! and vice versa — set equality, not just spot checks.

use hiero_streams::parse_record_file;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;

fn fixture(path: &str) -> Vec<u8> {
    fs::read(format!(
        "{}/tests/fixtures/{path}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

/// Every committed mainnet record file; each must have a matching
/// mirror-*.json fixture — adding coverage is dropping in a pair.
fn mainnet_files() -> Vec<String> {
    let dir = format!("{}/tests/fixtures/mainnet", env!("CARGO_MANIFEST_DIR"));
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| n.ends_with(".rcd.gz"))
        .map(|n| n.trim_end_matches(".rcd.gz").to_string())
        .collect();
    names.sort();
    assert!(names.len() >= 19, "mainnet fixture set went missing?");
    names
}

/// Mirror `name` ("CRYPTOTRANSFER", "NODE_STAKE_UPDATE") vs our oneof
/// case name ("cryptoTransfer", "nodeStakeUpdate"): uppercase ours and
/// strip the mirror's underscores.
fn same_type(ours: &str, mirror: &str) -> bool {
    ours.to_uppercase() == mirror.replace('_', "")
}

#[test]
fn mainnet_files_agree_with_the_mirror_node() {
    for name in mainnet_files() {
        let name = name.as_str();
        let parsed = parse_record_file(&fixture(&format!("mainnet/{name}.rcd.gz"))).unwrap();
        let mirror: Value =
            serde_json::from_slice(&fixture(&format!("mainnet/mirror-{name}.json"))).unwrap();
        let mirror_txs = mirror["transactions"].as_array().unwrap();

        assert_eq!(
            parsed.transactions.len(),
            mirror_txs.len(),
            "{name}: transaction count differs from the mirror"
        );

        let by_ts: BTreeMap<&str, &Value> = mirror_txs
            .iter()
            .map(|t| (t["consensus_timestamp"].as_str().unwrap(), t))
            .collect();

        for tx in &parsed.transactions {
            let m = by_ts
                .get(tx.consensus_timestamp.as_str())
                .unwrap_or_else(|| panic!("{name}: {} not on mirror", tx.consensus_timestamp));

            assert!(
                same_type(&tx.tx_type, m["name"].as_str().unwrap()),
                "{name}: type {} vs mirror {}",
                tx.tx_type,
                m["name"]
            );
            assert_eq!(
                tx.result,
                m["result"].as_str().unwrap(),
                "{name}: result differs at {}",
                tx.consensus_timestamp
            );
            assert_eq!(
                tx.charged_fee_tinybar,
                m["charged_tx_fee"].as_u64().unwrap(),
                "{name}: fee differs at {}",
                tx.consensus_timestamp
            );
            // Payer is the transaction id's account prefix ("0.0.X-sec-nano").
            if !tx.payer.is_empty() {
                let id = m["transaction_id"].as_str().unwrap();
                assert!(
                    id.starts_with(&format!("{}-", tx.payer)),
                    "{name}: payer {} vs mirror id {id}",
                    tx.payer
                );
            }

            let mut ours: Vec<(String, i64)> = tx
                .transfers
                .iter()
                .map(|l| (l.account.clone(), l.amount))
                .collect();
            let mut theirs: Vec<(String, i64)> = m["transfers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|l| {
                    (
                        l["account"].as_str().unwrap().to_string(),
                        l["amount"].as_i64().unwrap(),
                    )
                })
                .collect();
            ours.sort();
            theirs.sort();
            assert_eq!(
                ours, theirs,
                "{name}: transfer list differs at {}",
                tx.consensus_timestamp
            );

            let mut ours_tok: Vec<(String, String, i64)> = tx
                .token_transfers
                .iter()
                .map(|l| (l.token.clone(), l.account.clone(), l.amount))
                .collect();
            let mut theirs_tok: Vec<(String, String, i64)> = m["token_transfers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|l| {
                    (
                        l["token"].as_str().unwrap().to_string(),
                        l["account"].as_str().unwrap().to_string(),
                        l["amount"].as_i64().unwrap(),
                    )
                })
                .collect();
            ours_tok.sort();
            theirs_tok.sort();
            assert_eq!(
                ours_tok, theirs_tok,
                "{name}: token transfers differ at {}",
                tx.consensus_timestamp
            );

            // NFT legs: (token, sender, receiver, serial, approval), ""
            // where the mirror reports null (mint/burn/wipe sides).
            let mut ours_nft: Vec<(String, String, String, i64, bool)> = tx
                .nft_transfers
                .iter()
                .map(|l| {
                    (
                        l.token.to_string(),
                        l.sender.map(|a| a.to_string()).unwrap_or_default(),
                        l.receiver.map(|a| a.to_string()).unwrap_or_default(),
                        l.serial_number,
                        l.is_approval,
                    )
                })
                .collect();
            let mut theirs_nft: Vec<(String, String, String, i64, bool)> = m["nft_transfers"]
                .as_array()
                .map(|legs| {
                    legs.iter()
                        .map(|l| {
                            (
                                l["token_id"].as_str().unwrap().to_string(),
                                l["sender_account_id"].as_str().unwrap_or("").to_string(),
                                l["receiver_account_id"].as_str().unwrap_or("").to_string(),
                                l["serial_number"].as_i64().unwrap(),
                                l["is_approval"].as_bool().unwrap_or(false),
                            )
                        })
                        .collect()
                })
                .unwrap_or_default();
            ours_nft.sort();
            theirs_nft.sort();
            assert_eq!(
                ours_nft, theirs_nft,
                "{name}: NFT transfers differ at {}",
                tx.consensus_timestamp
            );
        }
    }
}
