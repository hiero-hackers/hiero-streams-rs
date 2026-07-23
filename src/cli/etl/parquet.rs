//! The Parquet sink — schemas and writers shared by both era pipelines.
//!
//! `TX_SCHEMA`/`LEG_SCHEMA` are a **published dataset contract**: existing
//! day-partitioned datasets (and any sibling ETL producing interchangeable
//! output) depend on these exact column names, order, and physical types.
//! The `parquet_schemas_are_stable` test at the bottom fails loudly if they
//! drift; change them only as a deliberate, dataset-versioned decision.

use hiero_streams::{NftTransfer, ParsedTransaction};
use parquet::basic::{Compression, ZstdLevel};
use parquet::data_type::{ByteArray, ByteArrayType, Int32Type, Int64Type};
use parquet::file::properties::WriterProperties;
use parquet::file::writer::SerializedFileWriter;
use parquet::schema::parser::parse_message_type;
use std::fs;
use std::sync::Arc;

const TX_SCHEMA: &str = "
message transactions {
    required byte_array consensus_timestamp (UTF8);
    required byte_array payer (UTF8);
    required byte_array type (UTF8);
    required byte_array result (UTF8);
    required int32 result_code;
    required int64 fee_tinybar;
}";

const LEG_SCHEMA: &str = "
message transfers {
    required byte_array consensus_timestamp (UTF8);
    required byte_array account (UTF8);
    required int64 amount;
    optional byte_array token (UTF8);
}";

#[derive(Debug, PartialEq)]
struct LegRow {
    consensus_timestamp: String,
    account: String,
    amount: i64,
    token: Option<String>,
}

/// NFT leg → ±1 ownership-delta rows, token "shard.realm.num#serial".
/// A missing side (mint has no sender, burn/wipe no receiver) emits no
/// row rather than a fabricated account.
fn nft_leg_rows(consensus_timestamp: &str, leg: &NftTransfer) -> Vec<LegRow> {
    let token = format!("{}#{}", leg.token, leg.serial_number);
    let mut rows = Vec::with_capacity(2);
    if let Some(sender) = leg.sender {
        rows.push(LegRow {
            consensus_timestamp: consensus_timestamp.to_string(),
            account: sender.to_string(),
            amount: -1,
            token: Some(token.clone()),
        });
    }
    if let Some(receiver) = leg.receiver {
        rows.push(LegRow {
            consensus_timestamp: consensus_timestamp.to_string(),
            account: receiver.to_string(),
            amount: 1,
            token: Some(token),
        });
    }
    rows
}

fn props() -> Arc<WriterProperties> {
    Arc::new(
        WriterProperties::builder()
            .set_compression(Compression::ZSTD(ZstdLevel::default()))
            .build(),
    )
}

fn byte_arrays(values: impl Iterator<Item = String>) -> Vec<ByteArray> {
    values.map(|s| ByteArray::from(s.into_bytes())).collect()
}

fn write_transactions(path: &str, rows: &[ParsedTransaction]) -> parquet::errors::Result<()> {
    let schema = Arc::new(parse_message_type(TX_SCHEMA)?);
    let file = fs::File::create(path)?;
    let mut writer = SerializedFileWriter::new(file, schema, props())?;
    let mut rg = writer.next_row_group()?;

    macro_rules! column {
        ($t:ty, $values:expr) => {{
            let mut col = rg.next_column()?.expect("schema column");
            col.typed::<$t>().write_batch(&$values, None, None)?;
            col.close()?;
        }};
    }
    column!(
        ByteArrayType,
        byte_arrays(rows.iter().map(|r| r.consensus_timestamp.clone()))
    );
    column!(
        ByteArrayType,
        byte_arrays(rows.iter().map(|r| r.payer.clone()))
    );
    column!(
        ByteArrayType,
        byte_arrays(rows.iter().map(|r| r.tx_type.clone()))
    );
    column!(
        ByteArrayType,
        byte_arrays(rows.iter().map(|r| r.result.clone()))
    );
    column!(
        Int32Type,
        rows.iter().map(|r| r.result_code).collect::<Vec<_>>()
    );
    column!(
        Int64Type,
        rows.iter()
            .map(|r| r.charged_fee_tinybar as i64)
            .collect::<Vec<_>>()
    );
    rg.close()?;
    writer.close()?;
    Ok(())
}

fn write_transfers(path: &str, rows: &[LegRow]) -> parquet::errors::Result<()> {
    let schema = Arc::new(parse_message_type(LEG_SCHEMA)?);
    let file = fs::File::create(path)?;
    let mut writer = SerializedFileWriter::new(file, schema, props())?;
    let mut rg = writer.next_row_group()?;

    let mut col = rg.next_column()?.expect("consensus_timestamp");
    col.typed::<ByteArrayType>().write_batch(
        &byte_arrays(rows.iter().map(|r| r.consensus_timestamp.clone())),
        None,
        None,
    )?;
    col.close()?;

    let mut col = rg.next_column()?.expect("account");
    col.typed::<ByteArrayType>().write_batch(
        &byte_arrays(rows.iter().map(|r| r.account.clone())),
        None,
        None,
    )?;
    col.close()?;

    let mut col = rg.next_column()?.expect("amount");
    col.typed::<Int64Type>().write_batch(
        &rows.iter().map(|r| r.amount).collect::<Vec<_>>(),
        None,
        None,
    )?;
    col.close()?;

    // optional column: definition level 1 = present, 0 = NULL
    let mut col = rg.next_column()?.expect("token");
    let def_levels: Vec<i16> = rows.iter().map(|r| i16::from(r.token.is_some())).collect();
    let present = byte_arrays(rows.iter().filter_map(|r| r.token.clone()));
    col.typed::<ByteArrayType>()
        .write_batch(&present, Some(&def_levels), None)?;
    col.close()?;

    rg.close()?;
    writer.close()?;
    Ok(())
}

/// One day's rows → the two Parquet partitions. Shared by both eras — the
/// schemas are the same dataset contract regardless of source.
pub(super) fn write_day(
    out: &str,
    day: &str,
    rows: &[ParsedTransaction],
    with_transfers: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let tx_dir = format!("{out}/transactions/day={day}");
    fs::create_dir_all(&tx_dir)?;
    write_transactions(&format!("{tx_dir}/data.parquet"), rows)?;

    if with_transfers {
        let mut legs = Vec::new();
        for tx in rows {
            for leg in &tx.transfers {
                legs.push(LegRow {
                    consensus_timestamp: tx.consensus_timestamp.clone(),
                    account: leg.account.clone(),
                    amount: leg.amount,
                    token: None,
                });
            }
            for leg in &tx.token_transfers {
                legs.push(LegRow {
                    consensus_timestamp: tx.consensus_timestamp.clone(),
                    account: leg.account.clone(),
                    amount: leg.amount,
                    token: Some(leg.token.clone()),
                });
            }
            for leg in &tx.nft_transfers {
                legs.extend(nft_leg_rows(&tx.consensus_timestamp, leg));
            }
        }
        let leg_dir = format!("{out}/transfers/day={day}");
        fs::create_dir_all(&leg_dir)?;
        write_transfers(&format!("{leg_dir}/data.parquet"), &legs)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Parquet schemas are a published dataset contract — this pins the
    /// exact column names, order, and physical types so an accidental edit
    /// fails here instead of in a downstream dataset consumer.
    #[test]
    fn parquet_schemas_are_stable() {
        let tx = parse_message_type(TX_SCHEMA).expect("TX_SCHEMA parses");
        let tx_cols: Vec<(String, String)> = tx
            .get_fields()
            .iter()
            .map(|f| (f.name().to_string(), format!("{:?}", f.get_physical_type())))
            .collect();
        assert_eq!(
            tx_cols,
            [
                ("consensus_timestamp", "BYTE_ARRAY"),
                ("payer", "BYTE_ARRAY"),
                ("type", "BYTE_ARRAY"),
                ("result", "BYTE_ARRAY"),
                ("result_code", "INT32"),
                ("fee_tinybar", "INT64"),
            ]
            .map(|(n, t)| (n.to_string(), t.to_string()))
        );

        let legs = parse_message_type(LEG_SCHEMA).expect("LEG_SCHEMA parses");
        let leg_cols: Vec<(String, String, bool)> = legs
            .get_fields()
            .iter()
            .map(|f| {
                (
                    f.name().to_string(),
                    format!("{:?}", f.get_physical_type()),
                    f.is_optional(),
                )
            })
            .collect();
        assert_eq!(
            leg_cols,
            [
                ("consensus_timestamp", "BYTE_ARRAY", false),
                ("account", "BYTE_ARRAY", false),
                ("amount", "INT64", false),
                ("token", "BYTE_ARRAY", true),
            ]
            .map(|(n, t, o)| (n.to_string(), t.to_string(), o))
        );
    }

    use hiero_streams::{AccountId, TokenId};

    fn account(n: i64) -> Option<AccountId> {
        Some(AccountId {
            shard_num: 0,
            realm_num: 0,
            account_num: n,
        })
    }

    fn nft(sender: Option<AccountId>, receiver: Option<AccountId>) -> NftTransfer {
        NftTransfer {
            sender,
            receiver,
            token: TokenId {
                shard_num: 0,
                realm_num: 0,
                token_num: 5000,
            },
            serial_number: 7,
            is_approval: false,
        }
    }

    /// A full transfer is two ±1 ownership-delta rows on "token#serial".
    #[test]
    fn nft_transfer_makes_paired_delta_rows() {
        let rows = nft_leg_rows("1.000000002", &nft(account(100), account(200)));
        assert_eq!(
            rows,
            [
                LegRow {
                    consensus_timestamp: "1.000000002".into(),
                    account: "0.0.100".into(),
                    amount: -1,
                    token: Some("0.0.5000#7".into()),
                },
                LegRow {
                    consensus_timestamp: "1.000000002".into(),
                    account: "0.0.200".into(),
                    amount: 1,
                    token: Some("0.0.5000#7".into()),
                },
            ]
        );
    }

    /// Mint (no sender) and burn/wipe (no receiver) each emit only the
    /// present side — never a fabricated "0.0.0" account row.
    #[test]
    fn nft_mint_and_burn_emit_one_sided_rows() {
        let mint = nft_leg_rows("1.000000002", &nft(None, account(200)));
        assert_eq!(mint.len(), 1);
        assert_eq!((mint[0].account.as_str(), mint[0].amount), ("0.0.200", 1));

        let burn = nft_leg_rows("1.000000002", &nft(account(100), None));
        assert_eq!(burn.len(), 1);
        assert_eq!((burn[0].account.as_str(), burn[0].amount), ("0.0.100", -1));
    }
}
