//! Record stream file parser: raw bytes (gzipped or not) → typed
//! transactions. Pure and synchronous — no I/O, no network.
//!
//! v6 file layout (mainnet since mid-2022): a 4-byte big-endian format
//! version followed by one protobuf `RecordStreamFile` message.
//!
//! Field semantics deliberately match the reference TypeScript parser
//! (hiero-recordstreams) so the differential tests can compare output
//! field-for-field.

use crate::{proto, Error};
use flate2::read::GzDecoder;
use prost::Message;
use std::io::Read;

const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];

/// One HBAR transfer leg (fee legs included, as on-ledger).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferLeg {
    /// Entity id, "0.0.123" form
    pub account: String,
    /// Signed amount in tinybar (negative = debit)
    pub amount: i64,
}

/// One token transfer leg.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenTransferLeg {
    pub token: String,
    pub account: String,
    pub amount: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedTransaction {
    /// Consensus timestamp, mirror-node string form "seconds.nanos"
    pub consensus_timestamp: String,
    /// UTC day "YYYY-MM-DD" derived from the consensus timestamp
    pub day: String,
    /// Fee payer, "0.0.123" ("" when the record carries no id)
    pub payer: String,
    /// Transaction type: the TransactionBody `data` oneof case in the
    /// protobufjs camelCase form, e.g. "cryptoTransfer", "contractCall".
    /// "unknown" when the body cannot be decoded.
    pub tx_type: String,
    /// proto.ResponseCodeEnum numeric result (22 = SUCCESS)
    pub result_code: i32,
    /// Result name, e.g. "SUCCESS" (numeric string when unknown)
    pub result: String,
    /// Total fee charged to the payer, in tinybar
    pub charged_fee_tinybar: u64,
    pub transfers: Vec<TransferLeg>,
    pub token_transfers: Vec<TokenTransferLeg>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRecordFile {
    /// Record file format version (currently only 6 is supported)
    pub version: i32,
    /// Consensus-node block number
    pub block_number: i64,
    /// HAPI semver the file was produced under, "major.minor.patch"
    pub hapi_version: String,
    pub transactions: Vec<ParsedTransaction>,
}

fn inflate(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    if bytes.len() >= 2 && bytes[..2] == GZIP_MAGIC {
        let mut out = Vec::new();
        GzDecoder::new(bytes).read_to_end(&mut out)?;
        Ok(out)
    } else {
        Ok(bytes.to_vec())
    }
}

fn account_entity_id(id: &Option<proto::AccountId>) -> String {
    match id {
        None => String::new(),
        Some(a) => {
            let num = match &a.account {
                Some(proto::account_id::Account::AccountNum(n)) => *n,
                _ => 0,
            };
            format!("{}.{}.{}", a.shard_num, a.realm_num, num)
        }
    }
}

fn token_entity_id(id: &Option<proto::TokenId>) -> String {
    match id {
        None => String::new(),
        Some(t) => format!("{}.{}.{}", t.shard_num, t.realm_num, t.token_num),
    }
}

fn consensus_string(ts: &Option<proto::Timestamp>) -> String {
    let (seconds, nanos) = ts.as_ref().map_or((0, 0), |t| (t.seconds, t.nanos));
    format!("{seconds}.{nanos:09}")
}

/// "seconds.nanos" → UTC day "YYYY-MM-DD" (civil-from-days algorithm —
/// no date dependency needed for a pure epoch→date conversion).
pub fn day_of(consensus_timestamp: &str) -> String {
    let seconds: i64 = consensus_timestamp
        .split('.')
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let z = seconds.div_euclid(86_400) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

/// Prost oneof variant name (`ContractCall`) → the protobufjs case name
/// (`contractCall`) the TypeScript reference emits. Derived from the
/// Debug representation so all ~70 variants stay covered without a
/// hand-maintained table that could silently drift.
fn oneof_case_name(data: &proto::transaction_body::Data) -> String {
    let debug = format!("{data:?}");
    let variant = debug.split(['(', ' ', '{']).next().unwrap_or("unknown");
    let mut chars = variant.chars();
    match chars.next() {
        Some(first) => first.to_lowercase().collect::<String>() + chars.as_str(),
        None => "unknown".to_string(),
    }
}

fn decode_body(tx: &Option<proto::Transaction>) -> Option<proto::TransactionBody> {
    let tx = tx.as_ref()?;
    if !tx.signed_transaction_bytes.is_empty() {
        let signed = proto::SignedTransaction::decode(&tx.signed_transaction_bytes[..]).ok()?;
        return proto::TransactionBody::decode(&signed.body_bytes[..]).ok();
    }
    #[allow(deprecated)]
    if !tx.body_bytes.is_empty() {
        return proto::TransactionBody::decode(&tx.body_bytes[..]).ok();
    }
    #[allow(deprecated)]
    tx.body.clone()
}

fn parse_item(item: &proto::RecordStreamItem) -> Option<ParsedTransaction> {
    let record = item.record.as_ref()?;

    let body = decode_body(&item.transaction);
    let tx_type = body
        .as_ref()
        .and_then(|b| b.data.as_ref())
        .map(oneof_case_name)
        .unwrap_or_else(|| "unknown".to_string());

    let consensus_timestamp = consensus_string(&record.consensus_timestamp);
    let result_code = record.receipt.as_ref().map_or(0, |r| r.status);
    let result = proto::ResponseCodeEnum::try_from(result_code)
        .map(|c| c.as_str_name().to_string())
        .unwrap_or_else(|_| result_code.to_string());

    let transfers = record
        .transfer_list
        .as_ref()
        .map(|list| {
            list.account_amounts
                .iter()
                .map(|leg| TransferLeg {
                    account: account_entity_id(&leg.account_id),
                    amount: leg.amount,
                })
                .collect()
        })
        .unwrap_or_default();

    let token_transfers = record
        .token_transfer_lists
        .iter()
        .flat_map(|list| {
            let token = token_entity_id(&list.token);
            list.transfers.iter().map(move |leg| TokenTransferLeg {
                token: token.clone(),
                account: account_entity_id(&leg.account_id),
                amount: leg.amount,
            })
        })
        .collect();

    Some(ParsedTransaction {
        day: day_of(&consensus_timestamp),
        consensus_timestamp,
        payer: account_entity_id(
            &record
                .transaction_id
                .as_ref()
                .and_then(|id| id.account_id.clone()),
        ),
        tx_type,
        result_code,
        result,
        charged_fee_tinybar: record.transaction_fee,
        transfers,
        token_transfers,
    })
}

/// Parse one record stream file. Accepts the bytes exactly as they sit
/// in the bucket — gzipped (`.rcd.gz`) or already inflated (`.rcd`).
pub fn parse_record_file(bytes: &[u8]) -> Result<ParsedRecordFile, Error> {
    let buf = inflate(bytes)?;
    if buf.len() < 4 {
        return Err(Error::TooShort);
    }
    let version = i32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if version != 6 {
        return Err(Error::UnsupportedVersion(version));
    }
    let file = proto::RecordStreamFile::decode(&buf[4..])?;
    let v = file.hapi_proto_version.as_ref();
    Ok(ParsedRecordFile {
        version,
        block_number: file.block_number,
        hapi_version: format!(
            "{}.{}.{}",
            v.map_or(0, |s| s.major),
            v.map_or(0, |s| s.minor),
            v.map_or(0, |s| s.patch),
        ),
        transactions: file
            .record_stream_items
            .iter()
            .filter_map(parse_item)
            .collect(),
    })
}
