//! The record-stream era (v6) — mainnet's format since mid-2022.
//!
//! `mod.rs` is the parser: raw bytes (gzipped or not) → typed
//! [`ParsedTransaction`]s. Pure and synchronous — no I/O, no network. A
//! v6 file is a 4-byte big-endian format version followed by one
//! protobuf `RecordStreamFile` message. The [`verify`] submodule holds
//! this era's trust machinery (node signatures, running-hash chain,
//! attestation).
//!
//! Field semantics follow the canonical JSON contract (see
//! [`crate::json`]); correctness is grounded in the network-signed
//! metadata hash and the mirror-node differential tests.

pub mod verify;

use crate::transaction::{day_from_seconds, ParsedTransaction, TokenTransferLeg, TransferLeg};
use crate::{inflate, proto, Error};
use prost::Message;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ParsedRecordFile {
    /// Record file format version (currently only 6 is supported)
    pub version: i32,
    /// Consensus-node block number
    pub block_number: i64,
    /// Running hash carried in from the previous file (chain link)
    pub start_running_hash: Vec<u8>,
    /// Running hash after this file's records (next file's start)
    pub end_running_hash: Vec<u8>,
    /// HAPI semver the file was produced under, "major.minor.patch"
    pub hapi_version: String,
    pub transactions: Vec<ParsedTransaction>,
}

fn account_entity_id(id: Option<&proto::AccountId>) -> String {
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

/// Prost oneof variant name (`ContractCall`) → the lowerCamelCase case
/// name the canonical JSON contract uses (`contractCall`). Derived from
/// the Debug representation so all ~70 variants stay covered without a
/// hand-maintained table that could silently drift — see
/// [`crate::debug_variant_camel`] for the early-abort mechanism that
/// keeps it cheap.
///
/// KEEP IN SYNC with the identical helper in [`crate::block`] (different
/// proto namespace, same behavior) — the parity test in `lib.rs`
/// enforces it. Relies on prost's Debug format (`Variant(..)`); the unit
/// test in `lib.rs` is the tripwire for prost upgrades changing that.
pub(crate) fn oneof_case_name(data: &proto::transaction_body::Data) -> String {
    crate::debug_variant_camel(data)
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

/// Response-code number → name. The record-era enum is tried first; codes
/// newer than that vendored proto version fall back to the block-era enum
/// (same append-only enum, vendored fresh from hiero-consensus-node), and
/// only then to the bare number. Mainnet emits codes newer than any pinned
/// proto eventually — observed live with 527 — so the fallback chain keeps
/// result names aligned with the network without re-vendoring on every code.
pub(crate) fn response_code_name(code: i32) -> String {
    proto::ResponseCodeEnum::try_from(code)
        .map(|c| c.as_str_name().to_string())
        .or_else(|_| {
            crate::generated_hapi::proto::ResponseCodeEnum::try_from(code)
                .map(|c| c.as_str_name().to_string())
        })
        .unwrap_or_else(|_| code.to_string())
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
    let consensus_seconds = record.consensus_timestamp.as_ref().map_or(0, |t| t.seconds);
    // A record without a receipt defaults to status 0 ("OK") — the committed
    // snapshots pin this behavior. Real mainnet records always carry a
    // receipt; the default exists only for defense.
    let result_code = record.receipt.as_ref().map_or(0, |r| r.status);
    let result = response_code_name(result_code);

    let transfers = record
        .transfer_list
        .as_ref()
        .map(|list| {
            list.account_amounts
                .iter()
                .map(|leg| TransferLeg {
                    account: account_entity_id(leg.account_id.as_ref()),
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
                account: account_entity_id(leg.account_id.as_ref()),
                amount: leg.amount,
            })
        })
        .collect();

    Some(ParsedTransaction {
        day: day_from_seconds(consensus_seconds),
        consensus_timestamp,
        payer: account_entity_id(
            record
                .transaction_id
                .as_ref()
                .and_then(|id| id.account_id.as_ref()),
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
        start_running_hash: file
            .start_object_running_hash
            .as_ref()
            .map(|h| h.hash.clone())
            .unwrap_or_default(),
        end_running_hash: file
            .end_object_running_hash
            .as_ref()
            .map(|h| h.hash.clone())
            .unwrap_or_default(),
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
