//! The shared transaction vocabulary — the output types both eras
//! produce. The record parser ([`crate::record`]) and the block parser
//! ([`crate::block`]) each decode a different wire format into these
//! same structs, so downstream consumers (`json`, the CLI, the ETL)
//! don't care which era a transaction came from.

use std::fmt;

/// A Hedera entity identifier in `shard.realm.num` form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AccountId {
    pub shard_num: i64,
    pub realm_num: i64,
    pub account_num: i64,
}

impl fmt::Display for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.shard_num, self.realm_num, self.account_num)
    }
}

/// A token identifier in `shard.realm.num` form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TokenId {
    pub shard_num: i64,
    pub realm_num: i64,
    pub token_num: i64,
}

impl fmt::Display for TokenId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.shard_num, self.realm_num, self.token_num)
    }
}

/// An on-ledger asset: HBAR, a fungible token, or a single NFT serial.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Asset {
    Hbar,
    FungibleToken { token_id: TokenId },
    Nft { token_id: TokenId, serial_number: u64 },
}

impl Asset {
    pub fn label(&self) -> String {
        match self {
            Asset::Hbar => "HBAR".to_string(),
            Asset::FungibleToken { token_id } | Asset::Nft { token_id, .. } =>
                token_id.to_string(),
        }
    }
}

impl fmt::Display for Asset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Asset::Hbar => f.write_str("HBAR"),
            Asset::FungibleToken { token_id } => write!(f, "{token_id}"),
            Asset::Nft {
                token_id,
                serial_number,
            } => write!(f, "{token_id}#{serial_number}"),
        }
    }
}

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

/// One NFT transfer leg.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftTransfer {
    pub sender: AccountId,
    pub receiver: AccountId,
    pub asset: Asset,
}

/// One transaction as parsed from either era's stream — the canonical
/// output shape. Its JSON contract is
/// [`record_file_to_json_value`](crate::record_file_to_json_value) /
/// [`block_to_json_value`](crate::block_to_json_value).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ParsedTransaction {
    /// Consensus timestamp, mirror-node string form "seconds.nanos"
    pub consensus_timestamp: String,
    /// UTC day "YYYY-MM-DD" derived from the consensus timestamp
    pub day: String,
    /// Fee payer, "0.0.123" ("" when the record carries no id)
    pub payer: String,
    /// The transaction id, "0.0.123@seconds.nanos" — the payer plus the
    /// validStart timestamp, exactly as wallets, SDKs, and explorers spell
    /// it ("" when the stream carries no id). Child and scheduled
    /// transactions share their parent's base id, as on the mirror node.
    pub transaction_id: String,
    /// Transaction type: the TransactionBody `data` oneof case in
    /// lowerCamelCase, e.g. "cryptoTransfer", "contractCall".
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
    pub nft_transfers: Vec<NftTransfer>,
}

/// "seconds.nanos" → UTC day "YYYY-MM-DD" (civil-from-days algorithm —
/// no date dependency needed for a pure epoch→date conversion).
pub fn day_of(consensus_timestamp: &str) -> String {
    let seconds: i64 = consensus_timestamp
        .split('.')
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    day_from_seconds(seconds)
}

/// Epoch-seconds → "YYYY-MM-DD" core. Called directly in the hot path,
/// which already holds the integer seconds — re-parsing the formatted
/// timestamp string per transaction (as the public [`day_of`] must) is
/// avoidable there.
pub(crate) fn day_from_seconds(seconds: i64) -> String {
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
