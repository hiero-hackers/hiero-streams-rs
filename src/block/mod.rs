//! Block-stream parser (HIP-1056) — the successor format to v6 record
//! files, live on mainnet in preview at
//! `gs://hedera-mainnet-streams/block-preview/mainnet/`.
//!
//! A block is one protobuf `Block` message (no version header),
//! gzipped, named by block number. Items interleave consensus
//! plumbing (event headers, node state-signature transactions,
//! proofs) with user transactions; a user transaction appears as a
//! `SignedTransaction` item whose following `TransactionResult`
//! carries the consensus outcome. Output is the same
//! transaction-shaped [`ParsedTransaction`] as the record-file
//! parser, so downstream consumers don't care which era produced it.
//!
//! Preview-format caveat: the stream is pre-GA; field usage may still
//! shift before the cutover formalizes. The vendored protos record
//! their source commit in `proto-hapi/VENDOR_COMMIT`.

// Block reading — always compiled (sha2/prost only): `wire` (shallow
// protobuf scan of a Block), `merkle` (streaming tree hasher), and
// `material` (extraction: block root, layout, bootstrap, continuity).
pub mod material;
mod merkle;
mod wire;

// Block proving — behind `block-proofs` (pulls in the arkworks stack).
#[cfg(feature = "block-proofs")]
pub mod proof;

use crate::block_proto::block_item::Item;
use crate::generated_hapi::com::hedera::hapi::block::stream::output::TransactionResult;
use crate::generated_hapi::proto as hapi;
use crate::transaction::{day_from_seconds, ParsedTransaction, TokenTransferLeg, TransferLeg};
use crate::{block_proto, inflate, Error};
use prost::Message;

/// A parsed block-stream block, shaped to mirror [`crate::ParsedRecordFile`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ParsedBlock {
    /// Consensus block number (the file name, verified from the header)
    pub block_number: u64,
    /// HAPI semver from the block header, "major.minor.patch"
    pub hapi_version: String,
    /// Consensus rounds contained in this block
    pub rounds: Vec<u64>,
    /// User transactions (consensus plumbing items are not included)
    pub transactions: Vec<ParsedTransaction>,
}

fn account_entity_id(id: Option<&hapi::AccountId>) -> String {
    match id {
        None => String::new(),
        Some(a) => {
            let num = match &a.account {
                Some(hapi::account_id::Account::AccountNum(n)) => *n,
                _ => 0,
            };
            format!("{}.{}.{}", a.shard_num, a.realm_num, num)
        }
    }
}

fn token_entity_id(id: &Option<hapi::TokenId>) -> String {
    match id {
        None => String::new(),
        Some(t) => format!("{}.{}.{}", t.shard_num, t.realm_num, t.token_num),
    }
}

fn consensus_string(ts: &Option<hapi::Timestamp>) -> String {
    let (seconds, nanos) = ts.as_ref().map_or((0, 0), |t| (t.seconds, t.nanos));
    format!("{seconds}.{nanos:09}")
}

/// Same Debug-derived oneof→camelCase mapping as the record parser.
/// KEEP IN SYNC with [`crate::record`]'s `oneof_case_name` — the parity
/// test in `lib.rs` compares the two over equivalent variants (both now
/// delegate to [`crate::debug_variant_camel`], so they agree by
/// construction).
pub(crate) fn oneof_case_name(data: &hapi::transaction_body::Data) -> String {
    crate::debug_variant_camel(data)
}

fn body_of(signed_transaction_bytes: &[u8]) -> Option<hapi::TransactionBody> {
    let signed = hapi::SignedTransaction::decode(signed_transaction_bytes).ok()?;
    hapi::TransactionBody::decode(&signed.body_bytes[..]).ok()
}

fn transaction_from(
    body: Option<&hapi::TransactionBody>,
    result: &TransactionResult,
) -> ParsedTransaction {
    let consensus_timestamp = consensus_string(&result.consensus_timestamp);
    let consensus_seconds = result.consensus_timestamp.as_ref().map_or(0, |t| t.seconds);
    let result_code = result.status;
    let result_name = hapi::ResponseCodeEnum::try_from(result_code)
        .map(|c| c.as_str_name().to_string())
        .unwrap_or_else(|_| result_code.to_string());
    ParsedTransaction {
        day: day_from_seconds(consensus_seconds),
        consensus_timestamp,
        payer: account_entity_id(
            body.and_then(|b| b.transaction_id.as_ref())
                .and_then(|id| id.account_id.as_ref()),
        ),
        tx_type: body
            .and_then(|b| b.data.as_ref())
            .map(oneof_case_name)
            .unwrap_or_else(|| "unknown".to_string()),
        result_code,
        result: result_name,
        charged_fee_tinybar: result.transaction_fee_charged,
        transfers: result
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
            .unwrap_or_default(),
        token_transfers: result
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
            .collect(),
    }
}

/// Per-block node liveness, derived from which consensus nodes
/// authored gossip events in the block. A node that appears here was
/// demonstrably alive and participating in consensus for this block's
/// rounds — a signal the record era never exposed (events were not in
/// the stream). Validated against the 0.0.802 staking payout list:
/// exact agreement on active/absent nodes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BlockActivity {
    pub block_number: u64,
    /// Consensus rounds contained in this block
    pub rounds: Vec<u64>,
    /// Gossip events per creator node — every node that authored at
    /// least one event in this block
    pub events_by_node: std::collections::BTreeMap<i64, u64>,
}

impl BlockActivity {
    pub fn total_events(&self) -> u64 {
        self.events_by_node.values().sum()
    }
}

/// Extract per-node event counts from one block-stream file
/// (`.blk.gz` or inflated bytes).
pub fn block_activity(bytes: &[u8]) -> Result<BlockActivity, Error> {
    let raw = inflate(bytes)?;
    let block = block_proto::Block::decode(&raw[..])?;

    let mut activity = BlockActivity {
        block_number: 0,
        rounds: Vec::new(),
        events_by_node: std::collections::BTreeMap::new(),
    };
    for item in &block.items {
        match &item.item {
            Some(Item::BlockHeader(h)) => activity.block_number = h.number,
            Some(Item::RoundHeader(r)) => activity.rounds.push(r.round_number),
            Some(Item::EventHeader(h)) => {
                let creator = h.event_core.as_ref().map_or(0, |c| c.creator_node_id);
                *activity.events_by_node.entry(creator).or_insert(0) += 1;
            }
            _ => {}
        }
    }
    Ok(activity)
}

/// Parse one block-stream file (`.blk.gz` or inflated bytes).
pub fn parse_block(bytes: &[u8]) -> Result<ParsedBlock, Error> {
    let raw = inflate(bytes)?;
    let block = block_proto::Block::decode(&raw[..])?;

    let mut block_number = 0u64;
    let mut hapi_version = String::from("0.0.0");
    let mut rounds = Vec::new();
    let mut transactions = Vec::new();
    // A user transaction is a SignedTransaction item whose consensus
    // outcome arrives as the NEXT TransactionResult item. Node
    // state-signature transactions never receive a result, so an
    // unpaired SignedTransaction is simply superseded by the next one.
    //
    // Known preview-era caveat: node-created child/preceding transactions
    // (TransactionResult carries parent_consensus_timestamp) can produce
    // results with no SignedTransaction item of their own; those rows are
    // kept with correct timestamps/transfers but tx_type "unknown" and an
    // empty payer. Re-examine against HIP-1056's final item ordering at GA
    // (the spec's block items/proofs have an open update PR, #1474).
    let mut pending: Option<hapi::TransactionBody> = None;

    for item in &block.items {
        match &item.item {
            Some(Item::BlockHeader(h)) => {
                block_number = h.number;
                if let Some(v) = &h.hapi_proto_version {
                    hapi_version = format!("{}.{}.{}", v.major, v.minor, v.patch);
                }
            }
            Some(Item::RoundHeader(r)) => rounds.push(r.round_number),
            Some(Item::SignedTransaction(bytes)) => pending = body_of(bytes),
            Some(Item::TransactionResult(result)) => {
                transactions.push(transaction_from(pending.as_ref(), result));
                pending = None;
            }
            _ => {}
        }
    }

    Ok(ParsedBlock {
        block_number,
        hapi_version,
        rounds,
        transactions,
    })
}
