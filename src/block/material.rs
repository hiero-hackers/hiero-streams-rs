//! Extraction of proof material from raw block bytes.
//!
//! This module rescans the block wire bytes instead of reusing the typed
//! decode in [`crate::block`]: the block merkle tree's leaves are the
//! EXACT serialized bytes of each `BlockItem` as they appear in the
//! file, and a prost re-encode of a decoded item is not guaranteed to be
//! byte-identical. The scan keeps each item's original bytes for
//! hashing and hands the same bytes to prost when a typed view is
//! needed (header, footer, proof, signed transaction).

use super::merkle::{
    hash_internal, hash_internal_single_child, hash_leaf, StreamingTreeHasher, HASH_LENGTH,
};
use super::wire::{
    scan_block_items, F_BLOCK_FOOTER, F_BLOCK_HEADER, F_BLOCK_PROOF, F_EVENT_HEADER,
    F_FILTERED_SINGLE_ITEM, F_RECORD_FILE, F_REDACTED_ITEM, F_ROUND_HEADER, F_SIGNED_TRANSACTION,
    F_STATE_CHANGES, F_TRACE_DATA, F_TRANSACTION_OUTPUT, F_TRANSACTION_RESULT,
};
use crate::block_proto::block_item::Item;
use crate::block_proto::{BlockItem, BlockProof};
use crate::generated_hapi::com::hedera::hapi::block::stream::output::BlockFooter;
use crate::generated_hapi::com::hedera::hapi::block::stream::output::BlockHeader;
use crate::generated_hapi::proto as hapi;
use crate::{inflate, Error};
use prost::Message;

/// Which proof scheme the packed `block_signature` suffix carries.
///
/// `#[non_exhaustive]`: the proof format is pre-GA (HIP-1056 has an
/// open update PR) and new schemes may appear. Match with a `_` arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProofPath {
    /// 192-byte aggregate Schnorr signature (genesis / pre-settled blocks)
    AggregateSchnorr,
    /// 704-byte compressed WRAPS proof (settled blocks)
    WrapsCompressedProof,
    Unknown,
}

/// The packed `TssSignedBlockProof.block_signature`, split into its
/// fixed-layout parts (layout confirmed against consensus-node
/// `BlockVerificationUtils`): hinTS verification key (1096 bytes),
/// hinTS threshold signature (1632 bytes), then a scheme-specific
/// suffix.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProofLayout {
    pub path: ProofPath,
    pub hints_verification_key: Vec<u8>,
    pub hints_signature: Vec<u8>,
    pub suffix: Vec<u8>,
}

const HINTS_VK_LENGTH: usize = 1096;
const HINTS_SIG_LENGTH: usize = 1632;
const FIXED_PREFIX_LENGTH: usize = HINTS_VK_LENGTH + HINTS_SIG_LENGTH;
const SCHNORR_SUFFIX_LENGTH: usize = 192;
const WRAPS_SUFFIX_LENGTH: usize = 704;

/// One node's entry in the bootstrap address book.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NodeContribution {
    pub node_id: u64,
    pub weight: u64,
    /// 192-byte Schnorr history proof key (public key, PoK commitment,
    /// PoK challenge/response — consumed by `block::proof`'s
    /// `verify_schnorr`)
    pub history_proof_key: Vec<u8>,
}

/// The `LedgerIdPublicationTransactionBody` a network publishes in its
/// genesis block: the ledger ID, the WRAPS verification key, and the
/// per-node address book that anchors every later proof.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Bootstrap {
    pub ledger_id: Vec<u8>,
    pub history_proof_verification_key: Vec<u8>,
    pub node_contributions: Vec<NodeContribution>,
}

/// Everything proof verification needs from one block file.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BlockProofMaterial {
    pub block_number: u64,
    /// Recomputed block merkle root (SHA-384) — the message the hinTS
    /// threshold signature signs
    pub block_root: [u8; 48],
    /// Previous block's root from the footer, for continuity checks
    pub previous_block_root: Vec<u8>,
    pub layout: ProofLayout,
    /// Present only in the block that carries the ledger-ID publication
    /// (the genesis block); later blocks verify against a carried-forward
    /// bootstrap
    pub bootstrap: Option<Bootstrap>,
}

/// The continuity view of one block: enough to assert that a sequence
/// of blocks is gapless and hash-chained, without requiring a proof to
/// be present (the block-era analogue of the v6 running-hash chain).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BlockChainInfo {
    pub block_number: u64,
    /// Recomputed block merkle root (SHA-384)
    pub block_root: [u8; 48],
    /// The footer's claim of the previous block's root — empty for the
    /// genesis block, and it MUST equal the previous block's recomputed
    /// root everywhere else
    pub previous_block_root: Vec<u8>,
}

// ─── Extraction ─────────────────────────────────────────────────────────────

fn classify_layout(block_signature: &[u8]) -> ProofLayout {
    if block_signature.len() < FIXED_PREFIX_LENGTH {
        return ProofLayout {
            path: ProofPath::Unknown,
            hints_verification_key: Vec::new(),
            hints_signature: Vec::new(),
            suffix: block_signature.to_vec(),
        };
    }
    let suffix = &block_signature[FIXED_PREFIX_LENGTH..];
    let path = match suffix.len() {
        SCHNORR_SUFFIX_LENGTH => ProofPath::AggregateSchnorr,
        WRAPS_SUFFIX_LENGTH => ProofPath::WrapsCompressedProof,
        _ => ProofPath::Unknown,
    };
    ProofLayout {
        path,
        hints_verification_key: block_signature[..HINTS_VK_LENGTH].to_vec(),
        hints_signature: block_signature[HINTS_VK_LENGTH..FIXED_PREFIX_LENGTH].to_vec(),
        suffix: suffix.to_vec(),
    }
}

fn bootstrap_from(signed_transaction_bytes: &[u8]) -> Option<Bootstrap> {
    let signed = hapi::SignedTransaction::decode(signed_transaction_bytes).ok()?;
    let body = hapi::TransactionBody::decode(&signed.body_bytes[..]).ok()?;
    let publication = match body.data {
        Some(hapi::transaction_body::Data::LedgerIdPublication(p)) => p,
        _ => return None,
    };
    Some(Bootstrap {
        ledger_id: publication.ledger_id,
        history_proof_verification_key: publication.history_proof_verification_key,
        node_contributions: publication
            .node_contributions
            .iter()
            .map(|c| NodeContribution {
                node_id: c.node_id,
                weight: c.weight,
                history_proof_key: c.history_proof_key.clone(),
            })
            .collect(),
    })
}

struct ScannedBlock {
    block_number: u64,
    block_root: [u8; 48],
    previous_block_root: Vec<u8>,
    /// `None` when the block carries no `TssSignedBlockProof` (e.g. a
    /// different proof variant) — continuity checks don't need one
    block_signature: Option<Vec<u8>>,
    bootstrap: Option<Bootstrap>,
}

/// Extract proof material from one block-stream file (`.blk.gz` or
/// inflated bytes): the packed signature split into its layout, the
/// recomputed block merkle root, and the bootstrap publication if this
/// block carries one.
pub fn extract_proof_material(bytes: &[u8]) -> Result<BlockProofMaterial, Error> {
    let scanned = scan_block(bytes)?;
    let block_signature = scanned
        .block_signature
        .ok_or_else(|| Error::Proof("signed block proof missing".into()))?;
    Ok(BlockProofMaterial {
        block_number: scanned.block_number,
        block_root: scanned.block_root,
        previous_block_root: scanned.previous_block_root,
        layout: classify_layout(&block_signature),
        bootstrap: scanned.bootstrap,
    })
}

/// Resolve the bootstrap for verifying `material`: the block's own
/// publication when it carries one (the genesis block), otherwise
/// extracted from `genesis_bytes`. `missing_hint` names the caller's
/// way of supplying the genesis block (a CLI flag, a function
/// argument) so the error teaches the fix.
pub fn resolve_bootstrap(
    material: &BlockProofMaterial,
    genesis_bytes: Option<&[u8]>,
    missing_hint: &str,
) -> Result<Bootstrap, Error> {
    if let Some(bootstrap) = &material.bootstrap {
        return Ok(bootstrap.clone());
    }
    let genesis_bytes = genesis_bytes.ok_or_else(|| {
        Error::Proof(format!(
            "this block does not carry the ledger-ID publication; {missing_hint}"
        ))
    })?;
    extract_proof_material(genesis_bytes)?
        .bootstrap
        .ok_or_else(|| Error::Proof("the genesis block carries no ledger-ID publication".into()))
}

/// Extract just the continuity view: block number, recomputed root,
/// and the footer's previous-root claim.
pub fn block_chain_info(bytes: &[u8]) -> Result<BlockChainInfo, Error> {
    let scanned = scan_block(bytes)?;
    Ok(BlockChainInfo {
        block_number: scanned.block_number,
        block_root: scanned.block_root,
        previous_block_root: scanned.previous_block_root,
    })
}

fn scan_block(bytes: &[u8]) -> Result<ScannedBlock, Error> {
    let raw = inflate(bytes)?;
    let items = scan_block_items(&raw)?;

    let mut header: Option<BlockHeader> = None;
    let mut footer: Option<BlockFooter> = None;
    let mut block_signature: Option<Vec<u8>> = None;
    let mut bootstrap: Option<Bootstrap> = None;

    let mut input_tree = StreamingTreeHasher::default();
    let mut output_tree = StreamingTreeHasher::default();
    let mut consensus_tree = StreamingTreeHasher::default();
    let mut state_changes_tree = StreamingTreeHasher::default();
    let mut trace_tree = StreamingTreeHasher::default();

    for item in &items {
        match item.field_number {
            F_BLOCK_HEADER | F_TRANSACTION_RESULT | F_TRANSACTION_OUTPUT => {
                output_tree.add_leaf(hash_leaf(item.item_bytes));
            }
            F_EVENT_HEADER | F_ROUND_HEADER => {
                consensus_tree.add_leaf(hash_leaf(item.item_bytes));
            }
            F_SIGNED_TRANSACTION => {
                input_tree.add_leaf(hash_leaf(item.item_bytes));
            }
            F_STATE_CHANGES => {
                state_changes_tree.add_leaf(hash_leaf(item.item_bytes));
            }
            F_TRACE_DATA => {
                trace_tree.add_leaf(hash_leaf(item.item_bytes));
            }
            F_BLOCK_PROOF | F_BLOCK_FOOTER | F_RECORD_FILE => {}
            F_FILTERED_SINGLE_ITEM | F_REDACTED_ITEM => {
                return Err(Error::Proof(
                    "filtered/redacted block items are not supported".into(),
                ));
            }
            other => {
                return Err(Error::Proof(format!("unknown BlockItem field {other}")));
            }
        }

        // Typed views, decoded from the same bytes the scan classified
        match item.field_number {
            F_BLOCK_HEADER | F_BLOCK_FOOTER | F_BLOCK_PROOF | F_SIGNED_TRANSACTION => {
                let decoded = BlockItem::decode(item.item_bytes)?;
                match decoded.item {
                    Some(Item::BlockHeader(h)) => header = Some(h),
                    Some(Item::BlockFooter(f)) => footer = Some(f),
                    Some(Item::BlockProof(p)) => {
                        if let Some(sig) = signed_block_signature(&p) {
                            block_signature = Some(sig);
                        }
                    }
                    Some(Item::SignedTransaction(tx_bytes)) if bootstrap.is_none() => {
                        bootstrap = bootstrap_from(&tx_bytes);
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    let header = header.ok_or_else(|| Error::Proof("block header missing".into()))?;
    let footer = footer.ok_or_else(|| Error::Proof("block footer missing".into()))?;

    // Fixed-shape upper tree over the five streaming subtree roots plus
    // the footer's chain hashes, capped by the block timestamp leaf.
    let state_root = if footer.start_of_block_state_root_hash.is_empty() {
        vec![0u8; HASH_LENGTH]
    } else {
        footer.start_of_block_state_root_hash.clone()
    };
    let depth5_1 = hash_internal(
        &footer.previous_block_root_hash,
        &footer.root_hash_of_all_block_hashes_tree,
    );
    let depth5_2 = hash_internal(&state_root, &consensus_tree.root());
    let depth5_3 = hash_internal(&input_tree.root(), &output_tree.root());
    let depth5_4 = hash_internal(&state_changes_tree.root(), &trace_tree.root());
    let depth4_1 = hash_internal(&depth5_1, &depth5_2);
    let depth4_2 = hash_internal(&depth5_3, &depth5_4);
    let fixed_root = hash_internal_single_child(&hash_internal(&depth4_1, &depth4_2));

    let timestamp_bytes = header
        .block_timestamp
        .as_ref()
        .map(Message::encode_to_vec)
        .unwrap_or_default();
    let block_root = hash_internal(&hash_leaf(&timestamp_bytes), &fixed_root);

    Ok(ScannedBlock {
        block_number: header.number,
        block_root,
        previous_block_root: footer.previous_block_root_hash,
        block_signature,
        bootstrap,
    })
}

fn signed_block_signature(proof: &BlockProof) -> Option<Vec<u8>> {
    use crate::block_proto::block_proof::Proof;
    match &proof.proof {
        Some(Proof::SignedBlockProof(signed)) => Some(signed.block_signature.clone()),
        _ => None,
    }
}
