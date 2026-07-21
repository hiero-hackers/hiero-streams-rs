//! The canonical JSON shape for a parsed record file — the single
//! source of truth shared by the CLI, the Node binding, and the
//! differential tests.
//!
//! The shape is pinned by the snapshot tests. Large integers that
//! exceed JS `Number` safety — block number, charged fee, transfer
//! amounts — are encoded as strings so JavaScript consumers never
//! silently lose precision.

use crate::{ParsedBlock, ParsedRecordFile, ParsedTransaction};
use serde_json::{json, Value};

fn transaction_value(t: &ParsedTransaction) -> Value {
    json!({
        "consensusTimestamp": t.consensus_timestamp,
        "day": t.day,
        "payer": t.payer,
        "transactionId": t.transaction_id,
        "type": t.tx_type,
        "resultCode": t.result_code,
        "result": t.result,
        "chargedFeeTinybar": t.charged_fee_tinybar.to_string(),
        "transfers": t.transfers.iter().map(|l| json!({
            "account": l.account,
            "amount": l.amount.to_string(),
        })).collect::<Vec<_>>(),
        "tokenTransfers": t.token_transfers.iter().map(|l| json!({
            "token": l.token,
            "account": l.account,
            "amount": l.amount.to_string(),
        })).collect::<Vec<_>>(),
    })
}

/// Serialize a parsed block into the canonical shape (same
/// transaction objects as record files, plus block-stream fields).
pub fn block_to_json_value(block: &ParsedBlock) -> Value {
    json!({
        "format": "block-stream",
        "blockNumber": block.block_number.to_string(),
        "hapiVersion": block.hapi_version,
        "rounds": block.rounds.iter().map(|r| r.to_string()).collect::<Vec<_>>(),
        "transactions": block.transactions.iter().map(transaction_value).collect::<Vec<_>>(),
    })
}

/// Serialize a parsed record file into the canonical golden shape.
/// Shares `transaction_value` with the block path so the two eras'
/// transaction objects cannot drift apart.
pub fn record_file_to_json_value(file: &ParsedRecordFile) -> Value {
    json!({
        "version": file.version,
        "blockNumber": file.block_number.to_string(),
        "hapiVersion": file.hapi_version,
        "transactions": file.transactions.iter().map(transaction_value).collect::<Vec<_>>(),
    })
}

/// Serialize a block-proof verification outcome — one shape for the
/// CLI and the Node binding, per-check fields mirroring the
/// differential golden reports.
#[cfg(feature = "block-proofs")]
pub fn block_proof_to_json_value(
    material: &crate::block::material::BlockProofMaterial,
    ledger_id: &[u8],
    verification: &crate::block::proof::BlockProofVerification,
) -> Value {
    use crate::block::material::ProofPath;
    let valid = verification.valid();
    let hints = &verification.hints;
    json!({
        "blockNumber": material.block_number,
        "blockRoot": hex::encode(material.block_root),
        "ledgerId": hex::encode(ledger_id),
        "proofPath": match material.layout.path {
            ProofPath::AggregateSchnorr => "aggregate-schnorr",
            ProofPath::WrapsCompressedProof => "wraps-compressed-proof",
            ProofPath::Unknown => "unknown",
        },
        "hints": {
            "thresholdMet": hints.threshold_met,
            "blsSignatureValid": hints.bls_signature_valid,
            "mergedKzgValid": hints.merged_kzg_valid,
            "parsumKzgValid": hints.parsum_kzg_valid,
            "bSkIdentityValid": hints.b_sk_identity_valid,
            "parsumAccumulationValid": hints.parsum_accumulation_valid,
            "parsumConstraintValid": hints.parsum_constraint_valid,
            "bitmapWellFormednessValid": hints.bitmap_well_formedness_valid,
            "bitmapConstraintValid": hints.bitmap_constraint_valid,
            "degreeCheckValid": hints.degree_check_valid,
        },
        "schnorr": verification.schnorr.as_ref().map(|s| json!({
            "valid": s.valid,
            "signerCount": s.signer_count,
            "totalNodes": s.total_nodes,
        })),
        "wraps": verification.wraps.as_ref().map(|w| json!({
            "ledgerIdMatch": w.ledger_id_match,
            "hintsVkHashMatch": w.hints_vk_hash_match,
            "iterationGuard": w.iteration_guard,
            "uCmEIsZero": w.u_cm_e_is_zero,
            "groth16Valid": w.groth16_valid,
            "kzg0Valid": w.kzg0_valid,
            "kzg1Valid": w.kzg1_valid,
        })),
        "valid": valid,
        "meaning": if valid {
            "the network's threshold signature covers exactly this block's \
             recomputed merkle root, anchored to the ledger ID"
        } else {
            "proof INVALID for the locally recomputed block root"
        },
    })
}
