//! Node.js bindings for hiero-streams via napi-rs.
//!
//! Deliberately thin: functions take `Buffer`s and return JSON strings
//! in exactly the golden shape the CLI and differential tests use, so
//! JavaScript consumers get output identical to every other surface of
//! this crate (that equality is what the binding's own test asserts).

use napi::bindgen_prelude::*;
use napi_derive::napi;

/// Parse a record file (gzipped or not) → JSON string in the golden
/// shape. `JSON.parse` on the JS side.
#[napi]
pub fn parse_record_file_json(bytes: Buffer) -> Result<String> {
    let parsed =
        hiero_streams::parse_record_file(&bytes).map_err(|e| Error::from_reason(e.to_string()))?;
    Ok(hiero_streams::record_file_to_json_value(&parsed).to_string())
}

/// Parse a block-stream file (HIP-1056, gzipped or not) → JSON string in
/// the canonical shape — era parity with `parse_record_file_json`.
#[napi]
pub fn parse_block_json(bytes: Buffer) -> Result<String> {
    let parsed =
        hiero_streams::parse_block(&bytes).map_err(|e| Error::from_reason(e.to_string()))?;
    Ok(hiero_streams::block_to_json_value(&parsed).to_string())
}

/// Verify a block's in-band proof (HIP-1056 `TssSignedBlockProof`):
/// recomputed merkle root, hinTS threshold signature, Schnorr/WRAPS
/// suffix → the same per-check JSON the CLI's `verify` prints.
///
/// `bootstrap_block` is the genesis block carrying the ledger-ID
/// publication — required for non-genesis blocks, ignored when the
/// block carries its own.
#[napi]
pub fn verify_block_proof_json(bytes: Buffer, bootstrap_block: Option<Buffer>) -> Result<String> {
    let material = hiero_streams::extract_proof_material(&bytes)
        .map_err(|e| Error::from_reason(e.to_string()))?;
    let bootstrap = hiero_streams::resolve_bootstrap(
        &material,
        bootstrap_block.as_deref(),
        "pass the genesis block as the second argument",
    )
    .map_err(|e| Error::from_reason(e.to_string()))?;
    let verification = hiero_streams::verify_block_proof(&material, &bootstrap)
        .map_err(|e| Error::from_reason(e.to_string()))?;
    Ok(
        hiero_streams::block_proof_to_json_value(&material, &bootstrap.ledger_id, &verification)
            .to_string(),
    )
}

/// SHA-384 of a record file (the signed hash domain), hex-encoded.
#[napi]
pub fn record_file_hash_hex(bytes: Buffer) -> Result<String> {
    let hash =
        hiero_streams::record_file_hash(&bytes).map_err(|e| Error::from_reason(e.to_string()))?;
    Ok(hex::encode(hash))
}

/// Verify one node's signature over a file hash (hex) with its
/// hex-DER public key.
#[napi]
pub fn verify_node_signature(
    file_hash_hex: String,
    signature: Buffer,
    public_key_hex: String,
) -> Result<bool> {
    let hash = hex::decode(&file_hash_hex).map_err(|e| Error::from_reason(e.to_string()))?;
    hiero_streams::verify_node_signature(&hash, &signature, &public_key_hex)
        .map_err(|e| Error::from_reason(e.to_string()))
}
