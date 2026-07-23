//! Block-stream proof verification (HIP-1056 `TssSignedBlockProof`).
//!
//! Behind the `block-proofs` feature (the whole module is gated), since
//! this is what pulls in the arkworks curve stack. The block *reading*
//! it verifies over — the wire scan, merkle root, layout, and bootstrap
//! — lives in the always-compiled sibling [`crate::block::material`].
//!
//! Blocks arrive pre-signed by the network: the packed `block_signature`
//! carries a hinTS BLS threshold signature over the block merkle root
//! (strictly >⅔ of network weight) plus a scheme-specific suffix — an
//! aggregate Schnorr signature for genesis/pre-settled blocks, a
//! compressed WRAPS (Groth16+KZG) proof once history is settled.
//! Verification needs no per-node fetches; everything is in-band and
//! anchored to the ledger ID published in the genesis block's bootstrap
//! transaction.
//!
//! The port is differentially tested against
//! [`hiero-block-verifier-js`](https://github.com/hiero-hackers/hiero-block-verifier-js)
//! over fixtures vendored from `hiero-block-node` (`tests/fixtures/tss/`,
//! golden expectations in `js-verifier-golden.json`). Algorithms follow
//! the consensus-node `hedera-cryptography` implementations; the wire
//! format is arkworks `CanonicalSerialize` throughout.

mod hints;
mod poseidon;
mod schnorr;
mod wraps;

pub use hints::{verify_hints, HintsChecks};
pub use schnorr::{verify_schnorr, SchnorrVerification};
pub use wraps::{verify_wraps, WrapsChecks};

use crate::block::material::{
    recompute_block_root, BlockInclusionWitness, BlockProofMaterial, Bootstrap, ProofPath,
};
use crate::Error;

/// Combined outcome of verifying one block's proof.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BlockProofVerification {
    pub block_number: u64,
    /// hinTS threshold signature over the recomputed block root —
    /// checked on every block regardless of suffix scheme
    pub hints: HintsChecks,
    /// Populated on the aggregate-Schnorr path (genesis / pre-settled)
    pub schnorr: Option<SchnorrVerification>,
    /// Populated on the WRAPS path (settled history)
    pub wraps: Option<WrapsChecks>,
}

impl BlockProofVerification {
    /// Every check on every applicable path passed.
    pub fn valid(&self) -> bool {
        self.hints.all_passed()
            && self.schnorr.as_ref().is_none_or(|s| s.valid)
            && self.wraps.as_ref().is_none_or(|w| w.all_passed())
    }
}

/// Verify one block's in-band proof end to end: recompute the block
/// merkle root, check the hinTS threshold signature over it, and check
/// the scheme-specific suffix (Schnorr or WRAPS) against the bootstrap.
///
/// `bootstrap` is the ledger-ID publication from the genesis block —
/// pass `material.bootstrap` for the genesis block itself, or carry it
/// forward for later blocks (see [`resolve_bootstrap`](crate::resolve_bootstrap)).
pub fn verify_block_proof(
    material: &BlockProofMaterial,
    bootstrap: &Bootstrap,
) -> Result<BlockProofVerification, Error> {
    verify_proof_over_root(material, bootstrap, &material.block_root)
}

/// Verify that one transaction is included in a network-signed block:
/// recompute the block root from the transaction bytes and their
/// [`BlockInclusionWitness`], then verify the block proof **over the
/// recomputed root**.
///
/// This is the safe path for inclusion checks. Calling
/// [`recompute_block_root`] and [`verify_block_proof`] separately is
/// sound only if the caller also compares the recomputed root against
/// `material.block_root` — forgetting that comparison verifies a proof
/// that says nothing about the transaction. This function makes the
/// mistake unrepresentable: the hinTS threshold signature is checked
/// against the root derived from `tx_bytes` itself, so the untrusted
/// `material.block_root` never enters the trust path.
///
/// Returns `Err` when the witness does not belong to this block's
/// material (root mismatch), and the usual proof verification outcome
/// otherwise — the result's [`valid`](BlockProofVerification::valid)
/// must still be checked.
pub fn verify_inclusion(
    tx_bytes: &[u8],
    witness: &BlockInclusionWitness,
    material: &BlockProofMaterial,
    bootstrap: &Bootstrap,
) -> Result<BlockProofVerification, Error> {
    let recomputed = recompute_block_root(tx_bytes, witness);
    // Diagnostic pre-check only — soundness does not depend on it. A
    // mismatched witness would equally fail the signature check below;
    // this turns that failure into a precise error.
    if recomputed != material.block_root {
        return Err(Error::Proof(
            "inclusion witness does not recompute this block's root — \
             the transaction is not in this block, or witness and proof \
             material belong to different blocks"
                .into(),
        ));
    }
    verify_proof_over_root(material, bootstrap, &recomputed)
}

/// Shared tail of [`verify_block_proof`] and [`verify_inclusion`]: the
/// hinTS check over the given root plus the scheme-specific suffix.
fn verify_proof_over_root(
    material: &BlockProofMaterial,
    bootstrap: &Bootstrap,
    block_root: &[u8; 48],
) -> Result<BlockProofVerification, Error> {
    let hints = verify_hints(&material.layout, block_root)?;
    let (schnorr, wraps) = match material.layout.path {
        ProofPath::AggregateSchnorr => (Some(verify_schnorr(&material.layout, bootstrap)?), None),
        ProofPath::WrapsCompressedProof => (None, Some(verify_wraps(&material.layout, bootstrap)?)),
        ProofPath::Unknown => {
            return Err(Error::Proof(format!(
                "unrecognized proof suffix of {} bytes",
                material.layout.suffix.len()
            )))
        }
    };
    Ok(BlockProofVerification {
        block_number: material.block_number,
        hints,
        schnorr,
        wraps,
    })
}
