//! Aggregate Schnorr signature verification on BabyJubjub
//! (`ark_ed_on_bn254`) for genesis / pre-settled blocks.
//!
//! What the signature attests: the signing nodes' rotation message,
//! `ledger_id (32 bytes) || Poseidon(hinTS VK) (32 bytes LE)` — i.e.
//! the address book identified by the ledger ID endorses this hinTS
//! key. The hinTS threshold signature over the block root
//! ([`super::hints`]) then ties the block itself to that key.
//!
//! Verification (consensus node `Schnorr::verify`):
//! 1. `claimed_commitment = prover_response·G + verifier_challenge·agg_pk`
//! 2. `e' = Blake2s(ser(agg_pk) || ser(claimed_commitment) || message)`,
//!    first 31 bytes as an LE scalar mod the subgroup order
//! 3. valid iff `e' == verifier_challenge`
//!
//! `ser()` is arkworks `serialize_uncompressed` for affine points:
//! x (32 bytes LE) || y (32 bytes LE).

use super::poseidon::hash_hints_vk;
use crate::block::material::{Bootstrap, ProofLayout, ProofPath};
use crate::Error;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ed_on_bn254::{EdwardsAffine, EdwardsProjective, Fr as JubjubFr};
use ark_ff::{BigInteger, PrimeField, Zero};
use ark_serialize::CanonicalSerialize;
use blake2::{Blake2s256, Digest};

/// The 192-byte Schnorr suffix: a 128-entry signer bitvector (one byte
/// per bool, MAX_AB_SIZE entries) followed by two BabyJubjub scalars.
const SUFFIX_LENGTH: usize = 192;
const BITVECTOR_LENGTH: usize = 128;
/// Each node's 192-byte history proof key: public key (x, y), PoK
/// commitment (x, y), PoK challenge, PoK response — 32 bytes LE each.
/// Only the public key participates in aggregate verification.
const NODE_KEY_LENGTH: usize = 192;

/// Outcome of aggregate-Schnorr verification.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SchnorrVerification {
    /// Recomputed challenge matched the signature's challenge
    pub valid: bool,
    /// Nodes whose bitvector entry is set (of the address book's nodes)
    pub signer_count: usize,
    pub total_nodes: usize,
}

fn point_from_key_bytes(bytes: &[u8]) -> Result<EdwardsAffine, Error> {
    // serialize_uncompressed layout is x || y, so the key's first 64
    // bytes deserialize directly (with on-curve + subgroup checks).
    ark_serialize::CanonicalDeserialize::deserialize_uncompressed(&bytes[..64])
        .map_err(|e| Error::Proof(format!("node public key: {e}")))
}

fn serialize_point(point: &EdwardsAffine) -> [u8; 64] {
    let mut buf = [0u8; 64];
    point
        .serialize_uncompressed(&mut buf[..])
        .expect("64-byte buffer fits an uncompressed Edwards affine point");
    buf
}

/// Verify the aggregate Schnorr signature in `layout` against the
/// bootstrap address book. Structural problems (wrong path, malformed
/// keys) are `Err`; a well-formed signature that does not verify is
/// `Ok` with `valid: false`.
pub fn verify_schnorr(
    layout: &ProofLayout,
    bootstrap: &Bootstrap,
) -> Result<SchnorrVerification, Error> {
    if layout.path != ProofPath::AggregateSchnorr {
        return Err(Error::Proof("not a Schnorr-path proof".into()));
    }
    if layout.suffix.len() != SUFFIX_LENGTH {
        return Err(Error::Proof(format!(
            "expected {SUFFIX_LENGTH}-byte Schnorr suffix, got {}",
            layout.suffix.len()
        )));
    }
    if bootstrap.node_contributions.is_empty() {
        return Err(Error::Proof("bootstrap has no node contributions".into()));
    }

    let bitvector = &layout.suffix[..BITVECTOR_LENGTH];
    let prover_response =
        JubjubFr::from_le_bytes_mod_order(&layout.suffix[BITVECTOR_LENGTH..BITVECTOR_LENGTH + 32]);
    let verifier_challenge =
        JubjubFr::from_le_bytes_mod_order(&layout.suffix[BITVECTOR_LENGTH + 32..]);

    // Aggregate public key over the signers the bitvector selects
    let total_nodes = bootstrap.node_contributions.len();
    let mut signer_count = 0;
    let mut agg_pk = EdwardsProjective::default(); // identity
    for (i, contribution) in bootstrap.node_contributions.iter().enumerate() {
        if i >= BITVECTOR_LENGTH || bitvector[i] == 0 {
            continue;
        }
        if contribution.history_proof_key.len() != NODE_KEY_LENGTH {
            return Err(Error::Proof(format!(
                "node {} history proof key is {} bytes, expected {NODE_KEY_LENGTH}",
                contribution.node_id,
                contribution.history_proof_key.len()
            )));
        }
        agg_pk += point_from_key_bytes(&contribution.history_proof_key)?;
        signer_count += 1;
    }

    // Soundness gate. An empty signer bitvector (or any selection whose
    // keys sum to the identity) leaves agg_pk = 0, which collapses the
    // verifier equation to `claimed_commitment = prover_response·G` —
    // independent of `verifier_challenge`. An attacker could then pick
    // any `prover_response`, solve for the matching challenge, and
    // "verify" an arbitrary message under an attacker-chosen hinTS VK,
    // forging the address book's endorsement. Non-empty selections draw
    // on the genuine bootstrap keys (whose discrete logs the attacker
    // lacks), so rejecting a zero aggregate rejects exactly the
    // forgeable cases. Honest fixtures never exercise this path, so the
    // differential tests can't catch it — see the regression test below.
    if signer_count == 0 || agg_pk.is_zero() {
        return Ok(SchnorrVerification {
            valid: false,
            signer_count,
            total_nodes,
        });
    }

    // Rotation message: ledger_id || Poseidon(hinTS VK), the VK from the
    // packed signature itself (bootstrap's copy is the fallback)
    let hints_vk = if layout.hints_verification_key.is_empty() {
        &bootstrap.history_proof_verification_key
    } else {
        &layout.hints_verification_key
    };
    let mut message = Vec::with_capacity(64);
    message.extend_from_slice(&bootstrap.ledger_id[..32.min(bootstrap.ledger_id.len())]);
    message.resize(32, 0);
    message.extend_from_slice(&hash_hints_vk(hints_vk).into_bigint().to_bytes_le());

    // claimed_commitment = prover_response·G + verifier_challenge·agg_pk
    let generator = EdwardsProjective::from(EdwardsAffine::generator());
    let claimed_commitment = generator * prover_response + agg_pk * verifier_challenge;

    // e' = Blake2s(ser(agg_pk) || ser(commitment) || message), first 31
    // bytes LE mod subgroup order (Parameters { salt: None })
    let mut hasher = Blake2s256::new();
    hasher.update(serialize_point(&agg_pk.into_affine()));
    hasher.update(serialize_point(&claimed_commitment.into_affine()));
    hasher.update(&message);
    let digest = hasher.finalize();
    let recomputed = JubjubFr::from_le_bytes_mod_order(&digest[..31]);

    Ok(SchnorrVerification {
        valid: recomputed == verifier_challenge,
        signer_count,
        total_nodes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::material::NodeContribution;

    /// A forged Schnorr suffix with an all-zero signer bitvector must be
    /// rejected. This constructs the actual forgery — the scalars are
    /// chosen so the verifier equation *would* pass if the identity
    /// aggregate key were accepted — so the test fails against the
    /// pre-fix code and passes only because of the soundness gate.
    #[test]
    fn empty_bitvector_forgery_is_rejected() {
        let ledger_id = vec![7u8; 32];
        // Any bytes: the bitvector is all zero, so no node key is read.
        let bootstrap = Bootstrap {
            ledger_id: ledger_id.clone(),
            history_proof_verification_key: Vec::new(),
            node_contributions: vec![NodeContribution {
                node_id: 0,
                weight: 1,
                history_proof_key: vec![0u8; NODE_KEY_LENGTH],
            }],
        };
        let hints_vk = vec![0u8; 1096];

        // Rebuild the exact message the verifier hashes.
        let mut message = Vec::with_capacity(64);
        message.extend_from_slice(&ledger_id);
        message.extend_from_slice(&hash_hints_vk(&hints_vk).into_bigint().to_bytes_le());

        // Forge: agg_pk = identity ⇒ claimed_commitment = prover_response·G.
        let prover_response = JubjubFr::from(12_345u64);
        let generator = EdwardsProjective::from(EdwardsAffine::generator());
        let commitment = generator * prover_response;
        let identity = EdwardsProjective::default();
        let mut hasher = Blake2s256::new();
        hasher.update(serialize_point(&identity.into_affine()));
        hasher.update(serialize_point(&commitment.into_affine()));
        hasher.update(&message);
        let digest = hasher.finalize();
        let forged_challenge = JubjubFr::from_le_bytes_mod_order(&digest[..31]);

        let mut suffix = vec![0u8; SUFFIX_LENGTH]; // 128 zero bitvector bytes
        suffix[BITVECTOR_LENGTH..BITVECTOR_LENGTH + 32]
            .copy_from_slice(&prover_response.into_bigint().to_bytes_le());
        suffix[BITVECTOR_LENGTH + 32..]
            .copy_from_slice(&forged_challenge.into_bigint().to_bytes_le());

        let layout = ProofLayout {
            path: ProofPath::AggregateSchnorr,
            hints_verification_key: hints_vk,
            hints_signature: Vec::new(),
            suffix,
        };

        let outcome = verify_schnorr(&layout, &bootstrap).expect("well-formed inputs");
        assert_eq!(outcome.signer_count, 0, "no signers were selected");
        assert!(
            !outcome.valid,
            "empty-bitvector forgery must be rejected by the soundness gate"
        );
    }
}
