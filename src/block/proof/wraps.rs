//! WRAPS proof verification: Groth16 + KZG pairing checks on BN254
//! (consensus node `verify_compressed_wraps_proof()` /
//! `DeciderEth::verify()`).
//!
//! The 704-byte suffix is a folding-scheme decider proof: it attests
//! that the chain of address-book rotations from the genesis ledger ID
//! (`z_0`) to the current hinTS key (`z_i`) was verified step-by-step,
//! compressed into one Groth16 proof plus two KZG openings over the
//! folded witness commitments. Verification:
//!
//! 1. state consistency — `z_0[0]` is the ledger ID, `z_i[1]` is
//!    `Poseidon(hinTS VK)`, step counter `i > 1`, `u.cmE` is zero
//! 2. fold the running/instance commitments with the proof's `r`
//! 3. encode folded G1 points as 55-bit nonnative limbs
//! 4. Groth16 pairing check over the 40-element public input
//! 5. two KZG opening checks against the folded commitments
//!
//! Unlike the hinTS material (ZCash byte conventions), both the proof
//! suffix and the verifier param in the bootstrap are arkworks
//! `CanonicalSerialize` compressed — deserialization is a derive.

use super::poseidon::hash_hints_vk;
use crate::block::material::{Bootstrap, ProofLayout, ProofPath};
use crate::Error;
use ark_bn254::{Bn254, Fq, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, One, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, Compress, Read, SerializationError, Valid, Validate};

const SUFFIX_LENGTH: usize = 704;
const VERIFIER_PARAM_LENGTH: usize = 1768;
const PUBLIC_INPUT_LENGTH: usize = 40;

/// Per-step outcome, mirroring the JS verifier's checks object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct WrapsChecks {
    pub ledger_id_match: bool,
    pub hints_vk_hash_match: bool,
    pub iteration_guard: bool,
    pub u_cm_e_is_zero: bool,
    pub groth16_valid: bool,
    pub kzg0_valid: bool,
    pub kzg1_valid: bool,
}

impl WrapsChecks {
    pub fn all_passed(&self) -> bool {
        self.ledger_id_match
            && self.hints_vk_hash_match
            && self.iteration_guard
            && self.u_cm_e_is_zero
            && self.groth16_valid
            && self.kzg0_valid
            && self.kzg1_valid
    }
}

// ─── Wire structs (arkworks compressed) ─────────────────────────────────────

#[derive(CanonicalDeserialize)]
struct KzgEvalProof {
    eval: Fr,
    proof: G1Affine,
}

struct EthProof {
    a: G1Affine,
    b: G2Affine,
    c: G1Affine,
    kzg_proofs: [KzgEvalProof; 2],
    cm_t: G1Affine,
    r: Fr,
    kzg_challenges: [Fr; 2],
}

// ark-serialize 0.4.2's blanket `CanonicalDeserialize` impl for `[T; N]`
// (impls.rs) builds the array with `core::array::from_fn(|_| {
// T::deserialize_with_mode(..).unwrap() })` — an `unwrap()` on
// attacker-controlled bytes, so a malformed element (e.g. a curve point
// not on the curve) panics instead of returning `Err`. `EthProof` has
// two fixed-size array fields, so it can't use `#[derive(CanonicalDeserialize)]`
// as-is; this hand-written impl mirrors what the derive would generate,
// but deserializes array elements with a `?`-propagating loop instead of
// going through the buggy blanket impl.
fn deserialize_fixed_array<T: CanonicalDeserialize, R: Read, const N: usize>(
    mut reader: R,
    compress: Compress,
    validate: Validate,
) -> Result<[T; N], SerializationError> {
    let mut values = Vec::with_capacity(N);
    for _ in 0..N {
        values.push(T::deserialize_with_mode(&mut reader, compress, validate)?);
    }
    Ok(values
        .try_into()
        .unwrap_or_else(|_| unreachable!("exactly N elements pushed above")))
}

impl Valid for EthProof {
    fn check(&self) -> Result<(), SerializationError> {
        self.a.check()?;
        self.b.check()?;
        self.c.check()?;
        Valid::batch_check(self.kzg_proofs.iter())?;
        self.cm_t.check()?;
        self.r.check()?;
        Valid::batch_check(self.kzg_challenges.iter())?;
        Ok(())
    }
}

impl CanonicalDeserialize for EthProof {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        Ok(Self {
            a: CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?,
            b: CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?,
            c: CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?,
            kzg_proofs: deserialize_fixed_array(&mut reader, compress, validate)?,
            cm_t: CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?,
            r: CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?,
            kzg_challenges: deserialize_fixed_array(&mut reader, compress, validate)?,
        })
    }
}

#[derive(CanonicalDeserialize)]
struct ProofData {
    i: Fr,
    z_0: Vec<Fr>,
    z_i: Vec<Fr>,
    running_commitments: Vec<G1Affine>,  // U_i: [cmW, cmE]
    instance_commitments: Vec<G1Affine>, // u_i: [cmW, cmE]
    eth_proof: EthProof,
}

#[derive(CanonicalDeserialize)]
struct KzgVerifierKey {
    g: G1Affine,
    _gamma_g: G1Affine,
    h: G2Affine,
    beta_h: G2Affine,
}

#[derive(CanonicalDeserialize)]
struct VerifierParam {
    pp_hash: Fr,
    alpha_g1: G1Affine,
    beta_g2: G2Affine,
    gamma_g2: G2Affine,
    delta_g2: G2Affine,
    gamma_abc_g1: Vec<G1Affine>,
    kzg_vk: KzgVerifierKey,
}

fn deserialize_exact<T: CanonicalDeserialize>(bytes: &[u8], what: &str) -> Result<T, Error> {
    let mut reader = bytes;
    let value = T::deserialize_with_mode(&mut reader, Compress::Yes, Validate::Yes)
        .map_err(|e| Error::Proof(format!("{what}: {e}")))?;
    if !reader.is_empty() {
        return Err(Error::Proof(format!(
            "{what}: {} trailing bytes",
            reader.len()
        )));
    }
    Ok(value)
}

// ─── Nonnative limb encoding ────────────────────────────────────────────────
// Each BN254 Fq coordinate → 5 limbs of 55 bits (LSB first), fed to the
// circuit as Fr public inputs.

const BITS_PER_LIMB: usize = 55;

fn fq_to_limbs(v: &Fq) -> [Fr; 5] {
    let bytes = v.into_bigint().to_bytes_le();
    let mut limbs = [Fr::zero(); 5];
    for (i, limb) in limbs.iter_mut().enumerate() {
        let mut value = 0u64;
        for bit in 0..BITS_PER_LIMB {
            let bit_index = i * BITS_PER_LIMB + bit;
            let byte = bytes.get(bit_index / 8).copied().unwrap_or(0);
            if byte >> (bit_index % 8) & 1 == 1 {
                value |= 1 << bit;
            }
        }
        *limb = Fr::from(value);
    }
    limbs
}

fn g1_to_nonnative(point: &G1Projective) -> [Fr; 10] {
    let affine = point.into_affine();
    let (x, y) = affine
        .xy()
        .map_or((Fq::zero(), Fq::zero()), |(x, y)| (*x, *y));
    let mut out = [Fr::zero(); 10];
    out[..5].copy_from_slice(&fq_to_limbs(&x));
    out[5..].copy_from_slice(&fq_to_limbs(&y));
    out
}

// ─── Pairing checks ─────────────────────────────────────────────────────────

fn groth16_valid(
    public_input: &[Fr],
    proof_a: &G1Affine,
    proof_b: &G2Affine,
    proof_c: &G1Affine,
    vp: &VerifierParam,
) -> Result<bool, Error> {
    if vp.gamma_abc_g1.len() != public_input.len() + 1 {
        return Err(Error::Proof(format!(
            "verifier param has {} input coefficients for {} public inputs",
            vp.gamma_abc_g1.len(),
            public_input.len()
        )));
    }
    let mut prepared_input = vp.gamma_abc_g1[0].into_group();
    for (value, coefficient) in public_input.iter().zip(&vp.gamma_abc_g1[1..]) {
        if !value.is_zero() {
            prepared_input += coefficient.into_group() * value;
        }
    }
    // e(A,B) · e(I,−γ) · e(C,−δ) · e(−α,β) == 1
    Ok(Bn254::multi_pairing(
        [
            *proof_a,
            prepared_input.into_affine(),
            *proof_c,
            (-vp.alpha_g1.into_group()).into_affine(),
        ],
        [
            *proof_b,
            (-vp.gamma_g2.into_group()).into_affine(),
            (-vp.delta_g2.into_group()).into_affine(),
            vp.beta_g2,
        ],
    )
    .0
    .is_one())
}

fn kzg_valid(
    commitment: &G1Projective,
    challenge: &Fr,
    eval: &Fr,
    witness: &G1Affine,
    vp: &VerifierParam,
) -> bool {
    // e(cm − eval·g, h) · e(−w, βh − challenge·h) == 1
    let lhs_g1 = *commitment - vp.kzg_vk.g.into_group() * eval;
    let rhs_g2 = vp.kzg_vk.beta_h.into_group() - vp.kzg_vk.h.into_group() * challenge;
    Bn254::multi_pairing(
        [lhs_g1.into_affine(), (-witness.into_group()).into_affine()],
        [vp.kzg_vk.h, rhs_g2.into_affine()],
    )
    .0
    .is_one()
}

// ─── Verification ───────────────────────────────────────────────────────────

/// Verify the compressed WRAPS proof in `layout` against the bootstrap
/// (ledger ID + verifier param). Structural problems are `Err`; a
/// well-formed proof yields per-check results.
pub fn verify_wraps(layout: &ProofLayout, bootstrap: &Bootstrap) -> Result<WrapsChecks, Error> {
    if layout.path != ProofPath::WrapsCompressedProof {
        return Err(Error::Proof("not a WRAPS-path proof".into()));
    }
    if layout.suffix.len() != SUFFIX_LENGTH {
        return Err(Error::Proof(format!(
            "expected {SUFFIX_LENGTH}-byte WRAPS suffix, got {}",
            layout.suffix.len()
        )));
    }
    if bootstrap.history_proof_verification_key.len() != VERIFIER_PARAM_LENGTH {
        return Err(Error::Proof(format!(
            "verifier param is {} bytes, expected {VERIFIER_PARAM_LENGTH}",
            bootstrap.history_proof_verification_key.len()
        )));
    }

    let proof: ProofData = deserialize_exact(&layout.suffix, "WRAPS proof")?;
    let vp: VerifierParam =
        deserialize_exact(&bootstrap.history_proof_verification_key, "verifier param")?;
    for (name, vector, expected) in [
        ("z_0", proof.z_0.len(), 2),
        ("z_i", proof.z_i.len(), 2),
        ("U_i", proof.running_commitments.len(), 2),
        ("u_i", proof.instance_commitments.len(), 2),
    ] {
        if vector != expected {
            return Err(Error::Proof(format!(
                "expected {name} length {expected}, got {vector}"
            )));
        }
    }

    // Step 1: state consistency
    let ledger_id_match = bootstrap.ledger_id.len() == 32
        && proof.z_0[0] == Fr::from_le_bytes_mod_order(&bootstrap.ledger_id);
    let hints_vk_hash_match = proof.z_i[1] == hash_hints_vk(&layout.hints_verification_key);
    let iteration_guard = proof.i.into_bigint() > 1u64.into();

    // Step 2: fold commitments with the proof's r
    let r = proof.eth_proof.r;
    let u_cm_e_is_zero = proof.instance_commitments[1].is_zero();
    let cm_w_final =
        proof.running_commitments[0].into_group() + proof.instance_commitments[0].into_group() * r;
    let cm_e_final =
        proof.running_commitments[1].into_group() + proof.eth_proof.cm_t.into_group() * r;

    // Steps 3-4: nonnative encoding and the 40-element public input
    let mut public_input = Vec::with_capacity(PUBLIC_INPUT_LENGTH);
    public_input.extend([vp.pp_hash, proof.i]);
    public_input.extend(&proof.z_0);
    public_input.extend(&proof.z_i);
    public_input.extend(g1_to_nonnative(&cm_w_final));
    public_input.extend(g1_to_nonnative(&cm_e_final));
    public_input.extend(proof.eth_proof.kzg_challenges);
    public_input.extend([
        proof.eth_proof.kzg_proofs[0].eval,
        proof.eth_proof.kzg_proofs[1].eval,
    ]);
    public_input.extend(g1_to_nonnative(&proof.eth_proof.cm_t.into_group()));
    debug_assert_eq!(public_input.len(), PUBLIC_INPUT_LENGTH);

    let groth16_valid = groth16_valid(
        &public_input,
        &proof.eth_proof.a,
        &proof.eth_proof.b,
        &proof.eth_proof.c,
        &vp,
    )?;

    // Step 5: KZG openings against the folded commitments
    let kzg0_valid = kzg_valid(
        &cm_w_final,
        &proof.eth_proof.kzg_challenges[0],
        &proof.eth_proof.kzg_proofs[0].eval,
        &proof.eth_proof.kzg_proofs[0].proof,
        &vp,
    );
    let kzg1_valid = kzg_valid(
        &cm_e_final,
        &proof.eth_proof.kzg_challenges[1],
        &proof.eth_proof.kzg_proofs[1].eval,
        &proof.eth_proof.kzg_proofs[1].proof,
        &vp,
    );

    Ok(WrapsChecks {
        ledger_id_match,
        hints_vk_hash_match,
        iteration_guard,
        u_cm_e_is_zero,
        groth16_valid,
        kzg0_valid,
        kzg1_valid,
    })
}
