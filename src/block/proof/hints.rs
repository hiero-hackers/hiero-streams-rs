//! hinTS threshold aggregate signature verification on BLS12-381
//! (consensus node `hints.rs` verify).
//!
//! The signature attests the block merkle root under an aggregate key
//! whose weight must exceed the threshold fraction of total network
//! weight. Beyond the BLS pairing check, a KZG-based SNARK-lite
//! argument proves the aggregate key really is the bitmap-selected
//! subset of the committee's keys:
//!
//! 0. threshold weight check
//! 1. BLS pairing: `e(agg_pk, H(root)) == e(g₀, agg_sig)`
//! 2. Fiat-Shamir challenge `r`
//! 3. merged KZG opening proof at `r` (7 polynomials batched)
//! 4. ParSum KZG opening proof at `r/ω`
//! 5. pairing identity `B·SK`
//! 6. four field-level polynomial identities
//! 7. degree check on `Qx`
//!
//! Wire encodings deviate from arkworks canonical serialization: G1/G2
//! coordinates are big-endian (ZCash convention) in both the
//! uncompressed layouts and the compressed Fiat-Shamir transcript, and
//! the transcript hash uses ark-ff 0.4's `expand_message_xmd`, whose
//! z_pad is the 48-byte output length instead of RFC 9380's 64-byte
//! SHA-256 block size. Both quirks are load-bearing: they must match
//! the consensus node byte-for-byte, and the differential test against
//! the JS verifier pins them.

use crate::block::material::ProofLayout;
use crate::Error;
use ark_bls12_381::{Bls12_381, Fq, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::hashing::curve_maps::wb::WBMap;
use ark_ec::hashing::map_to_curve_hasher::MapToCurveBasedHasher;
use ark_ec::hashing::HashToCurve;
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::field_hashers::DefaultFieldHasher;
use ark_ff::{BigInteger, FftField, Field, One, PrimeField, Zero};
use ark_serialize::CanonicalDeserialize;
use sha2::{Digest, Sha256};

const VK_LENGTH: usize = 1096;
const SIG_LENGTH: usize = 1632;

const HASH_TO_G2_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
const FIAT_SHAMIR_DST: &[u8] = b"HINTS_SIG_BLS12381:FIAT_SHAMIR";

/// Hedera's threshold fraction: aggregate weight must strictly exceed
/// 1/3 of total weight for the signature to carry, per the consensus
/// node's hinTS verifier. (The >⅔ block-acceptance rule is enforced by
/// consensus before a proof is ever emitted.)
const THRESHOLD_NUMERATOR: u128 = 1;
const THRESHOLD_DENOMINATOR: u128 = 3;

/// Per-step outcome, mirroring the JS verifier's checks object so the
/// two implementations diff field-for-field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct HintsChecks {
    pub threshold_met: bool,
    pub bls_signature_valid: bool,
    pub merged_kzg_valid: bool,
    pub parsum_kzg_valid: bool,
    pub b_sk_identity_valid: bool,
    pub parsum_accumulation_valid: bool,
    pub parsum_constraint_valid: bool,
    pub bitmap_well_formedness_valid: bool,
    pub bitmap_constraint_valid: bool,
    pub degree_check_valid: bool,
}

impl HintsChecks {
    pub fn all_passed(&self) -> bool {
        self.threshold_met
            && self.bls_signature_valid
            && self.merged_kzg_valid
            && self.parsum_kzg_valid
            && self.b_sk_identity_valid
            && self.parsum_accumulation_valid
            && self.parsum_constraint_valid
            && self.bitmap_well_formedness_valid
            && self.bitmap_constraint_valid
            && self.degree_check_valid
    }
}

// ─── ZCash-convention point I/O ─────────────────────────────────────────────

fn fq_from_be(bytes: &[u8]) -> Result<Fq, Error> {
    let mut le = bytes.to_vec();
    le.reverse();
    Fq::deserialize_uncompressed(&le[..]).map_err(|e| Error::Proof(format!("Fq: {e}")))
}

fn read_g1_uncompressed(bytes: &[u8]) -> Result<G1Affine, Error> {
    let x = fq_from_be(&bytes[..48])?;
    let y = fq_from_be(&bytes[48..96])?;
    if x.is_zero() && y.is_zero() {
        return Ok(G1Affine::identity());
    }
    let point = G1Affine::new_unchecked(x, y);
    if !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err(Error::Proof(
            "G1 point not in the prime-order subgroup".into(),
        ));
    }
    Ok(point)
}

fn read_g2_uncompressed(bytes: &[u8]) -> Result<G2Affine, Error> {
    // imaginary component first (c1), then real (c0)
    let x_c1 = fq_from_be(&bytes[..48])?;
    let x_c0 = fq_from_be(&bytes[48..96])?;
    let y_c1 = fq_from_be(&bytes[96..144])?;
    let y_c0 = fq_from_be(&bytes[144..192])?;
    if x_c0.is_zero() && x_c1.is_zero() && y_c0.is_zero() && y_c1.is_zero() {
        return Ok(G2Affine::identity());
    }
    let point = G2Affine::new_unchecked(
        ark_bls12_381::Fq2::new(x_c0, x_c1),
        ark_bls12_381::Fq2::new(y_c0, y_c1),
    );
    if !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err(Error::Proof(
            "G2 point not in the prime-order subgroup".into(),
        ));
    }
    Ok(point)
}

fn read_fr_le(bytes: &[u8]) -> Fr {
    Fr::from_le_bytes_mod_order(bytes)
}

fn fq_to_be48(v: &Fq) -> [u8; 48] {
    let mut out = [0u8; 48];
    let bytes = v.into_bigint().to_bytes_be();
    out[48 - bytes.len()..].copy_from_slice(&bytes);
    out
}

const FLAG_COMPRESSED: u8 = 0x80;
const FLAG_INFINITY: u8 = 0x40;
const FLAG_Y_NEGATIVE: u8 = 0x20;

fn fq_is_negative(v: &Fq) -> bool {
    // y > (p-1)/2
    let mut half = Fq::MODULUS;
    half.div2();
    v.into_bigint() > half
}

fn compress_g1(point: &G1Affine) -> [u8; 48] {
    if point.is_zero() {
        let mut buf = [0u8; 48];
        buf[0] = FLAG_COMPRESSED | FLAG_INFINITY;
        return buf;
    }
    let mut buf = fq_to_be48(&point.x);
    buf[0] |= FLAG_COMPRESSED;
    if fq_is_negative(&point.y) {
        buf[0] |= FLAG_Y_NEGATIVE;
    }
    buf
}

fn compress_g2(point: &G2Affine) -> [u8; 96] {
    let mut buf = [0u8; 96];
    if point.is_zero() {
        buf[0] = FLAG_COMPRESSED | FLAG_INFINITY;
        return buf;
    }
    buf[..48].copy_from_slice(&fq_to_be48(&point.x.c1)); // imaginary first
    buf[48..].copy_from_slice(&fq_to_be48(&point.x.c0));
    buf[0] |= FLAG_COMPRESSED;
    let y_negative = if point.y.c1.is_zero() {
        fq_is_negative(&point.y.c0)
    } else {
        fq_is_negative(&point.y.c1)
    };
    if y_negative {
        buf[0] |= FLAG_Y_NEGATIVE;
    }
    buf
}

// ─── Deserialization ────────────────────────────────────────────────────────

struct HintsVk {
    n: u64,
    total_weight: Fr,
    g0: G1Affine,
    h0: G2Affine,
    h1: G2Affine,
    ln_minus_1_of_tau_com: G1Affine,
    w_of_tau_com: G1Affine,
    sk_of_tau_com: G2Affine,
    z_of_tau_com: G2Affine,
}

struct HintsSignature {
    agg_pk: G1Affine,
    agg_weight: Fr,
    agg_sig: G2Affine,
    b_of_tau_com: G1Affine,
    qx_of_tau_com: G1Affine,
    qx_of_tau_mul_tau_com: G1Affine,
    qz_of_tau_com: G1Affine,
    parsum_of_tau_com: G1Affine,
    q1_of_tau_com: G1Affine,
    q3_of_tau_com: G1Affine,
    q2_of_tau_com: G1Affine,
    q4_of_tau_com: G1Affine,
    opening_proof_r: G1Affine,
    opening_proof_r_div_omega: G1Affine,
    parsum_of_r: Fr,
    parsum_of_r_div_omega: Fr,
    w_of_r: Fr,
    b_of_r: Fr,
    q1_of_r: Fr,
    q3_of_r: Fr,
    q2_of_r: Fr,
    q4_of_r: Fr,
}

fn deserialize_vk(bytes: &[u8]) -> Result<HintsVk, Error> {
    if bytes.len() != VK_LENGTH {
        return Err(Error::Proof(format!(
            "hints VK is {} bytes, expected {VK_LENGTH}",
            bytes.len()
        )));
    }
    Ok(HintsVk {
        n: u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes")),
        total_weight: read_fr_le(&bytes[8..40]),
        g0: read_g1_uncompressed(&bytes[40..136])?,
        h0: read_g2_uncompressed(&bytes[136..328])?,
        h1: read_g2_uncompressed(&bytes[328..520])?,
        ln_minus_1_of_tau_com: read_g1_uncompressed(&bytes[520..616])?,
        w_of_tau_com: read_g1_uncompressed(&bytes[616..712])?,
        sk_of_tau_com: read_g2_uncompressed(&bytes[712..904])?,
        z_of_tau_com: read_g2_uncompressed(&bytes[904..1096])?,
    })
}

fn deserialize_signature(bytes: &[u8]) -> Result<HintsSignature, Error> {
    if bytes.len() != SIG_LENGTH {
        return Err(Error::Proof(format!(
            "hints signature is {} bytes, expected {SIG_LENGTH}",
            bytes.len()
        )));
    }
    let g1 = |offset: usize| read_g1_uncompressed(&bytes[offset..offset + 96]);
    let fr = |offset: usize| read_fr_le(&bytes[offset..offset + 32]);
    Ok(HintsSignature {
        agg_pk: g1(0)?,
        agg_weight: fr(96),
        agg_sig: read_g2_uncompressed(&bytes[128..320])?,
        b_of_tau_com: g1(320)?,
        qx_of_tau_com: g1(416)?,
        qx_of_tau_mul_tau_com: g1(512)?,
        qz_of_tau_com: g1(608)?,
        parsum_of_tau_com: g1(704)?,
        q1_of_tau_com: g1(800)?,
        q3_of_tau_com: g1(896)?,
        q2_of_tau_com: g1(992)?,
        q4_of_tau_com: g1(1088)?,
        opening_proof_r: g1(1184)?,
        opening_proof_r_div_omega: g1(1280)?,
        parsum_of_r: fr(1376),
        parsum_of_r_div_omega: fr(1408),
        w_of_r: fr(1440),
        b_of_r: fr(1472),
        q1_of_r: fr(1504),
        q3_of_r: fr(1536),
        q2_of_r: fr(1568),
        q4_of_r: fr(1600),
    })
}

// ─── Fiat-Shamir ────────────────────────────────────────────────────────────

/// ark-ff 0.4's `expand_message_xmd` with its non-RFC z_pad (48 bytes,
/// = the output length, instead of SHA-256's 64-byte input block).
/// Implemented explicitly so an arkworks upgrade can never silently
/// change the transcript.
fn arkworks_expand_message_xmd(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Vec<u8> {
    const B_LEN: usize = 32; // SHA-256 output
    let ell = len_in_bytes.div_ceil(B_LEN);

    let mut dst_prime = dst.to_vec();
    dst_prime.push(u8::try_from(dst.len()).expect("DST under 256 bytes"));

    let mut hasher = Sha256::new();
    hasher.update(vec![0u8; len_in_bytes]); // the quirky z_pad
    hasher.update(msg);
    hasher.update((len_in_bytes as u16).to_be_bytes());
    hasher.update([0x00]);
    hasher.update(&dst_prime);
    let b0: [u8; 32] = hasher.finalize().into();

    let mut blocks = Vec::with_capacity(ell);
    let mut prev = b0;
    for i in 1..=ell {
        let mut hasher = Sha256::new();
        if i == 1 {
            hasher.update(b0);
        } else {
            let xored: Vec<u8> = b0.iter().zip(prev.iter()).map(|(a, b)| a ^ b).collect();
            hasher.update(xored);
        }
        hasher.update([i as u8]);
        hasher.update(&dst_prime);
        prev = hasher.finalize().into();
        blocks.push(prev);
    }
    blocks.concat()[..len_in_bytes].to_vec()
}

/// `DefaultFieldHasher<Sha256, 128>::hash_to_field(data, 1)`: expand to
/// 48 bytes, interpret big-endian, reduce mod the Fr order.
fn hash_to_fr(data: &[u8], dst: &[u8]) -> Fr {
    let expanded = arkworks_expand_message_xmd(data, dst, 48);
    Fr::from_be_bytes_mod_order(&expanded)
}

/// The 14-element compressed transcript from the consensus node's
/// `random_oracle()`, in its exact order.
fn fiat_shamir_challenge(vk: &HintsVk, sig: &HintsSignature) -> Fr {
    let mut transcript = Vec::with_capacity(2 * 96 + 48 * 11 + 32);
    transcript.extend_from_slice(&compress_g2(&vk.sk_of_tau_com));
    transcript.extend_from_slice(&compress_g2(&vk.h1));
    transcript.extend_from_slice(&compress_g1(&sig.agg_pk));
    transcript.extend_from_slice(&sig.agg_weight.into_bigint().to_bytes_le());
    transcript.extend_from_slice(&compress_g1(&vk.w_of_tau_com));
    transcript.extend_from_slice(&compress_g1(&sig.b_of_tau_com));
    transcript.extend_from_slice(&compress_g1(&sig.parsum_of_tau_com));
    transcript.extend_from_slice(&compress_g1(&sig.qx_of_tau_com));
    transcript.extend_from_slice(&compress_g1(&sig.qz_of_tau_com));
    transcript.extend_from_slice(&compress_g1(&sig.qx_of_tau_mul_tau_com));
    transcript.extend_from_slice(&compress_g1(&sig.q1_of_tau_com));
    transcript.extend_from_slice(&compress_g1(&sig.q2_of_tau_com));
    transcript.extend_from_slice(&compress_g1(&sig.q3_of_tau_com));
    transcript.extend_from_slice(&compress_g1(&sig.q4_of_tau_com));
    hash_to_fr(&transcript, FIAT_SHAMIR_DST)
}

// ─── Verification ───────────────────────────────────────────────────────────

fn fr_to_u128(v: &Fr) -> Result<u128, Error> {
    let limbs = v.into_bigint().0;
    if limbs[2] != 0 || limbs[3] != 0 {
        return Err(Error::Proof("weight exceeds 128 bits".into()));
    }
    Ok(u128::from(limbs[0]) | (u128::from(limbs[1]) << 64))
}

/// Product-of-pairings check: `∏ e(g1ᵢ, g2ᵢ) == 1`.
fn pairing_product_is_one(g1s: &[G1Projective], g2s: &[G2Projective]) -> bool {
    Bls12_381::multi_pairing(
        g1s.iter().map(|p| p.into_affine()),
        g2s.iter().map(|p| p.into_affine()),
    )
    .0
    .is_one()
}

/// Verify the hinTS threshold signature over `block_root`. Structural
/// problems are `Err`; a well-formed signature yields per-check results.
pub fn verify_hints(layout: &ProofLayout, block_root: &[u8; 48]) -> Result<HintsChecks, Error> {
    let vk = deserialize_vk(&layout.hints_verification_key)?;
    let sig = deserialize_signature(&layout.hints_signature)?;

    // Step 0: threshold — plain integer comparison of canonical values
    let threshold_met = THRESHOLD_DENOMINATOR * fr_to_u128(&sig.agg_weight)?
        > THRESHOLD_NUMERATOR * fr_to_u128(&vk.total_weight)?;

    // Step 1: BLS pairing check, message hashed to G2 with the standard
    // BLS ciphersuite DST
    let hasher = MapToCurveBasedHasher::<
        G2Projective,
        DefaultFieldHasher<Sha256, 128>,
        WBMap<ark_bls12_381::g2::Config>,
    >::new(HASH_TO_G2_DST)
    .map_err(|e| Error::Proof(format!("hash-to-curve init: {e}")))?;
    let h_msg: G2Affine = hasher
        .hash(block_root)
        .map_err(|e| Error::Proof(format!("hash-to-curve: {e}")))?;
    let bls_signature_valid = pairing_product_is_one(
        &[sig.agg_pk.into(), (-vk.g0.into_group())],
        &[h_msg.into(), sig.agg_sig.into()],
    );

    // Step 2: Fiat-Shamir challenge and evaluation domain
    let r = fiat_shamir_challenge(&vk, &sig);
    let omega = Fr::get_root_of_unity(vk.n)
        .ok_or_else(|| Error::Proof(format!("no root of unity of order {}", vk.n)))?;

    // Step 3: merged KZG opening at r.
    // W'(τ) = W(τ) - agg_weight·L_{n-1}(τ); batch the 7 openings with
    // powers of r; check e(merged, h₀) == e(π_r, h₁ - r·h₀).
    let w_adjusted =
        vk.w_of_tau_com.into_group() - vk.ln_minus_1_of_tau_com.into_group() * sig.agg_weight;
    let g0 = vk.g0.into_group();
    let mk_arg = |com: G1Projective, eval_at_r: Fr| com - g0 * eval_at_r;

    let args = [
        mk_arg(sig.parsum_of_tau_com.into(), sig.parsum_of_r),
        mk_arg(w_adjusted, sig.w_of_r),
        mk_arg(sig.b_of_tau_com.into(), sig.b_of_r),
        mk_arg(sig.q1_of_tau_com.into(), sig.q1_of_r),
        mk_arg(sig.q3_of_tau_com.into(), sig.q3_of_r),
        mk_arg(sig.q2_of_tau_com.into(), sig.q2_of_r),
        mk_arg(sig.q4_of_tau_com.into(), sig.q4_of_r),
    ];
    let mut merged = args[0];
    let mut r_pow = r;
    for arg in &args[1..] {
        merged += *arg * r_pow;
        r_pow *= r;
    }
    let kzg_rhs_g2 = vk.h1.into_group() - vk.h0.into_group() * r;
    let merged_kzg_valid = pairing_product_is_one(
        &[merged, -sig.opening_proof_r.into_group()],
        &[vk.h0.into(), kzg_rhs_g2],
    );

    // Step 4: ParSum KZG opening at r/ω
    let r_div_omega = r * omega
        .inverse()
        .ok_or_else(|| Error::Proof("ω is zero".into()))?;
    let parsum_arg = sig.parsum_of_tau_com.into_group() - g0 * sig.parsum_of_r_div_omega;
    let parsum_rhs_g2 = vk.h1.into_group() - vk.h0.into_group() * r_div_omega;
    let parsum_kzg_valid = pairing_product_is_one(
        &[parsum_arg, -sig.opening_proof_r_div_omega.into_group()],
        &[vk.h0.into(), parsum_rhs_g2],
    );

    // Step 5: e(B(τ), SK(τ)) == e(Qz(τ), Z(τ)) · e(Qx(τ), h₁) · e(agg_pk, h₀)
    let b_sk_identity_valid = pairing_product_is_one(
        &[
            sig.b_of_tau_com.into(),
            -sig.qz_of_tau_com.into_group(),
            -sig.qx_of_tau_com.into_group(),
            -sig.agg_pk.into_group(),
        ],
        &[
            vk.sk_of_tau_com.into(),
            vk.z_of_tau_com.into(),
            vk.h1.into(),
            vk.h0.into(),
        ],
    );

    // Step 6: field-level polynomial identities at r
    let n_fr = Fr::from(vk.n);
    let vanishing_of_r = r.pow([vk.n]) - Fr::one();
    let omega_pow_n_minus_1 = omega.pow([vk.n - 1]);
    let ln_minus_1_of_r =
        (omega_pow_n_minus_1 / n_fr) * (vanishing_of_r / (r - omega_pow_n_minus_1));

    let parsum_accumulation_valid =
        sig.parsum_of_r - sig.parsum_of_r_div_omega - sig.w_of_r * sig.b_of_r
            == sig.q1_of_r * vanishing_of_r;
    let parsum_constraint_valid = ln_minus_1_of_r * sig.parsum_of_r == vanishing_of_r * sig.q3_of_r;
    let bitmap_well_formedness_valid =
        sig.b_of_r * sig.b_of_r - sig.b_of_r == sig.q2_of_r * vanishing_of_r;
    let bitmap_constraint_valid =
        ln_minus_1_of_r * (sig.b_of_r - Fr::one()) == vanishing_of_r * sig.q4_of_r;

    // Step 7: degree check — e(Qx(τ), h₁) == e(Qx(τ)·τ, h₀)
    let degree_check_valid = pairing_product_is_one(
        &[
            sig.qx_of_tau_com.into(),
            -sig.qx_of_tau_mul_tau_com.into_group(),
        ],
        &[vk.h1.into(), vk.h0.into()],
    );

    Ok(HintsChecks {
        threshold_met,
        bls_signature_valid,
        merged_kzg_valid,
        parsum_kzg_valid,
        b_sk_identity_valid,
        parsum_accumulation_valid,
        parsum_constraint_valid,
        bitmap_well_formedness_valid,
        bitmap_constraint_valid,
        degree_check_valid,
    })
}
