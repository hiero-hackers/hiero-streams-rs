//! Poseidon hash over BN254 Fr, matching the consensus node's
//! `poseidon_canonical_config::<Fr>()` (t=5: rate 4 + capacity 1,
//! 8 full / 60 partial rounds, α=5, grain-generated constants).
//!
//! Used in two places: the Schnorr rotation message commits to the
//! hinTS verification key via `Poseidon(chunks(vk))`, and the WRAPS
//! proof's `z_i[1]` state element carries the same hash.

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::poseidon::{
    find_poseidon_ark_and_mds, PoseidonConfig, PoseidonSponge,
};
use ark_crypto_primitives::sponge::CryptographicSponge;
use ark_ff::PrimeField;

fn canonical_config() -> PoseidonConfig<Fr> {
    let full_rounds = 8;
    let partial_rounds = 60;
    let alpha = 5;
    let rate = 4;
    let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
        Fr::MODULUS_BIT_SIZE as u64,
        rate,
        full_rounds,
        partial_rounds,
        0,
    );
    PoseidonConfig::new(
        full_rounds as usize,
        partial_rounds as usize,
        alpha,
        mds,
        ark,
        rate,
        1,
    )
}

/// Absorb-all, squeeze-one — `PoseidonCRH::evaluate` semantics.
pub(crate) fn poseidon_hash(inputs: &[Fr]) -> Fr {
    let config = canonical_config();
    let mut sponge = PoseidonSponge::new(&config);
    for input in inputs {
        sponge.absorb(input);
    }
    sponge.squeeze_field_elements::<Fr>(1)[0]
}

/// Hash the hinTS verification key bytes to a BN254 Fr element:
/// 32-byte chunks, each `from_le_bytes_mod_order`, Poseidon over the
/// chunk elements (consensus node `hash_hints_vk()`).
pub(crate) fn hash_hints_vk(vk_bytes: &[u8]) -> Fr {
    let elements: Vec<Fr> = vk_bytes
        .chunks(32)
        .map(Fr::from_le_bytes_mod_order)
        .collect();
    poseidon_hash(&elements)
}
