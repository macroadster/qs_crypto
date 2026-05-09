//! KEM encapsulation.
//!
//! 1. Sample random coin m
//! 2. Derive deterministic blinding from m (Fujisaki-Okamoto)
//! 3. Compute ciphertext (c₁, c₂) encoding m under the public key
//! 4. Derive shared secret = SpinHash(0x11 ‖ m ‖ ct)

use super::ring::{
    encode_message, expand_a, hash_pk, params_from_level_byte, poly_add, poly_mul, sample_cbd, Poly,
};
use super::types::{Ciphertext, EncapsulationResult, PublicKey, SharedSecret};
use crate::primitives::hash::spin_hash;
use crate::primitives::prng::SpinPrng;

/// Deterministic inner encapsulation (used by both encaps and decaps FO check).
pub(crate) fn encaps_inner(pk: &PublicKey, coin: &[u8]) -> (Ciphertext, [u8; 32]) {
    let pk_bytes = pk.as_bytes();
    let params = params_from_level_byte(pk_bytes[0]);
    let n = params.total_spins;

    // Parse pk
    let seed: [u8; 32] = pk_bytes[1..33].try_into().unwrap();
    let b = Poly::from_bytes(&pk_bytes[33..], n);

    let a = expand_a(&seed, &params);

    // Derive deterministic randomness from coin
    let mut fo_input = Vec::with_capacity(1 + coin.len() + 32);
    fo_input.push(0x10);
    fo_input.extend_from_slice(coin);
    fo_input.extend_from_slice(&hash_pk(pk_bytes));
    let r_seed = spin_hash(&fo_input);

    let mut prng = SpinPrng::with_params(&r_seed, &params);
    let r = sample_cbd(&mut prng, params.cbd_eta, n);
    let e1 = sample_cbd(&mut prng, params.cbd_eta, n);
    let e2 = sample_cbd(&mut prng, params.cbd_eta, n);

    // c₁ = a·r + e₁
    let c1 = poly_add(&poly_mul(&a, &r), &e1);
    // c₂ = b·r + e₂ + encode(m)
    let msg_poly = encode_message(coin, n);
    let c2 = poly_add(&poly_add(&poly_mul(&b, &r), &e2), &msg_poly);

    // Serialize ciphertext: [level, c1(2N), c2(2N)]
    let level_byte = pk_bytes[0];
    let mut ct_bytes = Vec::with_capacity(1 + n * 4);
    ct_bytes.push(level_byte);
    ct_bytes.extend_from_slice(&c1.to_bytes());
    ct_bytes.extend_from_slice(&c2.to_bytes());

    let ct = Ciphertext::from_bytes(&ct_bytes).unwrap();

    // Shared secret = SpinHash(0x11 ‖ m ‖ ct)
    let mut ss_input = Vec::new();
    ss_input.push(0x11);
    ss_input.extend_from_slice(coin);
    ss_input.extend_from_slice(&ct_bytes);
    let ss = spin_hash(&ss_input);

    (ct, ss)
}

/// Encapsulate a fresh shared secret under `pk`.
///
/// Returns the ciphertext (to send to the key holder) and the shared
/// secret (kept locally). The FO transform makes this CCA2-secure.
pub fn encapsulate(pk: &PublicKey) -> EncapsulationResult {
    let pk_bytes = pk.as_bytes();
    let params = params_from_level_byte(pk_bytes[0]);
    let coin_len = params.coin_bytes();

    // Sample random coin m
    let mut coin = vec![0u8; coin_len];
    getrandom::getrandom(&mut coin).expect("OS RNG failed");

    let (ciphertext, ss_bytes) = encaps_inner(pk, &coin);

    EncapsulationResult {
        ciphertext,
        shared_secret: SharedSecret::from_bytes(ss_bytes),
    }
}
