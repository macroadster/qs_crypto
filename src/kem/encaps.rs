//! KEM encapsulation.
//!
//! Hardened Fujisaki-Okamoto construction:
//! - Random coin `m` comes from OS entropy.
//! - All blinding factors (r, e1, e2) are derived deterministically from `m`
//!   using SHAKE256 (vetted XOF). This keeps the CCA security reduction clean.

use zeroize::Zeroize;

use super::ring::{encode_message, hash_pk, params_from_level_byte, poly_add, poly_mul, Poly};
use super::types::{Ciphertext, EncapsulationResult, PublicKey, SharedSecret};
use super::xof::{derive_fo_materials, expand_a_shake};
use crate::primitives::hash::spin_hash;

/// Deterministic inner encapsulation (used by both encaps and decaps FO check).
///
/// All blinding vectors are derived from the coin via SHAKE256 so that
/// the correctness of the FO transform does not rely on SpinPrng.
pub(crate) fn encaps_inner(pk: &PublicKey, coin: &[u8]) -> (Ciphertext, [u8; 32]) {
    let pk_bytes = pk.as_bytes();
    let params = params_from_level_byte(pk_bytes[0]);
    let n = params.ring_dim;

    // Parse pk
    let seed: [u8; 32] = pk_bytes[1..33].try_into().unwrap();
    let b = Poly::from_bytes(&pk_bytes[33..], n);

    let a = expand_a_shake(&seed, &params);

    // Derive deterministic FO blinding material using the vetted XOF
    let pk_hash = hash_pk(pk_bytes);
    let (r, e1, e2) = derive_fo_materials(coin, &pk_hash, &params);

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

    // Shared secret = SpinHash(0x11 ‖ m ‖ ct)  — still uses the library hash
    // (acceptable: the SS is user-visible output; the reduction protects the
    //  confidentiality of the message inside the KEM).
    let mut ss_input = Vec::with_capacity(1 + coin.len() + ct_bytes.len());
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

    // Zeroize the FO coin — it is the secret that protects IND-CCA2.
    coin.zeroize();

    EncapsulationResult {
        ciphertext,
        shared_secret: SharedSecret::from_bytes(ss_bytes),
    }
}

/// Deterministic encapsulation with a caller-supplied FO coin.
///
/// This is exposed for reproducible KAT vector generation; production
/// callers should use [`encapsulate`] which samples from OS entropy.
pub fn encapsulate_deterministic(pk: &PublicKey, coin: &[u8]) -> EncapsulationResult {
    let (ciphertext, ss_bytes) = encaps_inner(pk, coin);
    EncapsulationResult {
        ciphertext,
        shared_secret: SharedSecret::from_bytes(ss_bytes),
    }
}
