//! Key pair generation.
//!
//! Hardened version: all internal randomness (seed expansion and CBD sampling)
//! is derived from SHAKE256 (a NIST-standard XOF). This ensures the KEM's
//! security reduction depends only on Ring-LWE + SHAKE256, independent of
//! the novel SpinSponge construction (which remains available for symmetric
//! primitives and the visual layer).

use zeroize::Zeroize;

use super::ring::{poly_add, poly_mul};
use super::types::{KeyPair, PrivateKey, PublicKey};
use super::xof::{expand_a_shake, sample_cbd_shake};
use crate::params::Params;
use getrandom;

/// Generate a fresh keypair for the given parameter set.
///
/// All randomness for `a`, `s`, and `e` is derived via SHAKE256 from
/// high-entropy OS seeds. This makes the KEM's concrete security
/// reduction independent of the SpinSponge permutation.
pub fn generate_keypair(params: &Params) -> KeyPair {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).expect("OS RNG failed");

    let mut os_seed = [0u8; 64];
    getrandom::getrandom(&mut os_seed).expect("OS RNG failed");

    let kp = generate_keypair_deterministic(params, &seed, &os_seed);
    os_seed.zeroize();
    kp
}

/// Deterministic keypair generation from caller-supplied seeds.
///
/// `seed` (32 bytes) expands the public polynomial **a**.
/// `os_seed` (64 bytes) derives the secret **s** and noise **e**.
///
/// This is exposed for reproducible KAT vector generation; production
/// callers should use [`generate_keypair`] which samples from OS entropy.
pub fn generate_keypair_deterministic(
    params: &Params,
    seed: &[u8; 32],
    os_seed: &[u8; 64],
) -> KeyPair {
    let n = params.ring_dim;
    let level_byte = params.security_level.to_byte();
    let eta = params.cbd_eta;

    let a = expand_a_shake(seed, params);

    let s_label = {
        let mut l = b"qs-kem-keygen-s".to_vec();
        l.extend_from_slice(&os_seed[..32]);
        l
    };
    let e_label = {
        let mut l = b"qs-kem-keygen-e".to_vec();
        l.extend_from_slice(&os_seed[32..]);
        l
    };

    let s = sample_cbd_shake(&s_label, eta, n);
    let e = sample_cbd_shake(&e_label, eta, n);

    // b = a·s + e  (mod X^N+1, mod q)
    let b = poly_add(&poly_mul(&a, &s), &e);

    // ── Serialize ──────────────────────────────────────────────
    // pk = [level, seed(32), b(2N)]
    let mut pk_bytes = Vec::with_capacity(1 + 32 + n * 2);
    pk_bytes.push(level_byte);
    pk_bytes.extend_from_slice(seed);
    pk_bytes.extend_from_slice(&b.to_bytes());

    // sk = [level, s(2N), pk]
    let mut sk_bytes = Vec::with_capacity(1 + n * 2 + pk_bytes.len());
    sk_bytes.push(level_byte);
    sk_bytes.extend_from_slice(&s.to_bytes());
    sk_bytes.extend_from_slice(&pk_bytes); // embed pk for FO re-encaps

    KeyPair {
        public_key: PublicKey::from_bytes(&pk_bytes).unwrap(),
        private_key: PrivateKey::from_bytes(&sk_bytes).unwrap(),
    }
}
