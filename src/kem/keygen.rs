//! Key pair generation.
//!
//! 1. Sample seed → expand public polynomial `a(X)`
//! 2. Sample secret `s(X)` and noise `e(X)` from CBD
//! 3. Compute `b = a·s + e`
//! 4. `pk = (level ‖ seed ‖ b)`, `sk = (level ‖ s ‖ pk)`

use super::ring::{expand_a, poly_add, poly_mul, sample_cbd};
use super::types::{KeyPair, PrivateKey, PublicKey};
use crate::params::Params;
use crate::primitives::prng::SpinPrng;

/// Generate a fresh keypair for the given parameter set.
pub fn generate_keypair(params: &Params) -> KeyPair {
    let n = params.total_spins;
    let level_byte = params.security_level.to_byte();

    // Sample random seed for the public polynomial a(X)
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).expect("OS RNG failed");

    let a = expand_a(&seed, params);

    // Sample secret s and noise e from CBD, seeded from OS entropy
    let mut noise_seed = [0u8; 64];
    getrandom::getrandom(&mut noise_seed).expect("OS RNG failed");

    let mut prng_s = SpinPrng::with_params(&noise_seed[..32], params);
    let mut prng_e = SpinPrng::with_params(&noise_seed[32..], params);

    let s = sample_cbd(&mut prng_s, params.cbd_eta, n);
    let e = sample_cbd(&mut prng_e, params.cbd_eta, n);

    // b = a·s + e  (mod X^N+1, mod q)
    let b = poly_add(&poly_mul(&a, &s), &e);

    // ── Serialize ──────────────────────────────────────────────
    // pk = [level, seed(32), b(2N)]
    let mut pk_bytes = Vec::with_capacity(1 + 32 + n * 2);
    pk_bytes.push(level_byte);
    pk_bytes.extend_from_slice(&seed);
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
