//! KEM decapsulation.
//!
//! 1. Recover noisy message m̃  = c₂ − s·c₁  (mod X^N+1, mod q)
//! 2. Decode m' from m̃
//! 3. Re-encapsulate with m' and verify ciphertext matches (FO check)
//! 4. On mismatch → implicit rejection (return hash of sk ‖ ct)

use subtle::ConstantTimeEq;

use super::encaps::encaps_inner;
use super::ring::{decode_message, params_from_level_byte, poly_mul, poly_sub, Poly};
use super::types::{Ciphertext, PrivateKey, PublicKey, SharedSecret};
use crate::primitives::hash::spin_hash;

/// Decapsulate a shared secret from `ct` using `sk`.
///
/// Implicit rejection: if the FO re-encapsulation check fails, a
/// deterministic but unrelated secret is returned (derived from sk ‖ ct)
/// so the caller cannot distinguish valid from invalid ciphertexts.
pub fn decapsulate(sk: &PrivateKey, ct: &Ciphertext) -> crate::Result<SharedSecret> {
    let sk_bytes = sk.as_bytes();
    let ct_bytes = ct.as_bytes();

    if sk_bytes[0] != ct_bytes[0] {
        return Err(crate::Error::DecapsulationFailed);
    }

    let params = params_from_level_byte(sk_bytes[0]);
    let n = params.total_spins;
    let coin_len = params.coin_bytes();

    // Parse secret key:  [level, s(2N), pk(1+32+2N)]
    let s = Poly::from_bytes(&sk_bytes[1..], n);
    let pk_bytes = &sk_bytes[1 + n * 2..];
    let pk = PublicKey::from_bytes(pk_bytes).unwrap();

    // Parse ciphertext: [level, c1(2N), c2(2N)]
    let c1 = Poly::from_bytes(&ct_bytes[1..], n);
    let c2 = Poly::from_bytes(&ct_bytes[1 + n * 2..], n);

    // 1. Recover noisy message: m̃ = c₂ − s·c₁
    let s_c1 = poly_mul(&s, &c1);
    let m_noisy = poly_sub(&c2, &s_c1);

    // 2. Decode message bits
    let m_prime = decode_message(&m_noisy, coin_len);

    // 3. Re-encapsulate (FO check)
    let (ct_prime, ss_valid) = encaps_inner(&pk, &m_prime);

    // 4. Constant-time comparison of ciphertexts
    let ct_match = ct_bytes.ct_eq(ct_prime.as_bytes());
    // Derive mask without branching: 0xFF if match, 0x00 if not
    let mask = ct_match.unwrap_u8().wrapping_neg();

    // Implicit-rejection secret: SpinHash(0x12 ‖ sk ‖ ct)
    let mut rej_input = Vec::new();
    rej_input.push(0x12);
    rej_input.extend_from_slice(sk_bytes);
    rej_input.extend_from_slice(ct_bytes);
    let ss_reject = spin_hash(&rej_input);

    // Select valid or rejection secret in constant time
    let mut ss = [0u8; 32];
    for i in 0..32 {
        ss[i] = (ss_valid[i] & mask) | (ss_reject[i] & !mask);
    }

    Ok(SharedSecret::from_bytes(ss))
}
