//! Vetted extendable-output function (XOF) based on SHAKE256.
//!
//! Used exclusively for security-critical randomness inside the KEM
//! (key generation, Fujisaki-Okamoto coin derivation, noise sampling).
//! This ensures that the IND-CCA2 security reduction for the KEM
//! depends only on Ring-LWE + SHAKE256 (a NIST-standard primitive),
//! and does *not* depend on the correctness or strength of the novel
//! SpinSponge / SpinPrng construction.

use crate::core::reduce::barrett_reduce_unsigned;
use core::hint::black_box;
use sha3::digest::{ExtendableOutput, Update};
use sha3::Shake256;
use std::io::Read;

use super::ring::Poly;
use crate::params::Params;

/// A simple wrapper that squeezes bytes from a Shake256 instance.
pub struct ShakePrng {
    reader: sha3::Shake256Reader,
}

impl ShakePrng {
    /// Initialize a Shake256 XOF with the given seed material.
    pub fn new(seed: &[u8]) -> Self {
        let mut hasher = Shake256::default();
        hasher.update(seed);
        Self {
            reader: hasher.finalize_xof(),
        }
    }

    /// Squeeze the next `len` bytes.
    pub fn next_bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        self.reader
            .read_exact(&mut out)
            .expect("SHAKE256 XOF read must not fail");
        out
    }
}

/// SHAKE256 squeeze of `input` to 32 bytes.
///
/// Used for FO `H` / `H'` (domain bytes `0x11` / `0x12`) so the
/// IND-CCA2 reduction depends on a vetted random oracle, not SpinHash.
pub(crate) fn shake256_32(input: &[u8]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(input);
    let mut out = [0u8; 32];
    let mut reader = hasher.finalize_xof();
    reader
        .read_exact(&mut out)
        .expect("SHAKE256 XOF read must not fail");
    out
}

/// FIPS 203 / Kyber 12-bit candidate: accept iff already in `[0, q)`.
///
/// Rejecting `d ≥ q` (instead of reducing a range that is not a multiple
/// of `q`) is what makes public `a` uniform in `R_q`.
#[inline]
pub(crate) fn accept_uniform_zq_12(d: u16) -> Option<u16> {
    if d < crate::params::FIELD_MODULUS {
        Some(d)
    } else {
        None
    }
}

/// Deterministically expand a 32-byte seed into a uniform polynomial
/// over Z_q using SHAKE256.  Used for the public 'a' polynomial in the
/// hardened KEM path.
///
/// Coefficients are sampled by 12-bit rejection (FIPS 203 SampleNTT):
/// each 3-byte block yields two 12-bit candidates; a candidate is kept
/// only when it is already in `[0, q)`. Nothing is reduced modulo `q`
/// from a range that is not a multiple of `q`.
pub fn expand_a_shake(seed: &[u8; 32], params: &Params) -> Poly {
    let n = params.ring_dim;
    let mut xof = ShakePrng::new(seed);
    let mut coeffs = Vec::with_capacity(n);
    while coeffs.len() < n {
        let buf = xof.next_bytes(3);
        let d1 = u16::from(buf[0]) | ((u16::from(buf[1]) & 0x0f) << 8);
        let d2 = (u16::from(buf[1]) >> 4) | (u16::from(buf[2]) << 4);
        if let Some(c) = accept_uniform_zq_12(d1) {
            coeffs.push(c);
            if coeffs.len() == n {
                break;
            }
        }
        if let Some(c) = accept_uniform_zq_12(d2) {
            if coeffs.len() < n {
                coeffs.push(c);
            }
        }
    }
    Poly { coeffs, n }
}

/// Sample a polynomial from the Centered Binomial Distribution CBD(η)
/// using a SHAKE256 XOF.  Domain-separated by the provided label.
pub fn sample_cbd_shake(label: &[u8], eta: u8, n: usize) -> Poly {
    let bits_per_sample = 2 * eta as usize;
    let bytes_needed = (bits_per_sample * n).div_ceil(8);

    let mut xof = ShakePrng::new(label);
    let random = xof.next_bytes(bytes_needed);

    let mut coeffs = Vec::with_capacity(n);
    let mut bit_pos = 0usize;

    for _ in 0..n {
        let mut a: u32 = 0;
        let mut b: u32 = 0;
        for _ in 0..eta {
            let byte_idx = bit_pos / 8;
            let bit_idx = bit_pos % 8;
            if byte_idx < random.len() {
                a += black_box(((random[byte_idx] >> bit_idx) & 1) as u32);
            }
            bit_pos += 1;
        }
        for _ in 0..eta {
            let byte_idx = bit_pos / 8;
            let bit_idx = bit_pos % 8;
            if byte_idx < random.len() {
                b += black_box(((random[byte_idx] >> bit_idx) & 1) as u32);
            }
            bit_pos += 1;
        }
        coeffs.push(black_box(barrett_reduce_unsigned(
            (a + crate::params::FIELD_MODULUS as u32 - b) as u64,
        )));
    }
    Poly { coeffs, n }
}

/// Derive the Fujisaki-Okamoto blinding factors (r, e1, e2) from the
/// random coin `m` and the public key hash, using SHAKE256.
/// This is the critical step that must be deterministic for the FO check
/// but must also be unpredictable to an attacker.
pub fn derive_fo_materials(coin: &[u8], pk_hash: &[u8; 32], params: &Params) -> (Poly, Poly, Poly) {
    let n = params.ring_dim;
    let eta = params.cbd_eta;

    // Domain separation: 0x10 || coin || pk_hash
    let mut seed = Vec::with_capacity(1 + coin.len() + 32);
    seed.push(0x10);
    seed.extend_from_slice(coin);
    seed.extend_from_slice(pk_hash);

    // We need three independent CBD samples + the message encoding is separate.
    // To keep sampling deterministic and non-overlapping, we use labeled prefixes.
    let mut xof = ShakePrng::new(&seed);

    // First 32 bytes for r seed
    let r_label = xof.next_bytes(32);
    let r = sample_cbd_shake(&r_label, eta, n);

    // Next for e1
    let e1_label = xof.next_bytes(32);
    let e1 = sample_cbd_shake(&e1_label, eta, n);

    // Next for e2
    let e2_label = xof.next_bytes(32);
    let e2 = sample_cbd_shake(&e2_label, eta, n);

    (r, e1, e2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::reduce::barrett_reduce_unsigned;
    use crate::params::{Params, FIELD_MODULUS};

    #[test]
    fn twelve_bit_candidate_at_or_above_q_is_rejected() {
        assert_eq!(accept_uniform_zq_12(0), Some(0));
        assert_eq!(
            accept_uniform_zq_12(FIELD_MODULUS - 1),
            Some(FIELD_MODULUS - 1)
        );
        assert_eq!(accept_uniform_zq_12(FIELD_MODULUS), None);
        assert_eq!(accept_uniform_zq_12(4095), None);
    }

    #[test]
    fn expand_a_shake_coeffs_in_range() {
        let params = Params::default();
        let seed = [0x11u8; 32];
        let a = expand_a_shake(&seed, &params);
        assert_eq!(a.coeffs.len(), params.ring_dim);
        assert!(a.coeffs.iter().all(|&c| c < FIELD_MODULUS));
    }

    #[test]
    fn expand_a_shake_is_deterministic() {
        let params = Params::default();
        let seed = [0x5Au8; 32];
        let a = expand_a_shake(&seed, &params);
        let b = expand_a_shake(&seed, &params);
        assert_eq!(a.coeffs, b.coeffs);
    }

    #[test]
    fn expand_a_shake_does_not_barrett_reduce_raw_u16() {
        // HEAD mapped each SHAKE u16 through Barrett (biased: 0..2284
        // appear 20 times, 2285..3328 appear 19). Rejection sampling
        // must not reproduce that map.
        let params = Params::default();
        let seed = [0xA5u8; 32];
        let a = expand_a_shake(&seed, &params);

        let mut xof = ShakePrng::new(&seed);
        let raw = xof.next_bytes(params.ring_dim * 2);
        let old: Vec<u16> = raw
            .chunks(2)
            .map(|c| barrett_reduce_unsigned(u16::from_le_bytes([c[0], c[1]]) as u64))
            .collect();

        assert_ne!(
            a.coeffs, old,
            "public a must not be the old u16-then-Barrett image of SHAKE"
        );
    }
}
