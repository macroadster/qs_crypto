//! Polynomial arithmetic over Z_q\[X\]/(X^N + 1).
//!
//! Provides the algebraic foundation for the Ring-LWE KEM.  N=256 (QS256)
//! uses NTT-based O(N log N) multiplication; other sizes fall back to
//! schoolbook O(N²).

use crate::params::{Params, SecurityLevel, FIELD_MODULUS};
use crate::primitives::hash::spin_hash;
use crate::primitives::prng::SpinPrng;
use core::hint::black_box;

/// A polynomial in Z_q\[X\]/(X^N + 1), stored as a vector of coefficients.
#[derive(Clone, Debug)]
pub struct Poly {
    pub coeffs: Vec<u16>,
    pub n: usize,
}

impl Poly {
    #[allow(dead_code)]
    pub fn zero(n: usize) -> Self {
        Self {
            coeffs: vec![0u16; n],
            n,
        }
    }

    #[allow(dead_code)]
    pub fn from_coeffs(coeffs: Vec<u16>) -> Self {
        let n = coeffs.len();
        Self { coeffs, n }
    }

    /// Serialize to bytes (little-endian u16 per coefficient).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.n * 2);
        for &c in &self.coeffs {
            out.extend_from_slice(&c.to_le_bytes());
        }
        out
    }

    /// Deserialize from bytes.
    pub fn from_bytes(data: &[u8], n: usize) -> Self {
        let mut coeffs = Vec::with_capacity(n);
        for chunk in data[..n * 2].chunks(2) {
            coeffs.push(u16::from_le_bytes([chunk[0], chunk[1]]));
        }
        Self { coeffs, n }
    }
}

/// `c = a + b  (mod q)`, coefficient-wise.
pub fn poly_add(a: &Poly, b: &Poly) -> Poly {
    let q = FIELD_MODULUS as u32;
    let n = a.n;
    let coeffs: Vec<u16> = a
        .coeffs
        .iter()
        .zip(b.coeffs.iter())
        .map(|(&ai, &bi)| ((ai as u32 + bi as u32) % q) as u16)
        .collect();
    Poly { coeffs, n }
}

/// `c = a − b  (mod q)`, coefficient-wise.
pub fn poly_sub(a: &Poly, b: &Poly) -> Poly {
    let q = FIELD_MODULUS as u32;
    let n = a.n;
    let coeffs: Vec<u16> = a
        .coeffs
        .iter()
        .zip(b.coeffs.iter())
        .map(|(&ai, &bi)| ((ai as u32 + q - bi as u32) % q) as u16)
        .collect();
    Poly { coeffs, n }
}

/// `c = a · b  (mod X^N + 1, mod q)`
///
/// Uses NTT (O(N log N)) for N=256, schoolbook (O(N²)) for other sizes.
pub fn poly_mul(a: &Poly, b: &Poly) -> Poly {
    if a.n == 256 {
        use super::ntt;
        let aa = ntt::coeffs_to_i32(&a.coeffs);
        let bb = ntt::coeffs_to_i32(&b.coeffs);
        let res = ntt::ntt_mul(&aa, &bb);
        let coeffs = ntt::i32_to_u16(&res);
        return Poly { coeffs, n: a.n };
    }

    // Schoolbook for non-power-of-2 sizes (QS128 N=144, QS192 N=196)
    let q = FIELD_MODULUS as u64;
    let n = a.n;

    let mut temp = vec![0i64; 2 * n];
    for i in 0..n {
        for j in 0..n {
            let ai = black_box(a.coeffs[i] as i64);
            let bj = black_box(b.coeffs[j] as i64);
            temp[i + j] += ai * bj;
        }
    }

    let mut coeffs = vec![0u16; n];
    for k in 0..n {
        let val = temp[k] - temp[k + n];
        coeffs[k] = (val.rem_euclid(q as i64)) as u16;
    }
    Poly { coeffs, n }
}

/// Exposed for differential testing and verification (always the reliable schoolbook version)
pub fn schoolbook_poly_mul(a: &Poly, b: &Poly) -> Poly {
    let q = FIELD_MODULUS as u64;
    let n = a.n;

    let mut temp = vec![0i64; 2 * n];
    for i in 0..n {
        for j in 0..n {
            temp[i + j] += a.coeffs[i] as i64 * b.coeffs[j] as i64;
        }
    }

    let mut coeffs = vec![0u16; n];
    for k in 0..n {
        let val = temp[k] - temp[k + n];
        coeffs[k] = (val.rem_euclid(q as i64)) as u16;
    }
    Poly { coeffs, n }
}

/// Deterministically expand a 32-byte `seed` into a uniformly random
/// polynomial over Z_q (used for the public matrix element `a`).
///
/// This SpinPrng-based version is retained for research / "pure physics"
/// experiments. The hardened KEM uses `expand_a_shake`.
#[allow(dead_code)]
pub fn expand_a(seed: &[u8; 32], params: &Params) -> Poly {
    let n = params.total_spins;
    let q = params.q;
    let mut prng = SpinPrng::with_params(seed, params);
    let raw = prng.next_bytes(n * 2);
    let mut coeffs = Vec::with_capacity(n);
    for chunk in raw.chunks(2) {
        coeffs.push(u16::from_le_bytes([chunk[0], chunk[1]]) % q);
    }
    Poly { coeffs, n }
}

/// Sample a polynomial from the Centered Binomial Distribution CBD(η).
///
/// This SpinPrng-based version is retained for research / "pure physics"
/// experiments. The hardened KEM uses `sample_cbd_shake`.
#[allow(dead_code)]
pub fn sample_cbd(prng: &mut SpinPrng, eta: u8, n: usize) -> Poly {
    let q = FIELD_MODULUS as u32;
    let bits_per_sample = 2 * eta as usize;
    let bytes_needed = (bits_per_sample * n).div_ceil(8);
    let random = prng.next_bytes(bytes_needed);

    let mut coeffs = Vec::with_capacity(n);
    let mut bit_pos = 0usize;

    for _ in 0..n {
        let mut a: u32 = 0;
        let mut b: u32 = 0;
        for _ in 0..eta {
            let byte_idx = bit_pos / 8;
            let bit_idx = bit_pos % 8;
            if byte_idx < random.len() {
                a += ((random[byte_idx] >> bit_idx) & 1) as u32;
            }
            bit_pos += 1;
        }
        for _ in 0..eta {
            let byte_idx = bit_pos / 8;
            let bit_idx = bit_pos % 8;
            if byte_idx < random.len() {
                b += ((random[byte_idx] >> bit_idx) & 1) as u32;
            }
            bit_pos += 1;
        }
        coeffs.push(((a + q - b) % q) as u16);
    }
    Poly { coeffs, n }
}

/// Encode a message (byte slice) into a polynomial.
/// Each bit maps to 0 or ⌊q/2⌋.
pub fn encode_message(m: &[u8], n: usize) -> Poly {
    let half_q = FIELD_MODULUS / 2;
    let mut coeffs = vec![0u16; n];
    let bits = m.len() * 8;
    for i in 0..bits.min(n) {
        if (m[i / 8] >> (i % 8)) & 1 == 1 {
            coeffs[i] = half_q;
        }
    }
    Poly { coeffs, n }
}

/// Decode a polynomial back to message bytes.
/// Each coefficient is rounded to the nearest of {0, ⌊q/2⌋}.
pub fn decode_message(poly: &Poly, msg_bytes: usize) -> Vec<u8> {
    let q = FIELD_MODULUS;
    let half_q = q / 2;
    let mut result = vec![0u8; msg_bytes];
    let bits = msg_bytes * 8;
    for i in 0..bits.min(poly.n) {
        let c = poly.coeffs[i];
        // Distance to 0
        let d0 = c.min(q - c) as u32;
        // Distance to q/2
        let d_half = if c >= half_q {
            (c - half_q) as u32
        } else {
            (half_q - c) as u32
        };
        if d_half < d0 {
            result[i / 8] |= 1 << (i % 8);
        }
    }
    result
}

/// Hash a public key for the FO transform.
pub fn hash_pk(pk_bytes: &[u8]) -> [u8; 32] {
    spin_hash(pk_bytes)
}

/// Infer [`Params`] from a security-level byte stored at the start of
/// a serialized key/ciphertext.
pub fn params_from_level_byte(b: u8) -> Params {
    let level = SecurityLevel::from_byte(b).expect("invalid security level byte");
    Params::from_security_level(level)
}
