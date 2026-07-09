//! Polynomial arithmetic over Z_q\[X\]/(X^N + 1).
//!
//! Provides the algebraic foundation for the Ring-LWE KEM.  N=256 (QS256)
//! and N=128 (QS128) use NTT-based O(N log N) multiplication; other sizes
//! fall back to schoolbook O(N²).

use crate::core::reduce::{barrett_reduce_signed, barrett_reduce_unsigned};
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
    ///
    /// # Panics
    /// Panics if `data.len() < n * 2`.
    pub fn from_bytes(data: &[u8], n: usize) -> Self {
        assert!(
            data.len() >= n * 2,
            "Poly::from_bytes: data too short ({} < {})",
            data.len(),
            n * 2
        );
        let mut coeffs = Vec::with_capacity(n);
        for chunk in data[..n * 2].chunks(2) {
            let c = u16::from_le_bytes([chunk[0], chunk[1]]);
            coeffs.push(barrett_reduce_unsigned(c as u64));
        }
        Self { coeffs, n }
    }
}

/// `c = a + b  (mod q)`, coefficient-wise.
pub fn poly_add(a: &Poly, b: &Poly) -> Poly {
    let n = a.n;
    let coeffs: Vec<u16> = a
        .coeffs
        .iter()
        .zip(b.coeffs.iter())
        .map(|(&ai, &bi)| barrett_reduce_unsigned((ai as u32 + bi as u32) as u64))
        .collect();
    Poly { coeffs, n }
}

/// `c = a − b  (mod q)`, coefficient-wise.
pub fn poly_sub(a: &Poly, b: &Poly) -> Poly {
    let n = a.n;
    let coeffs: Vec<u16> = a
        .coeffs
        .iter()
        .zip(b.coeffs.iter())
        .map(|(&ai, &bi)| {
            barrett_reduce_unsigned((ai as u32 + FIELD_MODULUS as u32 - bi as u32) as u64)
        })
        .collect();
    Poly { coeffs, n }
}

/// `c = a · b  (mod X^N + 1, mod q)`
///
/// Uses NTT (O(N log N)) when [`uses_ntt_mul`] is true (N=256 and N=128);
/// otherwise schoolbook (O(N²)). Dispatch is gated on that helper so path
/// queries and implementation cannot drift apart.
pub fn poly_mul(a: &Poly, b: &Poly) -> Poly {
    if uses_ntt_mul(a.n) {
        return ntt_poly_mul(a, b);
    }

    // Schoolbook fallback for non-NTT sizes (timing-hardened with black_box)
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
        coeffs[k] = barrett_reduce_signed(val) as u16;
    }
    Poly { coeffs, n }
}

/// NTT fast path; only called when [`uses_ntt_mul`]`(a.n)` is true.
#[inline]
fn ntt_poly_mul(a: &Poly, b: &Poly) -> Poly {
    use super::ntt;
    match a.n {
        256 => {
            let aa = ntt::coeffs_to_i32(&a.coeffs);
            let bb = ntt::coeffs_to_i32(&b.coeffs);
            let res = ntt::ntt_mul(&aa, &bb);
            let coeffs = ntt::i32_to_u16(&res);
            Poly { coeffs, n: 256 }
        }
        128 => {
            let aa = ntt::coeffs_to_i32_128(&a.coeffs);
            let bb = ntt::coeffs_to_i32_128(&b.coeffs);
            let res = ntt::ntt_mul_128(&aa, &bb);
            let coeffs = ntt::i32_to_u16_128(&res);
            Poly { coeffs, n: 128 }
        }
        // uses_ntt_mul is the single source of truth for supported NTT sizes.
        n => unreachable!("uses_ntt_mul({n}) was true but no NTT implementation"),
    }
}

/// Exposed for differential testing and verification (always the reliable schoolbook version)
pub fn schoolbook_poly_mul(a: &Poly, b: &Poly) -> Poly {
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
        coeffs[k] = barrett_reduce_signed(val) as u16;
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
    let n = params.ring_dim;
    let mut prng = SpinPrng::with_params(seed, params);
    let raw = prng.next_bytes(n * 2);
    let mut coeffs = Vec::with_capacity(n);
    for chunk in raw.chunks(2) {
        coeffs.push(barrett_reduce_unsigned(
            u16::from_le_bytes([chunk[0], chunk[1]]) as u64,
        ));
    }
    Poly { coeffs, n }
}

/// Sample a polynomial from the Centered Binomial Distribution CBD(η).
///
/// This SpinPrng-based version is retained for research / "pure physics"
/// experiments. The hardened KEM uses `sample_cbd_shake`.
#[allow(dead_code)]
pub fn sample_cbd(prng: &mut SpinPrng, eta: u8, n: usize) -> Poly {
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
        coeffs.push(barrett_reduce_unsigned(
            (a + FIELD_MODULUS as u32 - b) as u64,
        ));
    }
    Poly { coeffs, n }
}

/// Encode a message (byte slice) into a polynomial.
/// Each bit maps to 0 or ⌊q/2⌋.
///
/// Uses branchless multiplication instead of a conditional to avoid
/// data-dependent timing on message bits.
pub fn encode_message(m: &[u8], n: usize) -> Poly {
    let half_q = FIELD_MODULUS / 2;
    let mut coeffs = vec![0u16; n];
    let bits = m.len() * 8;
    for i in 0..bits.min(n) {
        let bit = ((m[i / 8] >> (i % 8)) & 1) as u16;
        coeffs[i] = bit * half_q;
    }
    Poly { coeffs, n }
}

/// Decode a polynomial back to message bytes.
/// Each coefficient is rounded to the nearest of {0, ⌊q/2⌋}.
///
/// All comparisons use branchless arithmetic so the function runs in
/// constant time with respect to the coefficient values (critical for
/// the Fujisaki-Okamoto implicit-rejection path in decaps).
pub fn decode_message(poly: &Poly, msg_bytes: usize) -> Vec<u8> {
    let q = FIELD_MODULUS as i32;
    let half_q = (FIELD_MODULUS / 2) as i32;
    let mut result = vec![0u8; msg_bytes];
    let bits = msg_bytes * 8;
    for i in 0..bits.min(poly.n) {
        let c = black_box(poly.coeffs[i] as i32);

        // d0 = min(c, q - c): distance to 0 on the ring (branchless)
        let qmc = q - c;
        let diff = c - qmc;
        let lt_mask = diff >> 31; // -1 if c < q-c, 0 otherwise
        let d0 = qmc + (diff & lt_mask); // min(c, q-c)

        // d_half = |c - half_q|: distance to q/2 (branchless abs)
        let d = c - half_q;
        let sign = d >> 31;
        let d_half = (d ^ sign) - sign;

        // bit = 1 iff d_half < d0 (coefficient closer to q/2 than to 0)
        let bit = (((d_half - d0) >> 31) & 1) as u8;
        result[i / 8] |= bit << (i % 8);
    }
    result
}

/// Hash a public key for the FO transform.
pub fn hash_pk(pk_bytes: &[u8]) -> [u8; 32] {
    spin_hash(pk_bytes)
}

/// Infer [`Params`] from a security-level byte stored at the start of
/// a serialized key/ciphertext.
///
/// # Panics
/// Panics on an unrecognised level byte. Callers that handle untrusted
/// input should validate the byte before calling this function.
pub fn params_from_level_byte(b: u8) -> Params {
    let level = SecurityLevel::from_byte(b).expect("invalid security level byte");
    Params::from_security_level(level)
}

/// Returns true when `poly_mul` uses the NTT fast path for dimension `n`.
///
/// QS128 (`n == 128`) and QS256 (`n == 256`) are NTT-backed; other sizes
/// fall through to schoolbook. This is the **single source of truth** for
/// dispatch: [`poly_mul`] calls [`ntt_poly_mul`] only when this returns true.
#[inline]
pub fn uses_ntt_mul(n: usize) -> bool {
    matches!(n, 128 | 256)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::SecurityLevel;

    #[test]
    fn qs128_uses_ntt_path() {
        let params = Params::from_security_level(SecurityLevel::QS128);
        assert_eq!(params.ring_dim, 128, "QS128 must use ring_dim 128");
        assert!(
            uses_ntt_mul(params.ring_dim),
            "QS128 poly_mul must use NTT-128, not schoolbook"
        );
    }

    #[test]
    fn qs256_uses_ntt_path() {
        let params = Params::from_security_level(SecurityLevel::QS256);
        assert_eq!(params.ring_dim, 256);
        assert!(uses_ntt_mul(params.ring_dim));
    }

    #[test]
    fn qs192_uses_ntt_256() {
        // QS192 also uses N=256 ring (NTT-256), not schoolbook.
        let params = Params::from_security_level(SecurityLevel::QS192);
        assert_eq!(params.ring_dim, 256);
        assert!(uses_ntt_mul(params.ring_dim));
    }

    #[test]
    fn ntt128_poly_mul_matches_schoolbook() {
        // Correctness: poly_mul (NTT path via uses_ntt_mul) agrees with schoolbook.
        // Path activation is guaranteed by uses_ntt_mul being the poly_mul gate;
        // see also Criterion poly_mul_n128 timing vs schoolbook.
        let n = 128usize;
        assert!(
            uses_ntt_mul(n),
            "test precondition: N=128 must select NTT in poly_mul"
        );
        let mut a_coeffs = vec![0u16; n];
        let mut b_coeffs = vec![0u16; n];
        for i in 0..n {
            a_coeffs[i] = ((i * 17 + 3) % FIELD_MODULUS as usize) as u16;
            b_coeffs[i] = ((i * 41 + 11) % FIELD_MODULUS as usize) as u16;
        }
        let a = Poly::from_coeffs(a_coeffs);
        let b = Poly::from_coeffs(b_coeffs);
        let ntt_prod = poly_mul(&a, &b);
        let sb_prod = schoolbook_poly_mul(&a, &b);
        assert_eq!(
            ntt_prod.coeffs, sb_prod.coeffs,
            "NTT-128 poly_mul diverged from schoolbook"
        );
    }

    #[test]
    fn ntt128_poly_mul_random_vectors_match_schoolbook() {
        let n = 128usize;
        assert!(uses_ntt_mul(n));
        // A few more patterns including sparse / one / zero-ish cases.
        let cases: Vec<(Vec<u16>, Vec<u16>)> = vec![
            (vec![1u16; n], vec![1u16; n]),
            (
                {
                    let mut v = vec![0u16; n];
                    v[0] = 1;
                    v
                },
                {
                    let mut v = vec![0u16; n];
                    v[1] = 1;
                    v
                },
            ),
            (
                (0..n).map(|i| (i as u16 * 7) % FIELD_MODULUS).collect(),
                (0..n)
                    .map(|i| ((i as u16).wrapping_mul(13) + 5) % FIELD_MODULUS)
                    .collect(),
            ),
        ];
        for (a_c, b_c) in cases {
            let a = Poly::from_coeffs(a_c);
            let b = Poly::from_coeffs(b_c);
            assert_eq!(poly_mul(&a, &b).coeffs, schoolbook_poly_mul(&a, &b).coeffs);
        }
    }

    #[test]
    fn non_ntt_dimension_does_not_claim_ntt() {
        assert!(!uses_ntt_mul(64));
        assert!(!uses_ntt_mul(192));
        assert!(!uses_ntt_mul(0));
    }
}
