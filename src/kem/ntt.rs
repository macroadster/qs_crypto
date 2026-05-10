//! NTT-based polynomial multiplication for Z_3329[X] / (X^256 + 1).
//!
//! Uses the standard Kyber/ML-KEM Number Theoretic Transform:
//!   - 7-layer Cooley-Tukey forward NTT (degree-256 → 128 degree-2 polys)
//!   - Degree-2 base multiplication with alternating ±zeta per pair
//!   - 7-layer Gentleman-Sande inverse NTT
//!   - Final scaling by 128⁻¹ mod 3329 = 3303
//!
//! The primitive 256th root of unity is ζ = 17 (since 17^128 ≡ −1 mod 3329).
//! Z_3329 supports at most a 256th root of unity (ord(Z*) = 3328 = 2⁸·13),
//! so the NTT decomposes into 128 degree-2 factors, not 256 linear factors.

use crate::core::reduce::barrett_reduce_signed;
use core::hint::black_box;

const Q: i32 = 3329;
pub const N: usize = 256;

/// Standard Kyber/ML-KEM twiddle factors (standard form, not Montgomery).
/// ZETAS[k] = 17^{BitRev7(k)} mod 3329,  where 17 is the primitive 256th
/// root of unity (17^128 ≡ −1 mod 3329).
/// Entries [1..128) are used by the NTT; [64..128) also serve as basemul twiddles.
const ZETAS: [i32; 128] = [
    1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2786, 3260, 569, 1746, 296,
    2447, 1339, 1476, 3046, 56, 2240, 1333, 1426, 2094, 535, 2882, 2393, 2879, 1974, 821, 289, 331,
    3253, 1756, 1197, 2304, 2277, 2055, 650, 1977, 2513, 632, 2865, 33, 1320, 1915, 2319, 1435,
    807, 452, 1438, 2868, 1534, 2402, 2647, 2617, 1481, 648, 2474, 3110, 1227, 910, 17, 2761, 583,
    2649, 1637, 723, 2288, 1100, 1409, 2662, 3281, 233, 756, 2156, 3015, 3050, 1703, 1651, 2789,
    1789, 1847, 952, 1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641, 1584, 2298, 2037,
    3220, 375, 2549, 2090, 1645, 1063, 319, 2773, 757, 2099, 561, 2466, 2594, 2804, 1092, 403,
    1026, 1143, 2150, 2775, 886, 1722, 1212, 1874, 1029, 2110, 2935, 885, 2154,
];

/// Forward NTT (Cooley-Tukey, decimation-in-time, 7 layers).
pub fn ntt(r: &mut [i32; N]) {
    let mut k = 1usize;
    for l in (1..8).rev() {
        let len = 1usize << l;
        for start in (0..N).step_by(2 * len) {
            let zeta = ZETAS[k] as i64;
            k += 1;
            for j in start..start + len {
                let t = barrett_reduce_signed(zeta * black_box(r[j + len]) as i64);
                let r_j = black_box(r[j]);
                r[j] = barrett_reduce_signed(r_j as i64 + t as i64);
                r[j + len] = barrett_reduce_signed(r_j as i64 - t as i64);
            }
        }
    }
}

/// Inverse NTT (Gentleman-Sande, decimation-in-frequency, 7 layers).
pub fn inv_ntt(r: &mut [i32; N]) {
    let mut k = 127usize;
    for l in 1..8 {
        let len = 1usize << l;
        for start in (0..N).step_by(2 * len) {
            let zeta = ZETAS[k] as i64;
            k -= 1;
            for j in start..start + len {
                let r_j = black_box(r[j]) as i64;
                let r_jl = black_box(r[j + len]) as i64;
                r[j] = barrett_reduce_signed(r_j + r_jl);
                r[j + len] = barrett_reduce_signed(zeta * (r_jl - r_j));
            }
        }
    }
    // Scale by N/2⁻¹ = 128⁻¹ mod Q = 3303
    let f = 3303i64;
    for x in r.iter_mut() {
        *x = barrett_reduce_signed(black_box(*x) as i64 * f);
    }
}

/// Base multiplication: degree-2 polynomial multiply in NTT domain.
///
/// Each group of 4 coefficients [4i..4i+3] represents two degree-2
/// polynomials.  The first pair uses +zeta, the second uses −zeta,
/// matching the Kyber basemul convention.
fn base_mul(a: &[i32], b: &[i32]) -> [i32; N] {
    let mut r = [0i32; N];
    for i in 0..(N / 4) {
        let zeta = ZETAS[64 + i] as i64;
        let neg_zeta = Q as i64 - zeta; // Q - zeta is already in [0, Q)

        // First pair in group: indices [4i, 4i+1], twiddle = +zeta
        let j = 4 * i;
        let t0 = barrett_reduce_signed(a[j + 1] as i64 * b[j + 1] as i64);
        r[j] = barrett_reduce_signed(a[j] as i64 * b[j] as i64 + t0 as i64 * zeta);
        r[j + 1] =
            barrett_reduce_signed(a[j] as i64 * b[j + 1] as i64 + a[j + 1] as i64 * b[j] as i64);

        // Second pair in group: indices [4i+2, 4i+3], twiddle = −zeta
        let j = 4 * i + 2;
        let t1 = barrett_reduce_signed(a[j + 1] as i64 * b[j + 1] as i64);
        r[j] = barrett_reduce_signed(a[j] as i64 * b[j] as i64 + t1 as i64 * neg_zeta);
        r[j + 1] =
            barrett_reduce_signed(a[j] as i64 * b[j + 1] as i64 + a[j + 1] as i64 * b[j] as i64);
    }
    r
}

pub fn ntt_mul(a: &[i32; N], b: &[i32; N]) -> [i32; N] {
    let mut aa = *a;
    ntt(&mut aa);
    let mut bb = *b;
    ntt(&mut bb);
    let mut r = base_mul(&aa, &bb);
    inv_ntt(&mut r);
    r
}

// ═══════════════════════════════════════════════════════════════════
// NTT-128: 6-layer transform for Z_3329[X] / (X^128 + 1)
//
// Primitive 128th root of unity: ζ = 289 (= 17², since 289^64 ≡ −1 mod 3329).
// Decomposes into 64 degree-2 factors, with 6 butterfly layers.
// ═══════════════════════════════════════════════════════════════════

pub const N128: usize = 128;

/// ZETAS_128[k] = 289^{BitRev6(k)} mod 3329.
const ZETAS_128: [i32; 64] = [
    1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2786, 3260, 569, 1746, 296,
    2447, 1339, 1476, 3046, 56, 2240, 1333, 1426, 2094, 535, 2882, 2393, 2879, 1974, 821, 289, 331,
    3253, 1756, 1197, 2304, 2277, 2055, 650, 1977, 2513, 632, 2865, 33, 1320, 1915, 2319, 1435,
    807, 452, 1438, 2868, 1534, 2402, 2647, 2617, 1481, 648, 2474, 3110, 1227, 910,
];

/// Forward NTT for N=128 (Cooley-Tukey, 6 layers).
pub fn ntt_128(r: &mut [i32; N128]) {
    let mut k = 1usize;
    for l in (1..7).rev() {
        let len = 1usize << l;
        for start in (0..N128).step_by(2 * len) {
            let zeta = ZETAS_128[k] as i64;
            k += 1;
            for j in start..start + len {
                let t = barrett_reduce_signed(zeta * black_box(r[j + len]) as i64);
                let r_j = black_box(r[j]);
                r[j] = barrett_reduce_signed(r_j as i64 + t as i64);
                r[j + len] = barrett_reduce_signed(r_j as i64 - t as i64);
            }
        }
    }
}

/// Inverse NTT for N=128 (Gentleman-Sande, 6 layers).
pub fn inv_ntt_128(r: &mut [i32; N128]) {
    let mut k = 63usize;
    for l in 1..7 {
        let len = 1usize << l;
        for start in (0..N128).step_by(2 * len) {
            let zeta = ZETAS_128[k] as i64;
            k -= 1;
            for j in start..start + len {
                let r_j = black_box(r[j]) as i64;
                let r_jl = black_box(r[j + len]) as i64;
                r[j] = barrett_reduce_signed(r_j + r_jl);
                r[j + len] = barrett_reduce_signed(zeta * (r_jl - r_j));
            }
        }
    }
    // Scale by 64⁻¹ mod Q = 3277
    let f = 3277i64;
    for x in r.iter_mut() {
        *x = barrett_reduce_signed(black_box(*x) as i64 * f);
    }
}

/// Base multiplication for N=128 NTT domain (32 groups of 4).
fn base_mul_128(a: &[i32], b: &[i32]) -> [i32; N128] {
    let mut r = [0i32; N128];
    for i in 0..(N128 / 4) {
        let zeta = ZETAS_128[32 + i] as i64;
        let neg_zeta = Q as i64 - zeta;

        let j = 4 * i;
        let t0 = barrett_reduce_signed(a[j + 1] as i64 * b[j + 1] as i64);
        r[j] = barrett_reduce_signed(a[j] as i64 * b[j] as i64 + t0 as i64 * zeta);
        r[j + 1] =
            barrett_reduce_signed(a[j] as i64 * b[j + 1] as i64 + a[j + 1] as i64 * b[j] as i64);

        let j = 4 * i + 2;
        let t1 = barrett_reduce_signed(a[j + 1] as i64 * b[j + 1] as i64);
        r[j] = barrett_reduce_signed(a[j] as i64 * b[j] as i64 + t1 as i64 * neg_zeta);
        r[j + 1] =
            barrett_reduce_signed(a[j] as i64 * b[j + 1] as i64 + a[j + 1] as i64 * b[j] as i64);
    }
    r
}

pub fn ntt_mul_128(a: &[i32; N128], b: &[i32; N128]) -> [i32; N128] {
    let mut aa = *a;
    ntt_128(&mut aa);
    let mut bb = *b;
    ntt_128(&mut bb);
    let mut r = base_mul_128(&aa, &bb);
    inv_ntt_128(&mut r);
    r
}

pub fn coeffs_to_i32_128(c: &[u16]) -> [i32; N128] {
    let mut o = [0i32; N128];
    for (i, coeff) in c.iter().enumerate().take(N128) {
        o[i] = *coeff as i32;
    }
    o
}

pub fn i32_to_u16_128(a: &[i32; N128]) -> Vec<u16> {
    a.iter()
        .map(|&x| barrett_reduce_signed(x as i64) as u16)
        .collect()
}

pub fn coeffs_to_i32(c: &[u16]) -> [i32; N] {
    let mut o = [0i32; N];
    for i in 0..N {
        o[i] = c[i] as i32;
    }
    o
}
pub fn i32_to_u16(a: &[i32; N]) -> Vec<u16> {
    a.iter()
        .map(|&x| barrett_reduce_signed(x as i64) as u16)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zetas_table_matches_first_principles() {
        // Verify ZETAS[k] = 17^{BitRev7(k)} mod Q for all k in 0..128.
        // 17 is the primitive 256th root of unity (17^128 ≡ -1 mod Q).
        let q = Q as u64;
        let zeta_prim: u64 = 17;

        fn pow_mod(mut base: u64, mut exp: u32, modulus: u64) -> u64 {
            let mut result = 1u64;
            base %= modulus;
            while exp > 0 {
                if exp & 1 == 1 {
                    result = result * base % modulus;
                }
                exp >>= 1;
                base = base * base % modulus;
            }
            result
        }

        fn bit_rev_7(x: u32) -> u32 {
            let mut r = 0u32;
            let mut v = x;
            for _ in 0..7 {
                r = (r << 1) | (v & 1);
                v >>= 1;
            }
            r
        }

        // Sanity: 17^128 ≡ -1 mod Q
        assert_eq!(pow_mod(zeta_prim, 128, q), q - 1);

        let mut mismatches = 0;
        for k in 0..128u32 {
            let exp = bit_rev_7(k);
            let expected = pow_mod(zeta_prim, exp, q) as i32;
            let got = ZETAS[k as usize];
            if expected != got {
                if mismatches < 10 {
                    println!(
                        "ZETAS[{}]: expected 17^{} = {}, got {}",
                        k, exp, expected, got
                    );
                }
                mismatches += 1;
            }
        }
        assert_eq!(mismatches, 0, "{} ZETAS entries are wrong", mismatches);
    }

    #[test]
    fn ntt_of_constant_one() {
        // NTT([1,0,...,0]) = [1,0,1,0,...,1,0] regardless of zetas table.
        // Because "1 mod (X^2 - gamma)" = (1, 0) for every gamma.
        let mut r = [0i32; N];
        r[0] = 1;
        ntt(&mut r);
        for i in 0..N {
            let expected = if i % 2 == 0 { 1 } else { 0 };
            assert_eq!(
                r[i], expected,
                "NTT(e_0)[{}] = {}, expected {}",
                i, r[i], expected
            );
        }
    }

    #[test]
    fn ntt_of_x2_structure() {
        // NTT(X^2) should have f̂[2i+1] = 0 for all i
        // and f̂[2i] = gamma_i for some gamma_i
        let mut r = [0i32; N];
        r[2] = 1;
        ntt(&mut r);
        for i in 0..N / 2 {
            assert_eq!(
                r[2 * i + 1],
                0,
                "NTT(X^2)[{}] = {}, expected 0",
                2 * i + 1,
                r[2 * i + 1]
            );
        }
    }

    #[test]
    fn inv_ntt_of_known() {
        // INTT([1,0,1,0,...,1,0]) should give [1,0,0,...,0] (the polynomial 1)
        let mut r = [0i32; N];
        for i in 0..N / 2 {
            r[2 * i] = 1;
        }
        inv_ntt(&mut r);
        assert_eq!(r[0], 1, "INTT result[0] = {}, expected 1", r[0]);
        for i in 1..N {
            assert_eq!(r[i], 0, "INTT result[{}] = {}, expected 0", i, r[i]);
        }
    }

    #[test]
    fn ntt_of_x() {
        // NTT([0,1,0,...,0]) = [0,1,0,1,...,0,1] regardless of zetas table.
        // Because "X mod (X^2 - gamma)" = (0, 1) for every gamma.
        let mut r = [0i32; N];
        r[1] = 1;
        ntt(&mut r);
        for i in 0..N {
            let expected = if i % 2 == 1 { 1 } else { 0 };
            assert_eq!(
                r[i], expected,
                "NTT(e_1)[{}] = {}, expected {}",
                i, r[i], expected
            );
        }
    }

    #[test]
    fn ntt_inv_ntt_roundtrip_basis_vectors() {
        let mut passing: Vec<usize> = Vec::new();
        let mut failing: Vec<usize> = Vec::new();
        for idx in 0..N {
            let mut r = [0i32; N];
            r[idx] = 1;
            let orig = r;
            ntt(&mut r);
            inv_ntt(&mut r);
            if r == orig {
                passing.push(idx);
            } else {
                failing.push(idx);
            }
        }
        println!(
            "Pass ({}): {:?}",
            passing.len(),
            &passing[..passing.len().min(40)]
        );
        if !failing.is_empty() {
            println!("First 20 fail: {:?}", &failing[..failing.len().min(20)]);
        }
        assert!(
            failing.is_empty(),
            "{} basis vectors failed roundtrip",
            failing.len()
        );
    }

    #[test]
    fn ntt_inv_ntt_roundtrip_e2_debug() {
        // NTT(e_2), then INTT, check each step
        let mut r = [0i32; N];
        r[2] = 1;
        ntt(&mut r);
        let ntt_out = r;

        // NTT(e_2) should have odd positions = 0
        assert_eq!(ntt_out[1], 0);
        assert_eq!(ntt_out[3], 0);

        // Now apply INTT
        inv_ntt(&mut r);

        // Print first 16 elements of result
        println!("INTT(NTT(e_2))[0..16] = {:?}", &r[0..16]);

        // Should be e_2
        assert_eq!(r[0], 0, "r[0]");
        assert_eq!(r[1], 0, "r[1]");
        assert_eq!(r[2], 1, "r[2]");
        for i in 3..N {
            assert_eq!(r[i], 0, "r[{}]", i);
        }
    }

    #[test]
    fn ntt_inv_ntt_roundtrip_general() {
        let mut r = [0i32; N];
        for i in 0..N {
            r[i] = (i as i32 * 17 + 42) % Q;
        }
        let orig = r;

        ntt(&mut r);
        inv_ntt(&mut r);

        for i in 0..N {
            assert_eq!(r[i], orig[i], "roundtrip mismatch at index {}", i);
        }
    }

    #[test]
    fn ntt_mul_by_one() {
        let mut a = [0i32; N];
        for i in 0..N {
            a[i] = (i as i32 * 17 + 42) % Q;
        }
        let mut one = [0i32; N];
        one[0] = 1;

        let result = ntt_mul(&a, &one);
        let result_u16 = i32_to_u16(&result);
        for i in 0..N {
            assert_eq!(result_u16[i], a[i] as u16, "mul-by-1 mismatch at [{}]", i);
        }
    }
}
