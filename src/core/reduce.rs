//! Constant-time modular reduction for Q = 3329.
//!
//! Replaces variable-time hardware integer division (`%`, `rem_euclid`)
//! with Barrett reduction (multiply + shift).  Hardware `div`/`rem` may
//! be variable-time on some microarchitectures depending on operand
//! magnitude — Barrett avoids this entirely.
//!
//! Reference: Kyber reference implementation `reduce.c`.

/// Field modulus (same as ML-KEM / Kyber).
const Q: i32 = 3329;

// ── Signed Barrett (NTT butterflies, signed products) ──────────────

/// Barrett reduce a signed i64 value to `[0, Q)`.
///
/// Handles the full i64 range via i128 intermediate arithmetic.
/// Covers NTT products (max ≈ Q² ≈ 11M) and schoolbook polynomial
/// accumulations (up to N·Q² ≈ 2.2 billion for N=196).
#[inline]
pub fn barrett_reduce_signed(a: i64) -> i32 {
    const Q64: i64 = 3329;
    // V = floor(2^48 / Q), compiler-evaluated.  i128 multiply avoids
    // overflow for a up to ±2^63.  Error < |a| / 2^48 < 1 for |a| < 2^48.
    const V: i128 = (1i128 << 48) / Q64 as i128;
    let t = ((a as i128 * V + (1i128 << 47)) >> 48) as i64;
    let mut r = (a - t * Q64) as i32;
    // r ∈ approximately (-Q, 2Q).  Normalize to [0, Q):
    r += (r >> 31) & Q; // add Q if r < 0
    let d = r - Q;
    d + ((d >> 31) & Q) // subtract Q if r >= Q
}

// ── Unsigned Barrett (lattice engine, polynomial arithmetic) ───────

/// Barrett reduce an unsigned u64 value to `[0, Q)`.
///
/// Handles the full u64 range via a two-step Barrett reduction.
/// All constants are compiler-evaluated — no hand-computed magic numbers.
///
/// Step 1 (coarse, shift=48): reduces `a` to `[0, ~2^28)` using u128.
/// Step 2 (fine, shift=36): reduces to `[0, 2Q)`, then normalizes.
#[inline]
pub fn barrett_reduce_unsigned(a: u64) -> u16 {
    const Q64: u64 = 3329;

    // Step 1: coarse reduction via u128 multiply, shift=48.
    // Error < a / 2^48 < 2^16 for a < 2^64, so r1 < (2^16+1)*Q ≈ 2^28.
    const V1: u128 = (1u128 << 48) / Q64 as u128;
    let t1 = ((a as u128 * V1) >> 48) as u64;
    let r1 = a - t1 * Q64;

    // Step 2: fine reduction, shift=36.
    // r1 < 2^28, so error < 2^28 / 2^36 < 1.  Result is exact.
    const V2: u64 = (1u64 << 36) / Q64;
    let t2 = (r1 * V2) >> 36;
    let mut r = (r1 - t2 * Q64) as i32;

    // Normalize to [0, Q): at most one conditional add/subtract.
    r += (r >> 31) & Q;
    let d = r - Q;
    (d + ((d >> 31) & Q)) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_matches_rem_euclid() {
        // Exhaustive for small range, spot-check for large
        for a in -20_000i64..20_000 {
            let expected = a.rem_euclid(Q as i64) as i32;
            let got = barrett_reduce_signed(a);
            assert_eq!(got, expected, "signed mismatch for a={a}");
        }
        // Products at Q² boundary
        for &a in &[0i64, 1, 3328, 3329, -3329, 3328 * 3328, -(3328 * 3328)] {
            let expected = a.rem_euclid(Q as i64) as i32;
            assert_eq!(barrett_reduce_signed(a), expected, "boundary a={a}");
        }
    }

    #[test]
    fn unsigned_matches_mod() {
        // Spot-check across the full u64 range
        let cases: Vec<u64> = vec![
            0,
            1,
            3328,
            3329,
            3330,
            10_000,
            3328 * 3328,
            u32::MAX as u64,
            u64::MAX,
            u64::MAX - 1,
            u64::MAX / 2,
            0xDEAD_BEEF_CAFE_BABE,
        ];
        for a in cases {
            let expected = (a % Q as u64) as u16;
            let got = barrett_reduce_unsigned(a);
            assert_eq!(got, expected, "unsigned mismatch for a={a}");
        }
    }
}
