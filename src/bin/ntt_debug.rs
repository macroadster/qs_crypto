// Quick NTT debug — run from project root
use qs_crypto::kem::Poly;

fn main() {
    // Test 1: NTT roundtrip (ntt then inv_ntt should be identity)
    // We can't call ntt/inv_ntt directly since they're not pub from outside,
    // but we can test via poly_mul: multiply by 1 and check result
    let n = 256;
    let mut one_coeffs = vec![0u16; n];
    one_coeffs[0] = 1; // polynomial "1"
    let one = Poly {
        coeffs: one_coeffs,
        n,
    };

    // Random-ish polynomial
    let mut a_coeffs = vec![0u16; n];
    for (i, coeff) in a_coeffs.iter_mut().enumerate().take(n) {
        *coeff = (i as u16 * 17 + 42) % 3329;
    }
    let a = Poly {
        coeffs: a_coeffs.clone(),
        n,
    };

    // a * 1 should equal a
    let result = qs_crypto::kem::poly_mul(&a, &one);

    let mut mismatches = 0;
    for (i, orig) in a_coeffs.iter().enumerate().take(n) {
        if result.coeffs[i] != *orig {
            if mismatches < 10 {
                println!(
                    "MISMATCH at [{}]: got {} expected {}",
                    i, result.coeffs[i], orig
                );
            }
            mismatches += 1;
        }
    }
    if mismatches == 0 {
        println!("Test 1 (a * 1 = a): PASS");
    } else {
        println!("Test 1 (a * 1 = a): FAIL ({} mismatches)", mismatches);
    }

    // Test 2: NTT mul vs schoolbook on small values
    let mut b_coeffs = vec![0u16; n];
    for (i, coeff) in b_coeffs.iter_mut().enumerate().take(n) {
        *coeff = (i as u16 * 7 + 13) % 3329;
    }
    let b = Poly {
        coeffs: b_coeffs,
        n,
    };

    let ntt_result = qs_crypto::kem::poly_mul(&a, &b);
    let sb_result = qs_crypto::kem::schoolbook_poly_mul(&a, &b);

    let mut mismatches = 0;
    for i in 0..n {
        if ntt_result.coeffs[i] != sb_result.coeffs[i] {
            if mismatches < 10 {
                println!(
                    "DIFF at [{}]: ntt={} schoolbook={}",
                    i, ntt_result.coeffs[i], sb_result.coeffs[i]
                );
            }
            mismatches += 1;
        }
    }
    if mismatches == 0 {
        println!("Test 2 (NTT vs schoolbook): PASS");
    } else {
        println!(
            "Test 2 (NTT vs schoolbook): FAIL ({} mismatches)",
            mismatches
        );
    }
}
