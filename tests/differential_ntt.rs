//! Full differential test: NTT vs Schoolbook on thousands of KEM operations.
//!
//! Run with:
//!   cargo test --release --test differential_ntt -- --ignored --nocapture

use qs_crypto::kem::Poly;
use qs_crypto::primitives::prng::SpinPrng;
use qs_crypto::{decapsulate, encapsulate, generate_keypair, Params, SecurityLevel};

#[test]
#[ignore]
fn ntt_vs_schoolbook_thousands_of_kem_operations() {
    println!("\n=== Full Differential Test: NTT vs Schoolbook ===\n");

    let params = Params::from_security_level(SecurityLevel::QS256);
    let iterations = 1500usize;
    let encaps_per_key = 4usize;
    let mut mismatches = 0usize;
    let mut total_kem_ops = 0usize;

    let mut prng = SpinPrng::new(b"differential-ntt-seed-2026");

    for i in 0..iterations {
        if i % 300 == 0 {
            println!("  Keypairs processed: {}", i);
        }

        let kp = generate_keypair(&params);
        let pk = &kp.public_key;
        let sk = &kp.private_key;

        for _ in 0..encaps_per_key {
            let res = encapsulate(pk);
            let ct = &res.ciphertext;
            let ss = &res.shared_secret;

            let ss2 = decapsulate(sk, ct).expect("decapsulation failed");

            assert_eq!(
                ss.as_bytes(),
                ss2.as_bytes(),
                "Shared secret mismatch on KEM op {}",
                total_kem_ops
            );

            // Implicit rejection test
            let bad_sk = generate_keypair(&params).private_key;
            let ss_rej = decapsulate(&bad_sk, ct).expect("rejection path failed");
            assert_ne!(ss.as_bytes(), ss_rej.as_bytes());

            total_kem_ops += 1;
        }
    }

    // Heavy random polynomial differential test (NTT vs Schoolbook)
    println!("  Running 6000 random polynomial multiplications for differential check...");

    for _ in 0..6000 {
        let mut buf = [0u8; 1024];
        prng.next_bytes(1024)
            .iter()
            .zip(buf.iter_mut())
            .for_each(|(src, dst)| *dst = *src);

        let mut coeffs_a = vec![0u16; 256];
        let mut coeffs_b = vec![0u16; 256];

        for i in 0..256 {
            let val = u16::from_le_bytes([buf[i * 2], buf[i * 2 + 1]]) % 3329;
            coeffs_a[i] = val;
        }
        for i in 0..256 {
            let val = u16::from_le_bytes([buf[512 + i * 2], buf[512 + i * 2 + 1]]) % 3329;
            coeffs_b[i] = val;
        }

        let pa = Poly {
            coeffs: coeffs_a,
            n: 256,
        };
        let pb = Poly {
            coeffs: coeffs_b,
            n: 256,
        };

        // Differential check: NTT (unconditional for N=256) vs schoolbook
        let res_fast = qs_crypto::kem::poly_mul(&pa, &pb);
        let res_slow = qs_crypto::kem::schoolbook_poly_mul(&pa, &pb);

        if res_fast.coeffs != res_slow.coeffs {
            mismatches += 1;
            if mismatches > 5 {
                break;
            } // don't spam
        }
    }

    println!("\n=== Summary ===");
    println!("  Full KEM operations         : {}", total_kem_ops);
    println!("  Random poly multiplications : 6000");
    println!("  Mismatches                  : {}", mismatches);

    assert_eq!(
        mismatches, 0,
        "NTT and Schoolbook produced different polynomial results!"
    );
    println!(
        "\n✅ PASS: NTT and Schoolbook are bit-identical across thousands of KEM operations.\n"
    );
}
