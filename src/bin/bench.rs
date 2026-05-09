//! Simple performance benchmark for QS-Crypto
//!
//! Run with: cargo run --bin bench --release

use std::time::{Duration, Instant};

use qs_crypto::aead;
use qs_crypto::core::sponge::SpinSponge;
use qs_crypto::params::Params;
use qs_crypto::primitives::hash::spin_hash;
use qs_crypto::primitives::prng::SpinPrng;
use qs_crypto::{decapsulate, encapsulate, generate_keypair, hybrid, SecurityLevel};

fn time<F: FnMut()>(name: &str, mut f: F, iters: usize) -> Duration {
    let start = Instant::now();
    for _ in 0..iters {
        f();
    }
    let elapsed = start.elapsed();
    let per_op = elapsed / iters as u32;
    println!("{name:30} {:>8.2?} / op   ({iters} iters)", per_op);
    elapsed
}

fn main() {
    println!("QS-Crypto Performance Benchmark (release mode recommended)\n");

    let params = Params::from_security_level(SecurityLevel::QS256);

    // Keygen
    let _ = time(
        "Keygen (QS256)",
        || {
            let _ = generate_keypair(&params);
        },
        200,
    );

    let kp = generate_keypair(&params);

    // Encaps / Decaps
    let _ = time(
        "Encapsulate",
        || {
            let _ = encapsulate(&kp.public_key);
        },
        500,
    );

    let res = encapsulate(&kp.public_key);
    let _ = time(
        "Decapsulate",
        || {
            let _ = decapsulate(&kp.private_key, &res.ciphertext).unwrap();
        },
        500,
    );

    // Hybrid
    let hkp = hybrid::hybrid_generate_keypair(&params);
    let hpk = hkp.public_key();
    let _ = time(
        "Hybrid Encaps (Spin+X25519)",
        || {
            let _ = hybrid::hybrid_encapsulate(&hpk);
        },
        300,
    );

    let (hct, _) = hybrid::hybrid_encapsulate(&hpk);
    let hsk = hkp.private_key();
    let _ = time(
        "Hybrid Decaps",
        || {
            let _ = hybrid::hybrid_decapsulate(&hsk, &hct).unwrap();
        },
        300,
    );

    // Symmetric
    let key = [42u8; 32];
    let nonce = [7u8; 16];
    let aad = b"benchmark";
    let pt = vec![0x55u8; 1024];

    let _ = time(
        "SpinHash (32B)",
        || {
            let _ = spin_hash(b"benchmark input");
        },
        50_000,
    );

    let mut prng = SpinPrng::new(b"bench");
    let _ = time(
        "SpinPrng (1KB)",
        || {
            let _ = prng.next_bytes(1024);
        },
        5_000,
    );

    let ct = aead::encrypt(&key, &nonce, aad, &pt);
    let _ = time(
        "SpinAEAD encrypt (1KB)",
        || {
            let _ = aead::encrypt(&key, &nonce, aad, &pt);
        },
        2_000,
    );

    let _ = time(
        "SpinAEAD decrypt (1KB)",
        || {
            let _ = aead::decrypt(&key, &nonce, aad, &ct.ciphertext, &ct.tag).unwrap();
        },
        2_000,
    );

    // Sponge permutation cost
    let mut sponge = SpinSponge::new(&params);
    let _ = time(
        "1x Permute (32 rounds)",
        || {
            sponge.permute();
        },
        10_000,
    );

    println!("\nNote: These are rough micro-benchmarks. Real performance depends on CPU.");
}
