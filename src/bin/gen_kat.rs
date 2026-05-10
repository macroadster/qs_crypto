//! Known-Answer Test (KAT) Vector Generator
//!
//! Generates deterministic test vectors for all QS-Crypto primitives and
//! writes them to `tests/kat_vectors.json`. Any code change that alters
//! primitive output will cause the KAT test (`tests/kat.rs`) to fail,
//! providing automatic regression detection.
//!
//! Usage:
//!   cargo run --bin gen_kat

use serde::Serialize;
use std::fs;

use qs_crypto::core::sponge::SpinSponge;
use qs_crypto::params::{Params, SecurityLevel};
use qs_crypto::primitives::{aead, hash::spin_hash, kdf::spin_kdf};
use qs_crypto::{decapsulate, encapsulate, generate_keypair};

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ── Vector types ──────────────────────────────────────────────────

#[derive(Serialize)]
struct KatVectors {
    version: String,
    spin_hash: Vec<HashVector>,
    spin_kdf: Vec<KdfVector>,
    aead: Vec<AeadVector>,
    sponge: Vec<SpongeVector>,
    kem: Vec<KemVector>,
}

#[derive(Serialize)]
struct HashVector {
    description: String,
    input_hex: String,
    output_hex: String,
}

#[derive(Serialize)]
struct KdfVector {
    description: String,
    key_hex: String,
    salt_hex: String,
    info_ascii: String,
    length: usize,
    output_hex: String,
}

#[derive(Serialize)]
struct AeadVector {
    description: String,
    key_hex: String,
    nonce_hex: String,
    aad_hex: String,
    plaintext_hex: String,
    ciphertext_hex: String,
    tag_hex: String,
}

#[derive(Serialize)]
struct SpongeVector {
    description: String,
    input_hex: String,
    squeeze_len: usize,
    output_hex: String,
}

#[derive(Serialize)]
struct KemVector {
    description: String,
    level: String,
    pk_hex: String,
    sk_hex: String,
    ct_hex: String,
    ss_hex: String,
}

fn main() {
    println!("Generating KAT vectors for QS-Crypto v0.3...\n");

    let vectors = KatVectors {
        version: "0.3".to_string(),
        spin_hash: generate_hash_vectors(),
        spin_kdf: generate_kdf_vectors(),
        aead: generate_aead_vectors(),
        sponge: generate_sponge_vectors(),
        kem: generate_kem_vectors(),
    };

    let json = serde_json::to_string_pretty(&vectors).expect("JSON serialization failed");
    fs::write("tests/kat_vectors.json", &json).expect("failed to write KAT vectors");
    println!("Wrote tests/kat_vectors.json ({} bytes)", json.len());
}

fn generate_hash_vectors() -> Vec<HashVector> {
    println!("  spin_hash vectors...");
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty input", vec![]),
        ("single byte 0x00", vec![0x00]),
        ("ASCII 'abc'", b"abc".to_vec()),
        ("256 bytes (0x00..0xff)", (0..=255u8).collect()),
        (
            "1024 bytes (repeating pattern)",
            (0..1024).map(|i| (i % 256) as u8).collect(),
        ),
        (
            "ASCII 'The quick brown fox jumps over the lazy dog'",
            b"The quick brown fox jumps over the lazy dog".to_vec(),
        ),
    ];

    cases
        .into_iter()
        .map(|(desc, input)| {
            let output = spin_hash(&input);
            HashVector {
                description: desc.to_string(),
                input_hex: to_hex(&input),
                output_hex: to_hex(&output),
            }
        })
        .collect()
}

fn generate_kdf_vectors() -> Vec<KdfVector> {
    println!("  spin_kdf vectors...");
    let cases: Vec<(&str, Vec<u8>, Vec<u8>, &str, usize)> = vec![
        (
            "minimal key, empty salt/info, 32 bytes",
            vec![0x42; 32],
            vec![],
            "",
            32,
        ),
        (
            "32-byte key, 16-byte salt, info='test', 32 bytes",
            vec![0x01; 32],
            vec![0x02; 16],
            "test",
            32,
        ),
        (
            "key=0xff*32, salt=0xaa*32, info='expand', 64 bytes",
            vec![0xff; 32],
            vec![0xaa; 32],
            "expand",
            64,
        ),
        (
            "short key, long info, 48 bytes",
            vec![0x10; 16],
            vec![0x20; 8],
            "a]longer-info-string-for-kdf-testing",
            48,
        ),
        (
            "all-zero key/salt, info='zero', 128 bytes",
            vec![0x00; 32],
            vec![0x00; 32],
            "zero",
            128,
        ),
    ];

    cases
        .into_iter()
        .map(|(desc, key, salt, info, length)| {
            let output = spin_kdf(&key, &salt, info.as_bytes(), length);
            KdfVector {
                description: desc.to_string(),
                key_hex: to_hex(&key),
                salt_hex: to_hex(&salt),
                info_ascii: info.to_string(),
                length,
                output_hex: to_hex(&output),
            }
        })
        .collect()
}

fn generate_aead_vectors() -> Vec<AeadVector> {
    println!("  aead vectors...");
    let cases: Vec<(&str, [u8; 32], [u8; 16], Vec<u8>, Vec<u8>)> = vec![
        (
            "empty plaintext, empty aad",
            [0x42; 32],
            [0x01; 16],
            vec![],
            vec![],
        ),
        (
            "single byte plaintext",
            [0x42; 32],
            [0x01; 16],
            b"aad".to_vec(),
            vec![0xff],
        ),
        (
            "16-byte plaintext (one block)",
            [0x42; 32],
            [0x02; 16],
            b"associated-data".to_vec(),
            b"sixteen bytes!!".to_vec(),
        ),
        (
            "multi-block plaintext (64 bytes)",
            [0xaa; 32],
            [0xbb; 16],
            vec![],
            (0..64).collect(),
        ),
        (
            "large aad (256 bytes), small plaintext",
            [0x01; 32],
            [0x02; 16],
            (0..=255u8).collect(),
            b"secret".to_vec(),
        ),
    ];

    cases
        .into_iter()
        .map(|(desc, key, nonce, aad, plaintext)| {
            let result = aead::encrypt(&key, &nonce, &aad, &plaintext);
            AeadVector {
                description: desc.to_string(),
                key_hex: to_hex(&key),
                nonce_hex: to_hex(&nonce),
                aad_hex: to_hex(&aad),
                plaintext_hex: to_hex(&plaintext),
                ciphertext_hex: to_hex(&result.ciphertext),
                tag_hex: to_hex(&result.tag),
            }
        })
        .collect()
}

fn generate_sponge_vectors() -> Vec<SpongeVector> {
    println!("  sponge vectors...");
    let params = Params::default();

    let cases: Vec<(&str, Vec<u8>, usize)> = vec![
        ("empty absorb, squeeze 32", vec![], 32),
        ("absorb 'abc', squeeze 32", b"abc".to_vec(), 32),
        ("absorb 64 bytes, squeeze 64", (0..64).collect(), 64),
        ("absorb 256 bytes, squeeze 32", (0..=255u8).collect(), 32),
    ];

    cases
        .into_iter()
        .map(|(desc, input, squeeze_len)| {
            let mut sponge = SpinSponge::new(&params);
            sponge.absorb(&input);
            let output = sponge.squeeze_raw(squeeze_len);
            SpongeVector {
                description: desc.to_string(),
                input_hex: to_hex(&input),
                squeeze_len,
                output_hex: to_hex(&output),
            }
        })
        .collect()
}

fn generate_kem_vectors() -> Vec<KemVector> {
    println!("  kem vectors (all security levels)...");

    let levels = [
        (SecurityLevel::QS128, "QS128"),
        (SecurityLevel::QS192, "QS192"),
        (SecurityLevel::QS256, "QS256"),
    ];

    let mut vectors = Vec::new();

    for (level, level_name) in &levels {
        let params = Params::from_security_level(*level);

        // Generate 3 cases per level
        for case in 0..3 {
            let kp = generate_keypair(&params);
            let result = encapsulate(&kp.public_key);

            // Verify decaps works before storing
            let ss_dec = decapsulate(&kp.private_key, &result.ciphertext)
                .expect("decaps must succeed for KAT generation");
            assert_eq!(
                result.shared_secret.as_bytes(),
                ss_dec.as_bytes(),
                "decaps mismatch during KAT generation"
            );

            vectors.push(KemVector {
                description: format!("{} case {}", level_name, case),
                level: level_name.to_string(),
                pk_hex: to_hex(kp.public_key.as_bytes()),
                sk_hex: to_hex(kp.private_key.as_bytes()),
                ct_hex: to_hex(result.ciphertext.as_bytes()),
                ss_hex: to_hex(result.shared_secret.as_bytes()),
            });
        }
    }

    vectors
}
