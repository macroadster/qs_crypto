//! Property-based tests for cryptographic primitives.
//!
//! These tests use `proptest` to verify algebraic invariants that must
//! hold for *all* inputs, not just the handful covered by unit tests.

use proptest::prelude::*;
use qs_crypto::*;

// ── AEAD roundtrip ─────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn aead_roundtrip(
        key in prop::array::uniform32(any::<u8>()),
        nonce in prop::array::uniform16(any::<u8>()),
        aad in prop::collection::vec(any::<u8>(), 0..512),
        plaintext in prop::collection::vec(any::<u8>(), 0..1024),
    ) {
        let ct = aead::encrypt(&key, &nonce, &aad, &plaintext);
        let pt = aead::decrypt(&key, &nonce, &aad, &ct.ciphertext, &ct.tag)
            .expect("decryption must succeed for matching parameters");
        prop_assert_eq!(pt, plaintext);
    }

    #[test]
    fn aead_siv_roundtrip(
        key in prop::array::uniform32(any::<u8>()),
        nonce in prop::array::uniform16(any::<u8>()),
        aad in prop::collection::vec(any::<u8>(), 0..512),
        plaintext in prop::collection::vec(any::<u8>(), 0..1024),
    ) {
        let ct = aead::encrypt_siv(&key, &nonce, &aad, &plaintext);
        let pt = aead::decrypt_siv(&key, &nonce, &aad, &ct.siv, &ct.ciphertext, &ct.tag)
            .expect("SIV decryption must succeed for matching parameters");
        prop_assert_eq!(pt, plaintext);
    }

    #[test]
    fn aead_tampered_ciphertext_fails(
        key in prop::array::uniform32(any::<u8>()),
        nonce in prop::array::uniform16(any::<u8>()),
        plaintext in prop::collection::vec(any::<u8>(), 1..256),
        flip_pos in any::<prop::sample::Index>(),
    ) {
        let ct = aead::encrypt(&key, &nonce, b"aad", &plaintext);
        let mut bad_ct = ct.ciphertext.clone();
        let idx = flip_pos.index(bad_ct.len());
        bad_ct[idx] ^= 0x01;
        let result = aead::decrypt(&key, &nonce, b"aad", &bad_ct, &ct.tag);
        prop_assert!(result.is_err(), "tampered ciphertext must fail authentication");
    }

    #[test]
    fn aead_tampered_tag_fails(
        key in prop::array::uniform32(any::<u8>()),
        nonce in prop::array::uniform16(any::<u8>()),
        plaintext in prop::collection::vec(any::<u8>(), 0..256),
        flip_pos in 0..16usize,
    ) {
        let ct = aead::encrypt(&key, &nonce, b"", &plaintext);
        let mut bad_tag = ct.tag;
        bad_tag[flip_pos] ^= 0xFF;
        let result = aead::decrypt(&key, &nonce, b"", &ct.ciphertext, &bad_tag);
        prop_assert!(result.is_err(), "tampered tag must fail authentication");
    }
}

// ── KEM roundtrip ──────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn kem_roundtrip(level in prop::sample::select(vec![
        SecurityLevel::QS128,
        SecurityLevel::QS192,
        SecurityLevel::QS256,
    ])) {
        let params = Params::from_security_level(level);
        let kp = generate_keypair(&params);
        let result = encapsulate(&kp.public_key);
        let ss = decapsulate(&kp.private_key, &result.ciphertext)
            .expect("decapsulation must succeed for matching key/ct");
        prop_assert_eq!(result.shared_secret.as_bytes(), ss.as_bytes());
    }

    #[test]
    fn hybrid_kem_roundtrip(_ in 0..10u32) {
        let kp = hybrid_generate_keypair(&Params::default());
        let (ct, ss) = hybrid_encapsulate(&kp.public_key());
        let ss2 = hybrid_decapsulate(&kp.private_key(), &ct)
            .expect("hybrid decapsulation must succeed");
        prop_assert_eq!(ss.as_bytes(), ss2.as_bytes());
    }
}

// ── Session roundtrip ──────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn session_roundtrip(
        messages in prop::collection::vec(
            prop::collection::vec(any::<u8>(), 0..512),
            1..8,
        ),
    ) {
        let params = Params::default();
        let alice_kp = generate_keypair(&params);
        let bob_kp = generate_keypair(&params);
        let alice_pk = alice_kp.public_key.clone();
        let bob_pk = bob_kp.public_key.clone();
        let session_key = [0x42u8; 32];

        let mut alice = Session::new(alice_kp, bob_pk, &session_key);
        let mut bob = Session::new(bob_kp, alice_pk, &session_key);

        for msg in &messages {
            let ct = alice.encrypt(msg);
            let pt = bob.decrypt(&ct).expect("session decrypt must succeed");
            prop_assert_eq!(&pt, msg);
        }
    }

    #[test]
    fn session_tampered_message_fails(
        plaintext in prop::collection::vec(any::<u8>(), 1..256),
        flip_pos in any::<prop::sample::Index>(),
    ) {
        let params = Params::default();
        let alice_kp = generate_keypair(&params);
        let bob_kp = generate_keypair(&params);
        let alice_pk = alice_kp.public_key.clone();
        let bob_pk = bob_kp.public_key.clone();
        let session_key = [0x42u8; 32];

        let mut alice = Session::new(alice_kp, bob_pk, &session_key);
        let mut bob = Session::new(bob_kp, alice_pk, &session_key);

        let mut ct = alice.encrypt(&plaintext);
        // Flip a byte in the ciphertext body (skip the fixed header)
        let body_start = 1 + 8 + 12; // direction + msg_number + siv
        if ct.len() > body_start {
            let idx = body_start + flip_pos.index(ct.len() - body_start);
            ct[idx] ^= 0x01;
            let result = bob.decrypt(&ct);
            prop_assert!(result.is_err(), "tampered session message must fail");
        }
    }
}
