//! Integration tests — encryption (KEM encapsulation + session encrypt)
//! and identity-bound visual fingerprints.

use qs_crypto::{
    encapsulate, generate_keypair, identity_fingerprint, photo_hash, visual_fingerprint,
    Ciphertext, IdentityPhoto, Params, Session,
};

// ── Ciphertext type construction (runs now) ────────────────────────

#[test]
fn ciphertext_roundtrip_from_bytes() {
    let raw = vec![0xAA; 64];
    let ct = Ciphertext::from_bytes(&raw).unwrap();
    assert_eq!(ct.as_bytes(), &raw[..]);
    assert_eq!(ct.to_bytes(), raw);
}

#[test]
fn empty_ciphertext_rejected() {
    assert!(Ciphertext::from_bytes(&[]).is_err());
}

// ── KEM encapsulation (pending Layer 2) ────────────────────────────

#[test]
#[ignore = "pending: Layer 2 KEM implementation"]
fn kem_encapsulation_produces_valid_output() {
    let keypair = generate_keypair(&Params::default());
    let result = encapsulate(&keypair.public_key);

    assert!(
        !result.ciphertext.as_bytes().is_empty(),
        "ciphertext must not be empty"
    );
    assert_eq!(
        result.shared_secret.as_bytes().len(),
        32,
        "shared secret must be 256 bits"
    );
}

#[test]
#[ignore = "pending: Layer 2 KEM implementation"]
fn kem_encapsulation_is_nondeterministic() {
    let keypair = generate_keypair(&Params::default());

    let r1 = encapsulate(&keypair.public_key);
    let r2 = encapsulate(&keypair.public_key);

    assert_ne!(
        r1.ciphertext.as_bytes(),
        r2.ciphertext.as_bytes(),
        "two encapsulations must produce different ciphertexts"
    );
    assert_ne!(
        r1.shared_secret.as_bytes(),
        r2.shared_secret.as_bytes(),
        "two encapsulations must produce different shared secrets"
    );
}

// ── Session encryption (pending Layer 3) ───────────────────────────

#[test]
#[ignore = "pending: Layer 3 protocol implementation"]
fn session_encrypt_produces_ciphertext() {
    let params = Params::default();
    let alice_kp = generate_keypair(&params);
    let bob_kp = generate_keypair(&params);
    let bob_pk = bob_kp.public_key.clone();

    let session_key = [0x42u8; 32];
    let mut session = Session::new(alice_kp, bob_pk, &session_key);

    let plaintext = b"attack at dawn";
    let ciphertext = session.encrypt(plaintext);

    assert!(
        !ciphertext.is_empty(),
        "ciphertext must not be empty"
    );
    assert_ne!(
        &ciphertext[..],
        &plaintext[..],
        "ciphertext must differ from plaintext"
    );
}

#[test]
#[ignore = "pending: Layer 3 protocol implementation"]
fn session_encrypt_unique_per_message() {
    let params = Params::default();
    let alice_kp = generate_keypair(&params);
    let bob_kp = generate_keypair(&params);
    let bob_pk = bob_kp.public_key.clone();

    let session_key = [0x42u8; 32];
    let mut session = Session::new(alice_kp, bob_pk, &session_key);

    // Same plaintext encrypted twice must produce different ciphertexts
    // because the symmetric ratchet advances after each message.
    let ct1 = session.encrypt(b"hello");
    let ct2 = session.encrypt(b"hello");

    assert_ne!(ct1, ct2, "ratchet must produce unique ciphertexts for identical plaintext");
}

// ── Identity photo type construction (runs now) ────────────────────

#[test]
fn identity_photo_roundtrip() {
    let raw = vec![0xFF; 128];
    let photo = IdentityPhoto::new(raw.clone());
    assert_eq!(photo.as_bytes(), &raw[..]);
}

// ── Visual fingerprints (pending visual implementation) ────────────

#[test]
#[ignore = "pending: visual layer implementation"]
fn plain_fingerprint_deterministic() {
    let key = [0x42u8; 32];
    let fp1 = visual_fingerprint(&key, 64, 64);
    let fp2 = visual_fingerprint(&key, 64, 64);
    assert_eq!(fp1, fp2, "same key must produce identical fingerprints");
}

#[test]
#[ignore = "pending: visual layer implementation"]
fn plain_fingerprint_sensitive_to_key() {
    let key_a = [0x42u8; 32];
    let mut key_b = key_a;
    key_b[0] ^= 0x01; // flip one bit

    let fp_a = visual_fingerprint(&key_a, 64, 64);
    let fp_b = visual_fingerprint(&key_b, 64, 64);
    assert_ne!(fp_a, fp_b, "one-bit key change must produce a different fingerprint");
}

#[test]
#[ignore = "pending: visual layer implementation"]
fn identity_fingerprint_deterministic() {
    let key = [0x42u8; 32];
    let alice_photo = IdentityPhoto::new(vec![0xAA; 256]);
    let bob_photo = IdentityPhoto::new(vec![0xBB; 256]);

    let fp1 = identity_fingerprint(&key, &alice_photo, &bob_photo, 64, 64);
    let fp2 = identity_fingerprint(&key, &alice_photo, &bob_photo, 64, 64);
    assert_eq!(fp1, fp2, "same inputs must produce identical identity fingerprints");
}

#[test]
#[ignore = "pending: visual layer implementation"]
fn identity_fingerprint_sensitive_to_key() {
    let key_a = [0x42u8; 32];
    let mut key_b = key_a;
    key_b[0] ^= 0x01;

    let alice_photo = IdentityPhoto::new(vec![0xAA; 256]);
    let bob_photo = IdentityPhoto::new(vec![0xBB; 256]);

    let fp_a = identity_fingerprint(&key_a, &alice_photo, &bob_photo, 64, 64);
    let fp_b = identity_fingerprint(&key_b, &alice_photo, &bob_photo, 64, 64);
    assert_ne!(fp_a, fp_b, "different session key must produce different identity fingerprint");
}

#[test]
#[ignore = "pending: visual layer implementation"]
fn identity_fingerprint_sensitive_to_photo() {
    let key = [0x42u8; 32];
    let alice_photo = IdentityPhoto::new(vec![0xAA; 256]);
    let bob_photo_1 = IdentityPhoto::new(vec![0xBB; 256]);
    let bob_photo_2 = IdentityPhoto::new(vec![0xCC; 256]); // different photo

    let fp1 = identity_fingerprint(&key, &alice_photo, &bob_photo_1, 64, 64);
    let fp2 = identity_fingerprint(&key, &alice_photo, &bob_photo_2, 64, 64);
    assert_ne!(fp1, fp2, "different peer photo must produce different fingerprint");
}

#[test]
#[ignore = "pending: visual layer implementation"]
fn identity_fingerprint_differs_from_plain() {
    let key = [0x42u8; 32];
    let alice_photo = IdentityPhoto::new(vec![0xAA; 256]);
    let bob_photo = IdentityPhoto::new(vec![0xBB; 256]);

    let plain = visual_fingerprint(&key, 64, 64);
    let identity = identity_fingerprint(&key, &alice_photo, &bob_photo, 64, 64);
    assert_ne!(plain, identity, "identity fingerprint must differ from plain fingerprint");
}

#[test]
#[ignore = "pending: visual layer implementation"]
fn photo_hash_deterministic() {
    let photo = IdentityPhoto::new(vec![0xAA; 256]);
    let h1 = photo_hash(&photo);
    let h2 = photo_hash(&photo);
    assert_eq!(h1, h2, "same photo must produce identical hash");
}

#[test]
#[ignore = "pending: visual layer implementation"]
fn photo_hash_differs_for_different_photos() {
    let p1 = IdentityPhoto::new(vec![0xAA; 256]);
    let p2 = IdentityPhoto::new(vec![0xBB; 256]);
    assert_ne!(photo_hash(&p1), photo_hash(&p2));
}

// ── Session identity fingerprint (pending Layer 3 + visual) ────────

#[test]
#[ignore = "pending: Layer 3 + visual implementation"]
fn session_identity_fingerprint_requires_photos() {
    let params = Params::default();
    let alice_kp = generate_keypair(&params);
    let bob_kp = generate_keypair(&params);
    let bob_pk = bob_kp.public_key.clone();

    let session_key = [0x42u8; 32];
    let session = Session::new(alice_kp, bob_pk, &session_key);

    // Must fail if photos haven't been set.
    let result = session.identity_fingerprint(64, 64);
    assert!(result.is_err(), "identity fingerprint must fail without photos");
}

#[test]
#[ignore = "pending: Layer 3 + visual implementation"]
fn session_identity_fingerprint_with_photos() {
    let params = Params::default();
    let alice_kp = generate_keypair(&params);
    let bob_kp = generate_keypair(&params);
    let bob_pk = bob_kp.public_key.clone();

    let session_key = [0x42u8; 32];
    let mut session = Session::new(alice_kp, bob_pk, &session_key);

    session.set_identity_photos(
        IdentityPhoto::new(vec![0xAA; 256]),
        IdentityPhoto::new(vec![0xBB; 256]),
    );

    let fp = session.identity_fingerprint(64, 64).unwrap();
    assert_eq!(
        fp.len(),
        64 * 64 * 4,
        "RGBA output must be width × height × 4 bytes"
    );
}