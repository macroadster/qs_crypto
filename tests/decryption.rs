//! Integration tests — decryption (KEM decapsulation + session decrypt).

use qs_crypto::{decapsulate, encapsulate, generate_keypair, Params, SecurityLevel, Session};

// ── KEM roundtrip (pending Layer 2) ────────────────────────────────

#[test]
fn kem_roundtrip_same_shared_secret() {
    let keypair = generate_keypair(&Params::default());

    let result = encapsulate(&keypair.public_key);
    let decapsulated = decapsulate(&keypair.private_key, &result.ciphertext)
        .expect("decapsulation must succeed for a valid ciphertext");

    assert_eq!(
        result.shared_secret.as_bytes(),
        decapsulated.as_bytes(),
        "sender and receiver must derive the same shared secret"
    );
}

#[test]
fn kem_decapsulation_implicit_rejection() {
    let params = Params::default();
    let alice = generate_keypair(&params);
    let bob = generate_keypair(&params);

    // Encapsulate under Alice's public key.
    let result = encapsulate(&alice.public_key);

    // Attempt decapsulation with Bob's private key — wrong key.
    // FO implicit rejection: returns a *different* shared secret
    // rather than an error, so the adversary cannot distinguish.
    let wrong_secret = decapsulate(&bob.private_key, &result.ciphertext)
        .expect("implicit rejection should not return an error");

    assert_ne!(
        result.shared_secret.as_bytes(),
        wrong_secret.as_bytes(),
        "wrong private key must yield a different shared secret"
    );
}

// ── Session encrypt/decrypt roundtrip (pending Layer 3) ────────────

#[test]
fn session_encrypt_decrypt_roundtrip() {
    let params = Params::default();
    let alice_kp = generate_keypair(&params);
    let bob_kp = generate_keypair(&params);

    let alice_pk = alice_kp.public_key.clone();
    let bob_pk = bob_kp.public_key.clone();

    let session_key = [0x42u8; 32];
    let mut alice_session = Session::new(alice_kp, bob_pk, &session_key);
    let mut bob_session = Session::new(bob_kp, alice_pk, &session_key);

    let plaintext = b"Hello Bob, this is a secret message.";
    let ciphertext = alice_session.encrypt(plaintext);
    let decrypted = bob_session
        .decrypt(&ciphertext)
        .expect("decryption must succeed for a valid message");

    assert_eq!(
        &decrypted[..],
        &plaintext[..],
        "decrypted text must match original plaintext"
    );
}

#[test]
fn session_rejects_tampered_ciphertext() {
    let params = Params::default();
    let alice_kp = generate_keypair(&params);
    let bob_kp = generate_keypair(&params);

    let alice_pk = alice_kp.public_key.clone();
    let bob_pk = bob_kp.public_key.clone();

    let session_key = [0x42u8; 32];
    let mut alice_session = Session::new(alice_kp, bob_pk, &session_key);
    let mut bob_session = Session::new(bob_kp, alice_pk, &session_key);

    let mut ciphertext = alice_session.encrypt(b"authentic message");

    // Flip a byte in the ciphertext body.
    if let Some(byte) = ciphertext.last_mut() {
        *byte ^= 0xFF;
    }

    let result = bob_session.decrypt(&ciphertext);
    assert!(
        result.is_err(),
        "tampered ciphertext must be rejected by AEAD authentication"
    );
}

#[test]
fn session_forward_secrecy_unique_keys() {
    let params = Params::default();
    let alice_kp = generate_keypair(&params);
    let bob_kp = generate_keypair(&params);

    let alice_pk = alice_kp.public_key.clone();
    let bob_pk = bob_kp.public_key.clone();

    let session_key = [0x42u8; 32];
    let mut alice_session = Session::new(alice_kp, bob_pk, &session_key);
    let mut bob_session = Session::new(bob_kp, alice_pk, &session_key);

    // Exchange several messages in both directions.
    let ct1 = alice_session.encrypt(b"message 1");
    let _ = bob_session.decrypt(&ct1).unwrap();

    let ct2 = bob_session.encrypt(b"reply 1");
    let _ = alice_session.decrypt(&ct2).unwrap();

    let ct3 = alice_session.encrypt(b"message 2");
    let pt3 = bob_session.decrypt(&ct3).unwrap();

    assert_eq!(&pt3[..], b"message 2");
}

// ── PAKE full flow (pending Layer 3) ───────────────────────────────

#[test]
fn pake_full_handshake() {
    use qs_crypto::{pake_register, PakeClient, PakeServer};

    let params = Params::default();
    let keypair = generate_keypair(&params);
    let password = "correct horse battery staple";

    // Registration (one-time, over secure channel).
    let record = pake_register(password, &keypair);

    // Login (over insecure channel).
    let mut client = PakeClient::new(password);
    let mut server = PakeServer::new(record);

    let msg1 = client.start();
    let msg2 = server.respond(&msg1).unwrap();
    let client_key = client.finalize(&msg2).unwrap();
    let server_key = server.finalize().unwrap();

    assert_eq!(
        client_key, server_key,
        "client and server must derive the same session key"
    );
}

// ── KEM roundtrip at all security levels ───────────────────────────

#[test]
fn kem_roundtrip_qs128() {
    let params = Params::from_security_level(SecurityLevel::QS128);
    let keypair = generate_keypair(&params);
    let result = encapsulate(&keypair.public_key);
    let decapped = decapsulate(&keypair.private_key, &result.ciphertext).unwrap();
    assert_eq!(result.shared_secret.as_bytes(), decapped.as_bytes());
}

#[test]
fn kem_roundtrip_qs192() {
    let params = Params::from_security_level(SecurityLevel::QS192);
    let keypair = generate_keypair(&params);
    let result = encapsulate(&keypair.public_key);
    let decapped = decapsulate(&keypair.private_key, &result.ciphertext).unwrap();
    assert_eq!(result.shared_secret.as_bytes(), decapped.as_bytes());
}

// ── Session save/restore roundtrip ─────────────────────────────────

#[test]
fn session_save_restore_roundtrip() {
    let params = Params::default();
    let alice_kp = generate_keypair(&params);
    let bob_kp = generate_keypair(&params);

    let alice_pk = alice_kp.public_key.clone();
    let bob_pk = bob_kp.public_key.clone();

    let session_key = [0x42u8; 32];
    let mut alice_session = Session::new(alice_kp, bob_pk, &session_key);

    // Encrypt a message to advance the ratchet
    let ct1 = alice_session.encrypt(b"before save");

    // Save and restore
    let saved = alice_session.save();
    let mut restored = Session::restore(&saved).expect("restore must succeed");

    // Encrypt another message from the restored session
    let ct2 = restored.encrypt(b"after restore");

    // Both ciphertexts must be valid and different
    assert_ne!(ct1, ct2);
    assert!(!ct2.is_empty());

    // Bob should be able to decrypt both
    let mut bob_session = Session::new(bob_kp, alice_pk, &session_key);
    let pt1 = bob_session.decrypt(&ct1).unwrap();
    assert_eq!(&pt1[..], b"before save");
    let pt2 = bob_session.decrypt(&ct2).unwrap();
    assert_eq!(&pt2[..], b"after restore");
}

#[test]
fn session_save_restore_with_photos() {
    let params = Params::default();
    let alice_kp = generate_keypair(&params);
    let bob_kp = generate_keypair(&params);
    let bob_pk = bob_kp.public_key.clone();

    let session_key = [0x42u8; 32];
    let mut session = Session::new(alice_kp, bob_pk, &session_key);
    session.set_identity_photos(
        qs_crypto::IdentityPhoto::new(vec![0xAA; 64]),
        qs_crypto::IdentityPhoto::new(vec![0xBB; 64]),
    );

    let saved = session.save();
    let restored = Session::restore(&saved).expect("restore must succeed");

    // Identity fingerprint should work on restored session
    let fp = restored.identity_fingerprint(32, 32).unwrap();
    assert_eq!(fp.len(), 32 * 32 * 4);
}

#[test]
fn session_restore_rejects_invalid_data() {
    assert!(Session::restore(&[]).is_err());
    assert!(Session::restore(&[0x00]).is_err()); // wrong version
    assert!(Session::restore(&[0x01, 0x00]).is_err()); // truncated
}

// ── PAKE wrong password ────────────────────────────────────────────

#[test]
fn pake_wrong_password_fails() {
    use qs_crypto::{pake_register, PakeClient, PakeServer};

    let params = Params::default();
    let keypair = generate_keypair(&params);
    let record = pake_register("correct-password", &keypair);

    let mut client = PakeClient::new("wrong-password");
    let mut server = PakeServer::new(record);

    let msg1 = client.start();
    let msg2 = server.respond(&msg1).unwrap();

    // Client finalize should fail because the envelope can't be decrypted
    let result = client.finalize(&msg2);
    assert!(result.is_err(), "wrong password must fail during finalize");
}

// ── Multiple sequential messages ───────────────────────────────────

#[test]
fn session_many_messages_roundtrip() {
    let params = Params::default();
    let alice_kp = generate_keypair(&params);
    let bob_kp = generate_keypair(&params);
    let alice_pk = alice_kp.public_key.clone();
    let bob_pk = bob_kp.public_key.clone();

    let session_key = [0x99u8; 32];
    let mut alice = Session::new(alice_kp, bob_pk, &session_key);
    let mut bob = Session::new(bob_kp, alice_pk, &session_key);

    for i in 0..10 {
        let msg = format!("message number {i}");
        let ct = alice.encrypt(msg.as_bytes());
        let pt = bob.decrypt(&ct).unwrap();
        assert_eq!(&pt[..], msg.as_bytes());
    }
}

// ── Empty plaintext ────────────────────────────────────────────────

#[test]
fn session_empty_plaintext_roundtrip() {
    let params = Params::default();
    let alice_kp = generate_keypair(&params);
    let bob_kp = generate_keypair(&params);
    let alice_pk = alice_kp.public_key.clone();
    let bob_pk = bob_kp.public_key.clone();

    let session_key = [0x42u8; 32];
    let mut alice = Session::new(alice_kp, bob_pk, &session_key);
    let mut bob = Session::new(bob_kp, alice_pk, &session_key);

    let ct = alice.encrypt(b"");
    let pt = bob.decrypt(&ct).unwrap();
    assert!(pt.is_empty());
}

// ── Large plaintext ────────────────────────────────────────────────

#[test]
fn session_large_plaintext_roundtrip() {
    let params = Params::default();
    let alice_kp = generate_keypair(&params);
    let bob_kp = generate_keypair(&params);
    let alice_pk = alice_kp.public_key.clone();
    let bob_pk = bob_kp.public_key.clone();

    let session_key = [0x42u8; 32];
    let mut alice = Session::new(alice_kp, bob_pk, &session_key);
    let mut bob = Session::new(bob_kp, alice_pk, &session_key);

    // Multi-block message (AEAD block size is 32 bytes)
    let plaintext = vec![0xABu8; 1024];
    let ct = alice.encrypt(&plaintext);
    let pt = bob.decrypt(&ct).unwrap();
    assert_eq!(pt, plaintext);
}
