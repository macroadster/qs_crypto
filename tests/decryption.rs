//! Integration tests — decryption (KEM decapsulation + session decrypt).

use qs_crypto::{decapsulate, encapsulate, generate_keypair, Params, Session};

// ── KEM roundtrip (pending Layer 2) ────────────────────────────────

#[test]
#[ignore = "pending: Layer 2 KEM implementation"]
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
#[ignore = "pending: Layer 2 KEM implementation"]
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
#[ignore = "pending: Layer 3 protocol implementation"]
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
#[ignore = "pending: Layer 3 protocol implementation"]
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
#[ignore = "pending: Layer 3 protocol implementation"]
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
#[ignore = "pending: Layer 3 protocol implementation"]
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