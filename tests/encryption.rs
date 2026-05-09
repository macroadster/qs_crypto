//! Integration tests — encryption (KEM encapsulation + session encrypt)
//! and identity-bound visual fingerprints.

use qs_crypto::{
    aead, encapsulate, generate_keypair, identity_fingerprint, photo_hash, spin_hash, spin_kdf,
    visual_fingerprint, Ciphertext, IdentityPhoto, Params, Session, SpinLattice, SpinPrng,
    SpinSponge,
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
fn session_encrypt_produces_ciphertext() {
    let params = Params::default();
    let alice_kp = generate_keypair(&params);
    let bob_kp = generate_keypair(&params);
    let bob_pk = bob_kp.public_key.clone();

    let session_key = [0x42u8; 32];
    let mut session = Session::new(alice_kp, bob_pk, &session_key);

    let plaintext = b"attack at dawn";
    let ciphertext = session.encrypt(plaintext);

    assert!(!ciphertext.is_empty(), "ciphertext must not be empty");
    assert_ne!(
        &ciphertext[..],
        &plaintext[..],
        "ciphertext must differ from plaintext"
    );
}

#[test]
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

    assert_ne!(
        ct1, ct2,
        "ratchet must produce unique ciphertexts for identical plaintext"
    );
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
fn plain_fingerprint_deterministic() {
    let key = [0x42u8; 32];
    let fp1 = visual_fingerprint(&key, 64, 64);
    let fp2 = visual_fingerprint(&key, 64, 64);
    assert_eq!(fp1, fp2, "same key must produce identical fingerprints");
}

#[test]
fn plain_fingerprint_sensitive_to_key() {
    let key_a = [0x42u8; 32];
    let mut key_b = key_a;
    key_b[0] ^= 0x01; // flip one bit

    let fp_a = visual_fingerprint(&key_a, 64, 64);
    let fp_b = visual_fingerprint(&key_b, 64, 64);
    assert_ne!(
        fp_a, fp_b,
        "one-bit key change must produce a different fingerprint"
    );
}

#[test]
fn identity_fingerprint_deterministic() {
    let key = [0x42u8; 32];
    let alice_photo = IdentityPhoto::new(vec![0xAA; 256]);
    let bob_photo = IdentityPhoto::new(vec![0xBB; 256]);

    let fp1 = identity_fingerprint(&key, &alice_photo, &bob_photo, 64, 64);
    let fp2 = identity_fingerprint(&key, &alice_photo, &bob_photo, 64, 64);
    assert_eq!(
        fp1, fp2,
        "same inputs must produce identical identity fingerprints"
    );
}

#[test]
fn identity_fingerprint_sensitive_to_key() {
    let key_a = [0x42u8; 32];
    let mut key_b = key_a;
    key_b[0] ^= 0x01;

    let alice_photo = IdentityPhoto::new(vec![0xAA; 256]);
    let bob_photo = IdentityPhoto::new(vec![0xBB; 256]);

    let fp_a = identity_fingerprint(&key_a, &alice_photo, &bob_photo, 64, 64);
    let fp_b = identity_fingerprint(&key_b, &alice_photo, &bob_photo, 64, 64);
    assert_ne!(
        fp_a, fp_b,
        "different session key must produce different identity fingerprint"
    );
}

#[test]
fn identity_fingerprint_sensitive_to_photo() {
    let key = [0x42u8; 32];
    let alice_photo = IdentityPhoto::new(vec![0xAA; 256]);
    let bob_photo_1 = IdentityPhoto::new(vec![0xBB; 256]);
    let bob_photo_2 = IdentityPhoto::new(vec![0xCC; 256]); // different photo

    let fp1 = identity_fingerprint(&key, &alice_photo, &bob_photo_1, 64, 64);
    let fp2 = identity_fingerprint(&key, &alice_photo, &bob_photo_2, 64, 64);
    assert_ne!(
        fp1, fp2,
        "different peer photo must produce different fingerprint"
    );
}

#[test]
fn identity_fingerprint_differs_from_plain() {
    let key = [0x42u8; 32];
    let alice_photo = IdentityPhoto::new(vec![0xAA; 256]);
    let bob_photo = IdentityPhoto::new(vec![0xBB; 256]);

    let plain = visual_fingerprint(&key, 64, 64);
    let identity = identity_fingerprint(&key, &alice_photo, &bob_photo, 64, 64);
    assert_ne!(
        plain, identity,
        "identity fingerprint must differ from plain fingerprint"
    );
}

#[test]
fn photo_hash_deterministic() {
    let photo = IdentityPhoto::new(vec![0xAA; 256]);
    let h1 = photo_hash(&photo);
    let h2 = photo_hash(&photo);
    assert_eq!(h1, h2, "same photo must produce identical hash");
}

#[test]
fn photo_hash_differs_for_different_photos() {
    let p1 = IdentityPhoto::new(vec![0xAA; 256]);
    let p2 = IdentityPhoto::new(vec![0xBB; 256]);
    assert_ne!(photo_hash(&p1), photo_hash(&p2));
}

// ── Session identity fingerprint (pending Layer 3 + visual) ────────

#[test]
fn session_identity_fingerprint_requires_photos() {
    let params = Params::default();
    let alice_kp = generate_keypair(&params);
    let bob_kp = generate_keypair(&params);
    let bob_pk = bob_kp.public_key.clone();

    let session_key = [0x42u8; 32];
    let session = Session::new(alice_kp, bob_pk, &session_key);

    // Must fail if photos haven't been set.
    let result = session.identity_fingerprint(64, 64);
    assert!(
        result.is_err(),
        "identity fingerprint must fail without photos"
    );
}

#[test]
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

// ═══════════════════════════════════════════════════════════════════
// Layer 0 — Sponge and lattice properties
// ═══════════════════════════════════════════════════════════════════

#[test]
fn lattice_seed_is_deterministic() {
    let params = Params::default();
    let mut l1 = SpinLattice::new(&params);
    let mut l2 = SpinLattice::new(&params);
    l1.seed_from_bytes(b"test-seed");
    l2.seed_from_bytes(b"test-seed");
    assert_eq!(l1.spins(), l2.spins());
    assert_eq!(l1.couplings(), l2.couplings());
}

#[test]
fn lattice_different_seeds_differ() {
    let params = Params::default();
    let mut l1 = SpinLattice::new(&params);
    let mut l2 = SpinLattice::new(&params);
    l1.seed_from_bytes(b"seed-a");
    l2.seed_from_bytes(b"seed-b");
    assert_ne!(l1.spins(), l2.spins());
}

#[test]
fn lattice_step_changes_state() {
    let params = Params::default();
    let mut lattice = SpinLattice::new(&params);
    lattice.seed_from_bytes(b"step-test");
    let before = lattice.spins().to_vec();
    lattice.step();
    assert_ne!(lattice.spins(), &before[..], "one step must change state");
}

#[test]
fn sponge_absorb_squeeze_deterministic() {
    let params = Params::default();
    let mut s1 = SpinSponge::new(&params);
    let mut s2 = SpinSponge::new(&params);
    s1.absorb(b"hello world");
    s2.absorb(b"hello world");
    assert_eq!(s1.squeeze(64), s2.squeeze(64));
}

#[test]
fn sponge_different_inputs_differ() {
    let params = Params::default();
    let mut s1 = SpinSponge::new(&params);
    let mut s2 = SpinSponge::new(&params);
    s1.absorb(b"input-a");
    s2.absorb(b"input-b");
    assert_ne!(s1.squeeze(32), s2.squeeze(32));
}

#[test]
fn sponge_reset_returns_to_initial() {
    let params = Params::default();
    let mut sponge = SpinSponge::new(&params);
    sponge.absorb(b"some data");
    sponge.reset();
    // After reset, state should be all-zero spins
    let spins = sponge.lattice().spins();
    assert!(spins.iter().all(|&s| s == 0), "reset must zero all spins");
}

// ═══════════════════════════════════════════════════════════════════
// Layer 1 — Hash, KDF, PRNG, AEAD properties
// ═══════════════════════════════════════════════════════════════════

#[test]
fn hash_deterministic() {
    let h1 = spin_hash(b"test input");
    let h2 = spin_hash(b"test input");
    assert_eq!(h1, h2);
}

#[test]
fn hash_avalanche_one_bit_flip() {
    let h1 = spin_hash(b"\x00");
    let h2 = spin_hash(b"\x01");
    // Count differing bits (Hamming distance should be significant)
    let diff_bits: u32 = h1
        .iter()
        .zip(h2.iter())
        .map(|(&a, &b)| (a ^ b).count_ones())
        .sum();
    // Expect roughly 128 bits to differ (256 * 0.5). Accept >64 as adequate.
    assert!(
        diff_bits > 64,
        "one-bit input change must flip many output bits, got {diff_bits}/256"
    );
}

#[test]
fn hash_empty_input() {
    let h = spin_hash(b"");
    assert_ne!(h, [0u8; 32], "hash of empty input must not be all zeros");
}

#[test]
fn kdf_different_salts_differ() {
    let k1 = spin_kdf(b"key", b"salt-a", b"info", 32);
    let k2 = spin_kdf(b"key", b"salt-b", b"info", 32);
    assert_ne!(k1, k2);
}

#[test]
fn kdf_different_info_differ() {
    let k1 = spin_kdf(b"key", b"salt", b"info-a", 32);
    let k2 = spin_kdf(b"key", b"salt", b"info-b", 32);
    assert_ne!(k1, k2);
}

#[test]
fn kdf_variable_output_length() {
    let k16 = spin_kdf(b"key", b"salt", b"info", 16);
    let k64 = spin_kdf(b"key", b"salt", b"info", 64);
    assert_eq!(k16.len(), 16);
    assert_eq!(k64.len(), 64);
    // First 16 bytes of k64 should NOT equal k16 (they use different
    // expand rounds), but both must be non-zero.
    assert!(k16.iter().any(|&b| b != 0));
    assert!(k64.iter().any(|&b| b != 0));
}

#[test]
fn prng_deterministic_from_seed() {
    let mut p1 = SpinPrng::new(b"seed");
    let mut p2 = SpinPrng::new(b"seed");
    assert_eq!(p1.next_bytes(64), p2.next_bytes(64));
}

#[test]
fn prng_different_seeds_differ() {
    let mut p1 = SpinPrng::new(b"seed-a");
    let mut p2 = SpinPrng::new(b"seed-b");
    assert_ne!(p1.next_bytes(32), p2.next_bytes(32));
}

#[test]
fn prng_reseed_changes_output() {
    let mut p1 = SpinPrng::new(b"seed");
    let mut p2 = SpinPrng::new(b"seed");
    // Advance both identically
    let _ = p1.next_bytes(16);
    let _ = p2.next_bytes(16);
    // Reseed one
    p1.reseed(b"extra-entropy");
    assert_ne!(p1.next_bytes(32), p2.next_bytes(32));
}

#[test]
fn aead_roundtrip() {
    let key = [0x42u8; 32];
    let nonce = [0x01u8; 16];
    let plaintext = b"secret message";
    let aad = b"associated data";

    let ct = aead::encrypt(&key, &nonce, aad, plaintext);
    let pt = aead::decrypt(&key, &nonce, aad, &ct.ciphertext, &ct.tag).unwrap();
    assert_eq!(&pt[..], &plaintext[..]);
}

#[test]
fn aead_tampered_ciphertext_fails() {
    let key = [0x42u8; 32];
    let nonce = [0x01u8; 16];
    let ct = aead::encrypt(&key, &nonce, b"", b"secret");
    let mut bad_ct = ct.ciphertext.clone();
    bad_ct[0] ^= 0xFF;
    assert!(aead::decrypt(&key, &nonce, b"", &bad_ct, &ct.tag).is_err());
}

#[test]
fn aead_tampered_tag_fails() {
    let key = [0x42u8; 32];
    let nonce = [0x01u8; 16];
    let ct = aead::encrypt(&key, &nonce, b"", b"secret");
    let mut bad_tag = ct.tag;
    bad_tag[0] ^= 0xFF;
    assert!(aead::decrypt(&key, &nonce, b"", &ct.ciphertext, &bad_tag).is_err());
}

#[test]
fn aead_wrong_aad_fails() {
    let key = [0x42u8; 32];
    let nonce = [0x01u8; 16];
    let ct = aead::encrypt(&key, &nonce, b"correct aad", b"secret");
    assert!(aead::decrypt(&key, &nonce, b"wrong aad", &ct.ciphertext, &ct.tag).is_err());
}

#[test]
fn aead_wrong_key_fails() {
    let key = [0x42u8; 32];
    let wrong_key = [0x43u8; 32];
    let nonce = [0x01u8; 16];
    let ct = aead::encrypt(&key, &nonce, b"", b"secret");
    assert!(aead::decrypt(&wrong_key, &nonce, b"", &ct.ciphertext, &ct.tag).is_err());
}

#[test]
fn aead_wrong_nonce_fails() {
    let key = [0x42u8; 32];
    let nonce = [0x01u8; 16];
    let wrong_nonce = [0x02u8; 16];
    let ct = aead::encrypt(&key, &nonce, b"", b"secret");
    assert!(aead::decrypt(&key, &wrong_nonce, b"", &ct.ciphertext, &ct.tag).is_err());
}

#[test]
fn aead_empty_plaintext_roundtrip() {
    let key = [0x42u8; 32];
    let nonce = [0x01u8; 16];
    let ct = aead::encrypt(&key, &nonce, b"", b"");
    let pt = aead::decrypt(&key, &nonce, b"", &ct.ciphertext, &ct.tag).unwrap();
    assert!(pt.is_empty());
}

#[test]
fn aead_multiblock_plaintext() {
    let key = [0x42u8; 32];
    let nonce = [0x01u8; 16];
    let plaintext = vec![0xABu8; 200]; // spans multiple 32-byte blocks
    let ct = aead::encrypt(&key, &nonce, b"", &plaintext);
    let pt = aead::decrypt(&key, &nonce, b"", &ct.ciphertext, &ct.tag).unwrap();
    assert_eq!(pt, plaintext);
}
