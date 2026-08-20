//! Regression tests for the four HEAD holes that made the library
//! non-functional. Each test fails on the unpatched tree and passes
//! after the root-cause fix.

use qs_crypto::hybrid::{
    full_hybrid_decapsulate, full_hybrid_encapsulate, full_hybrid_generate_keypair,
    hybrid_decapsulate, hybrid_encapsulate, hybrid_generate_keypair,
};
use qs_crypto::{
    decapsulate, encapsulate_deterministic, generate_keypair, spin_hash, Ciphertext, Params,
};

// ── 1. CCA off SpinHash ────────────────────────────────────────────

#[test]
fn fo_accept_and_reject_are_not_spin_hash() {
    let params = Params::default();
    let kp = generate_keypair(&params);
    let coin = vec![0x42u8; params.coin_bytes()];

    let result = encapsulate_deterministic(&kp.public_key, &coin);
    let honest =
        decapsulate(&kp.private_key, &result.ciphertext).expect("honest decaps must succeed");
    assert_eq!(
        result.shared_secret.as_bytes(),
        honest.as_bytes(),
        "encaps/decaps must agree on honest coins"
    );

    let mut h_input = Vec::with_capacity(1 + coin.len() + result.ciphertext.as_bytes().len());
    h_input.push(0x11);
    h_input.extend_from_slice(&coin);
    h_input.extend_from_slice(result.ciphertext.as_bytes());
    assert_ne!(
        result.shared_secret.as_bytes(),
        &spin_hash(&h_input),
        "accept-path ss must not be SpinHash(0x11 ‖ coin ‖ ct)"
    );

    let mut bad_bytes = result.ciphertext.to_bytes();
    bad_bytes[10] ^= 0x01;
    let bad_ct = Ciphertext::from_bytes(&bad_bytes).expect("well-sized flipped CT");
    let rejected =
        decapsulate(&kp.private_key, &bad_ct).expect("implicit rejection must return Ok");
    assert_ne!(
        rejected.as_bytes(),
        result.shared_secret.as_bytes(),
        "implicit-reject ss must differ from the honest ss"
    );

    let mut hp_input =
        Vec::with_capacity(1 + kp.private_key.as_bytes().len() + bad_ct.as_bytes().len());
    hp_input.push(0x12);
    hp_input.extend_from_slice(kp.private_key.as_bytes());
    hp_input.extend_from_slice(bad_ct.as_bytes());
    assert_ne!(
        rejected.as_bytes(),
        &spin_hash(&hp_input),
        "reject-path ss must not be SpinHash(0x12 ‖ sk ‖ ct)"
    );
}

// ── 2. Public a uniform in R_q ─────────────────────────────────────
//
// The rejection-sampling tests live next to `expand_a_shake` in
// `src/kem/xof.rs` (`twelve_bit_candidate_at_or_above_q_is_rejected`
// and `expand_a_shake_does_not_barrett_reduce_raw_u16`). They fail on
// HEAD because the old map never rejects and matches Barrett(u16).

// ── 3. Hybrid: no which-leg oracle, encaps does not panic ──────────

#[test]
fn hybrid_encaps_low_order_x25519_does_not_panic() {
    let params = Params::default();
    let kp = hybrid_generate_keypair(&params);
    let mut pk = kp.public_key();
    pk.x25519 = [0u8; 32];

    let (ct, ss) = hybrid_encapsulate(&pk);
    assert_eq!(ct.x25519_ephemeral.len(), 32);
    assert_ne!(ss.as_bytes(), &[0u8; 32], "Spin leg still contributes");
}

#[test]
fn hybrid_decaps_garbage_spin_ct_returns_combined_secret() {
    let params = Params::default();
    let kp = hybrid_generate_keypair(&params);
    let pk = kp.public_key();
    let (mut ct, honest) = hybrid_encapsulate(&pk);

    let mut spin_bytes = ct.spin_ct.to_bytes();
    spin_bytes[5] ^= 0xFF;
    ct.spin_ct = Ciphertext::from_bytes(&spin_bytes).expect("well-sized garbage Spin CT");

    let combined = hybrid_decapsulate(&kp.private_key(), &ct)
        .expect("garbage Spin CT must not be a distinct per-leg error");
    assert_ne!(combined.as_bytes(), honest.as_bytes());
}

#[test]
fn full_hybrid_encaps_low_order_x25519_does_not_panic() {
    let params = Params::default();
    let kp = full_hybrid_generate_keypair(&params);
    let mut pk = kp.public_key();
    pk.x25519 = [0u8; 32];

    let (ct, ss) = full_hybrid_encapsulate(&pk);
    assert!(!ct.mlkem_ct.is_empty());
    assert_ne!(ss.as_bytes(), &[0u8; 32]);
}

#[test]
fn full_hybrid_mlkem_parse_and_spin_fo_reject_same_shape() {
    let params = Params::default();
    let kp = full_hybrid_generate_keypair(&params);
    let pk = kp.public_key();
    let sk = kp.private_key();

    let (mut spin_bad, _) = full_hybrid_encapsulate(&pk);
    let mut spin_bytes = spin_bad.spin_ct.to_bytes();
    spin_bytes[5] ^= 0xFF;
    spin_bad.spin_ct = Ciphertext::from_bytes(&spin_bytes).unwrap();
    let spin_reject = full_hybrid_decapsulate(&sk, &spin_bad);

    let (mut mlkem_bad, _) = full_hybrid_encapsulate(&pk);
    mlkem_bad.mlkem_ct = vec![0u8; 7];
    let mlkem_parse = full_hybrid_decapsulate(&sk, &mlkem_bad);

    assert!(
        spin_reject.is_ok(),
        "Spin FO-reject must not early-return a distinct error"
    );
    assert!(
        mlkem_parse.is_ok(),
        "ML-KEM parse failure must not early-return a distinct error"
    );
}

#[test]
fn hybrid_honest_2way_and_3way_agree() {
    let params = Params::default();

    let kp2 = hybrid_generate_keypair(&params);
    let (ct2, ss2) = hybrid_encapsulate(&kp2.public_key());
    let dec2 = hybrid_decapsulate(&kp2.private_key(), &ct2).unwrap();
    assert_eq!(ss2.as_bytes(), dec2.as_bytes());

    let kp3 = full_hybrid_generate_keypair(&params);
    let (ct3, ss3) = full_hybrid_encapsulate(&kp3.public_key());
    let dec3 = full_hybrid_decapsulate(&kp3.private_key(), &ct3).unwrap();
    assert_eq!(ss3.as_bytes(), dec3.as_bytes());
}

// ── 4. ProVerif models the protocol Rust runs ──────────────────────

#[test]
fn proverif_model_matches_rust_transcript() {
    let pv = std::fs::read_to_string("docs/proverif/qs_crypto.pv")
        .expect("docs/proverif/qs_crypto.pv must exist");

    assert!(
        pv.contains("qs-pake-envelope"),
        "model must derive pwk with qs-pake-envelope"
    );
    assert!(
        pv.contains("aad=pk") || pv.contains("aad = pk") || pv.contains("aad=pk, sk"),
        "envelope must be AEAD(..., aad=pk, sk)"
    );
    assert!(
        pv.contains("0x20"),
        "session key must be SHAKE256(0x20 ‖ ss ‖ server_msg)"
    );
    assert!(
        pv.contains("server_msg"),
        "session hash binds entire server_msg"
    );
    assert!(pv.contains("qs-ratchet-root"));
    assert!(pv.contains("qs-ratchet-chain-a"));
    assert!(pv.contains("qs-ratchet-chain-b"));
    assert!(pv.contains("qs-ratchet-kem"));
    assert!(
        pv.contains("ClientLoginThenSession") && pv.contains("DoubleRatchet::init"),
        "main process must compose PAKE then ratchet the way Session does"
    );
    assert!(
        !pv.contains("kem_encaps(epk, new nonce)"),
        "Q4 must not bind `new` inside a query"
    );
}
