//! Integration tests — key generation.

use qs_crypto::{generate_keypair, Params, PrivateKey, PublicKey, SecurityLevel};

// ── Parameter validation (runs now) ────────────────────────────────

#[test]
fn params_default_is_qs256() {
    let params = Params::default();
    assert_eq!(params.security_level, SecurityLevel::QS256);
    assert_eq!(params.q, 3329);
    assert_eq!(params.lattice_side, 16);
    assert_eq!(params.total_spins, 256);
}

#[test]
fn params_qs128_dimensions() {
    let params = Params::from_security_level(SecurityLevel::QS128);
    assert_eq!(params.lattice_side, 12);
    assert_eq!(params.total_spins, 144);
    assert_eq!(params.sponge_rate, 48);
    assert_eq!(params.sponge_capacity, 96);
}

#[test]
fn params_qs192_dimensions() {
    let params = Params::from_security_level(SecurityLevel::QS192);
    assert_eq!(params.lattice_side, 14);
    assert_eq!(params.total_spins, 196);
    assert_eq!(params.sponge_rate, 64);
    assert_eq!(params.sponge_capacity, 132);
}

// ── Key type construction from raw bytes (runs now) ────────────────

#[test]
fn public_key_roundtrip_from_bytes() {
    // QS128 (0x01): pk = 1 + 32 + 2*144 = 321 bytes
    let mut raw = vec![0u8; 321];
    raw[0] = 0x01;
    let pk = PublicKey::from_bytes(&raw).unwrap();
    assert_eq!(pk.as_bytes(), &raw[..]);
    assert_eq!(pk.to_bytes(), raw);
}

#[test]
fn private_key_roundtrip_from_bytes() {
    // QS128 (0x01): sk = 1 + 2*144 + (1+32+2*144) = 610 bytes
    let mut raw = vec![0u8; 610];
    raw[0] = 0x01;
    // Embedded pk also needs a valid level byte
    raw[1 + 2 * 144] = 0x01;
    let sk = PrivateKey::from_bytes(&raw).unwrap();
    assert_eq!(sk.as_bytes(), &raw[..]);
    assert_eq!(sk.to_bytes(), raw);
}

#[test]
fn empty_bytes_rejected() {
    assert!(PublicKey::from_bytes(&[]).is_err());
    assert!(PrivateKey::from_bytes(&[]).is_err());
}

// ── Full key generation (pending Layer 2 implementation) ───────────

#[test]
fn generate_keypair_default_params() {
    let keypair = generate_keypair(&Params::default());

    assert!(
        !keypair.public_key.as_bytes().is_empty(),
        "public key must not be empty"
    );
    assert!(
        !keypair.private_key.as_bytes().is_empty(),
        "private key must not be empty"
    );
}

#[test]
fn generate_keypair_all_security_levels() {
    for level in [
        SecurityLevel::QS128,
        SecurityLevel::QS192,
        SecurityLevel::QS256,
    ] {
        let params = Params::from_security_level(level);
        let keypair = generate_keypair(&params);
        assert!(!keypair.public_key.as_bytes().is_empty());
    }
}

#[test]
fn keypairs_are_unique() {
    let params = Params::default();
    let kp1 = generate_keypair(&params);
    let kp2 = generate_keypair(&params);

    assert_ne!(
        kp1.public_key.as_bytes(),
        kp2.public_key.as_bytes(),
        "independently generated keypairs must differ"
    );
}

#[test]
fn public_key_serialization_roundtrip() {
    let keypair = generate_keypair(&Params::default());

    let bytes = keypair.public_key.to_bytes();
    let restored =
        PublicKey::from_bytes(&bytes).expect("deserialization must succeed for a valid key");

    assert_eq!(keypair.public_key.as_bytes(), restored.as_bytes());
}

#[test]
fn private_key_serialization_roundtrip() {
    let keypair = generate_keypair(&Params::default());

    let bytes = keypair.private_key.to_bytes();
    let restored =
        PrivateKey::from_bytes(&bytes).expect("deserialization must succeed for a valid key");

    assert_eq!(keypair.private_key.as_bytes(), restored.as_bytes());
}

// ── Security-level byte roundtrip ──────────────────────────────────

#[test]
fn security_level_byte_roundtrip() {
    for level in [
        SecurityLevel::QS128,
        SecurityLevel::QS192,
        SecurityLevel::QS256,
    ] {
        let byte = level.to_byte();
        let restored = SecurityLevel::from_byte(byte).expect("valid level byte");
        assert_eq!(level, restored);
    }
}

#[test]
fn security_level_invalid_byte_returns_none() {
    assert!(SecurityLevel::from_byte(0x00).is_none());
    assert!(SecurityLevel::from_byte(0xFF).is_none());
}

// ── Public key embeds security level ───────────────────────────────

#[test]
fn public_key_starts_with_level_byte() {
    for level in [
        SecurityLevel::QS128,
        SecurityLevel::QS192,
        SecurityLevel::QS256,
    ] {
        let params = Params::from_security_level(level);
        let keypair = generate_keypair(&params);
        assert_eq!(
            keypair.public_key.as_bytes()[0],
            level.to_byte(),
            "first byte of public key must be the security level"
        );
    }
}

// ── Key sizes scale with security level ────────────────────────────

#[test]
fn key_sizes_increase_with_security_level() {
    let kp128 = generate_keypair(&Params::from_security_level(SecurityLevel::QS128));
    let kp192 = generate_keypair(&Params::from_security_level(SecurityLevel::QS192));
    let kp256 = generate_keypair(&Params::from_security_level(SecurityLevel::QS256));

    assert!(
        kp128.public_key.as_bytes().len() < kp192.public_key.as_bytes().len(),
        "QS-192 pk must be larger than QS-128"
    );
    assert!(
        kp192.public_key.as_bytes().len() < kp256.public_key.as_bytes().len(),
        "QS-256 pk must be larger than QS-192"
    );
}
