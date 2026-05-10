//! Hybrid KEM: SpinKEM || X25519
//!
//! This construction provides defense-in-depth. The resulting shared secret
//! is at least as strong as the stronger of the two components.
//!
//! Combiner: SHAKE256( ss_spin || ss_x25519 || "qs-hybrid-v1" )

use rand_core::OsRng;
use sha3::digest::{ExtendableOutput, Update};
use sha3::Shake256;
use std::io::Read;
use x25519_dalek::{PublicKey as XPublic, StaticSecret as XSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::types::{Ciphertext, PrivateKey, PublicKey};
use crate::kem::{decapsulate, encapsulate, generate_keypair};
use crate::params::Params;

/// A hybrid keypair containing both a Spin (Ring-LWE) keypair and an X25519 keypair.
#[derive(Clone)]
pub struct HybridKeyPair {
    pub spin: super::types::KeyPair,
    pub x25519_secret: XSecret,
    pub x25519_public: XPublic,
}

/// Public key for the hybrid KEM (Spin + X25519).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridPublicKey {
    pub spin: PublicKey,
    pub x25519: [u8; 32],
}

/// Private key for the hybrid KEM.
#[derive(Clone)]
pub struct HybridPrivateKey {
    pub spin: PrivateKey,
    spin_public: PublicKey,
    pub x25519: XSecret,
    pub x25519_public: XPublic,
}

impl Drop for HybridPrivateKey {
    fn drop(&mut self) {
        self.x25519.zeroize();
    }
}

impl HybridPrivateKey {
    pub fn public(&self) -> HybridPublicKey {
        HybridPublicKey {
            spin: self.spin_public.clone(),
            x25519: self.x25519_public.to_bytes(),
        }
    }
}

// Note: For simplicity in v1 we store the Spin public key inside the private key
// (already done by the base KEM). We reconstruct the hybrid public on demand.

/// Generate a fresh hybrid keypair (Spin + X25519).
pub fn hybrid_generate_keypair(params: &Params) -> HybridKeyPair {
    let spin_kp = generate_keypair(params);

    let x_secret = XSecret::random_from_rng(OsRng);
    let x_public = XPublic::from(&x_secret);

    HybridKeyPair {
        spin: spin_kp,
        x25519_secret: x_secret,
        x25519_public: x_public,
    }
}

impl HybridKeyPair {
    /// Returns the hybrid public key (cheap to call).
    pub fn public_key(&self) -> HybridPublicKey {
        HybridPublicKey {
            spin: self.spin.public_key.clone(),
            x25519: self.x25519_public.to_bytes(),
        }
    }

    /// Returns the hybrid private key (clones the X25519 secret).
    /// Use this for decapsulation.
    pub fn private_key(&self) -> HybridPrivateKey {
        HybridPrivateKey {
            spin: self.spin.private_key.clone(),
            spin_public: self.spin.public_key.clone(),
            x25519: self.x25519_secret.clone(),
            x25519_public: self.x25519_public,
        }
    }
}

/// Encapsulate to a hybrid public key.
/// Returns (hybrid_ciphertext, hybrid_shared_secret).
pub fn hybrid_encapsulate(pk: &HybridPublicKey) -> (HybridCiphertext, HybridSharedSecret) {
    // Spin encapsulation
    let spin_pk = &pk.spin;
    let spin_result = encapsulate(spin_pk);
    let ss_spin = spin_result.shared_secret;

    // X25519 encapsulation (ephemeral)
    let eph_secret = XSecret::random_from_rng(OsRng);
    let eph_public = XPublic::from(&eph_secret);
    let peer_x25519 = XPublic::from(pk.x25519);
    let ss_x25519 = eph_secret.diffie_hellman(&peer_x25519);
    // Reject low-order / identity points that would yield an all-zero shared secret.
    assert_ne!(
        ss_x25519.as_bytes(),
        &[0u8; 32],
        "X25519 produced all-zero shared secret (low-order peer key)"
    );

    let ct = HybridCiphertext {
        spin_ct: spin_result.ciphertext,
        x25519_ephemeral: eph_public.to_bytes(),
    };

    // Combine with SHAKE256, binding all transcript material (NIST SP 800-56Cr2).
    let combined = hybrid_combine(
        ss_spin.as_bytes(),
        ss_x25519.as_bytes(),
        pk.spin.as_bytes(),
        &pk.x25519,
        ct.spin_ct.as_bytes(),
        &ct.x25519_ephemeral,
    );

    (ct, HybridSharedSecret::from_bytes(combined))
}

/// Decapsulate a hybrid ciphertext.
///
/// Both KEM legs always execute regardless of individual errors, so the
/// X25519 component provides its security guarantee even when the Spin
/// component fails. Errors are combined after both legs complete.
pub fn hybrid_decapsulate(
    sk: &HybridPrivateKey,
    ct: &HybridCiphertext,
) -> crate::Result<HybridSharedSecret> {
    // Always run both legs — no short-circuit on Spin failure.
    let spin_result = decapsulate(&sk.spin, &ct.spin_ct);

    // X25519 decapsulation (always runs)
    let eph_public = XPublic::from(ct.x25519_ephemeral);
    let ss_x25519 = sk.x25519.diffie_hellman(&eph_public);

    // Propagate Spin error only after X25519 has completed
    let ss_spin = spin_result?;

    // Same combiner, binding all transcript material.
    let combined = hybrid_combine(
        ss_spin.as_bytes(),
        ss_x25519.as_bytes(),
        sk.spin_public.as_bytes(),
        &sk.x25519_public.to_bytes(),
        ct.spin_ct.as_bytes(),
        &ct.x25519_ephemeral,
    );

    Ok(HybridSharedSecret::from_bytes(combined))
}

/// Hybrid combiner: SHAKE256 over both shared secrets + all public transcript
/// material (public keys and ciphertexts), per NIST SP 800-56Cr2 guidance.
fn hybrid_combine(
    ss_spin: &[u8],
    ss_x25519: &[u8],
    pk_spin: &[u8],
    pk_x25519: &[u8],
    ct_spin: &[u8],
    ct_x25519: &[u8],
) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(ss_spin);
    hasher.update(ss_x25519);
    hasher.update(pk_spin);
    hasher.update(pk_x25519);
    hasher.update(ct_spin);
    hasher.update(ct_x25519);
    hasher.update(b"qs-hybrid-v2");

    let mut combined = [0u8; 32];
    let mut reader = hasher.finalize_xof();
    reader.read_exact(&mut combined).expect("SHAKE read failed");
    combined
}

// --- 3-Way Hybrid KEM (Spin + X25519 + ML-KEM-768) ---

use ml_kem::kem::{
    Decapsulate, DecapsulationKey as MlKemDecapsKey, Encapsulate,
    EncapsulationKey as MlKemEncapsKey,
};
use ml_kem::{KemCore, MlKem768, MlKem768Params};

/// ML-KEM-768 key type aliases.
type MlKemEk = MlKemEncapsKey<MlKem768Params>;
type MlKemDk = MlKemDecapsKey<MlKem768Params>;

/// A full 3-way hybrid keypair: Spin (Ring-LWE) + X25519 + ML-KEM-768.
///
/// The resulting shared secret is at least as strong as the strongest of
/// the three components: `combined_ss = SHAKE256(ss_spin ‖ ss_x25519 ‖ ss_mlkem ‖ transcript)`.
#[derive(Clone)]
pub struct FullHybridKeyPair {
    pub spin: super::types::KeyPair,
    pub x25519_secret: XSecret,
    pub x25519_public: XPublic,
    pub mlkem_dk: MlKemDk,
    pub mlkem_ek: MlKemEk,
}

/// Public key for the 3-way hybrid KEM.
#[derive(Clone, Debug, PartialEq)]
pub struct FullHybridPublicKey {
    pub spin: PublicKey,
    pub x25519: [u8; 32],
    pub mlkem_ek: MlKemEk,
}

/// Private key for the 3-way hybrid KEM.
#[derive(Clone)]
pub struct FullHybridPrivateKey {
    pub spin: PrivateKey,
    spin_public: PublicKey,
    pub x25519: XSecret,
    pub x25519_public: XPublic,
    pub mlkem_dk: MlKemDk,
    mlkem_ek: MlKemEk,
}

impl Drop for FullHybridPrivateKey {
    fn drop(&mut self) {
        self.x25519.zeroize();
    }
}

impl FullHybridPrivateKey {
    pub fn public(&self) -> FullHybridPublicKey {
        FullHybridPublicKey {
            spin: self.spin_public.clone(),
            x25519: self.x25519_public.to_bytes(),
            mlkem_ek: self.mlkem_ek.clone(),
        }
    }
}

/// Ciphertext for the 3-way hybrid KEM.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FullHybridCiphertext {
    pub spin_ct: Ciphertext,
    pub x25519_ephemeral: [u8; 32],
    pub mlkem_ct: Vec<u8>,
}

/// Generate a 3-way hybrid keypair (Spin + X25519 + ML-KEM-768).
pub fn full_hybrid_generate_keypair(params: &Params) -> FullHybridKeyPair {
    let spin_kp = generate_keypair(params);
    let x_secret = XSecret::random_from_rng(OsRng);
    let x_public = XPublic::from(&x_secret);
    let (mlkem_dk, mlkem_ek) = MlKem768::generate(&mut OsRng);

    FullHybridKeyPair {
        spin: spin_kp,
        x25519_secret: x_secret,
        x25519_public: x_public,
        mlkem_dk,
        mlkem_ek,
    }
}

impl FullHybridKeyPair {
    pub fn public_key(&self) -> FullHybridPublicKey {
        FullHybridPublicKey {
            spin: self.spin.public_key.clone(),
            x25519: self.x25519_public.to_bytes(),
            mlkem_ek: self.mlkem_ek.clone(),
        }
    }

    pub fn private_key(&self) -> FullHybridPrivateKey {
        FullHybridPrivateKey {
            spin: self.spin.private_key.clone(),
            spin_public: self.spin.public_key.clone(),
            x25519: self.x25519_secret.clone(),
            x25519_public: self.x25519_public,
            mlkem_dk: self.mlkem_dk.clone(),
            mlkem_ek: self.mlkem_ek.clone(),
        }
    }
}

/// Encapsulate to a 3-way hybrid public key.
/// Returns (hybrid_ciphertext, hybrid_shared_secret).
pub fn full_hybrid_encapsulate(
    pk: &FullHybridPublicKey,
) -> (FullHybridCiphertext, HybridSharedSecret) {
    // 1. Spin encapsulation
    let spin_result = encapsulate(&pk.spin);
    let ss_spin = spin_result.shared_secret;

    // 2. X25519 encapsulation (ephemeral)
    let eph_secret = XSecret::random_from_rng(OsRng);
    let eph_public = XPublic::from(&eph_secret);
    let peer_x25519 = XPublic::from(pk.x25519);
    let ss_x25519 = eph_secret.diffie_hellman(&peer_x25519);
    assert_ne!(
        ss_x25519.as_bytes(),
        &[0u8; 32],
        "X25519 produced all-zero shared secret (low-order peer key)"
    );

    // 3. ML-KEM-768 encapsulation
    let (mlkem_ct, mlkem_ss) = pk
        .mlkem_ek
        .encapsulate(&mut OsRng)
        .expect("ML-KEM encapsulation failed");
    let mlkem_ct_bytes: Vec<u8> = AsRef::<[u8]>::as_ref(&mlkem_ct).to_vec();

    let ct = FullHybridCiphertext {
        spin_ct: spin_result.ciphertext,
        x25519_ephemeral: eph_public.to_bytes(),
        mlkem_ct: mlkem_ct_bytes,
    };

    // 4. 3-way SHAKE256 combiner, binding all transcript material (NIST SP 800-56Cr2)
    let combined = full_hybrid_combine(&FullHybridTranscript {
        ss_spin: ss_spin.as_bytes(),
        ss_x25519: ss_x25519.as_bytes(),
        ss_mlkem: mlkem_ss.as_ref(),
        pk_spin: pk.spin.as_bytes(),
        pk_x25519: &pk.x25519,
        ct_spin: ct.spin_ct.as_bytes(),
        ct_x25519: &ct.x25519_ephemeral,
        ct_mlkem: &ct.mlkem_ct,
    });

    (ct, HybridSharedSecret::from_bytes(combined))
}

/// Decapsulate a 3-way hybrid ciphertext.
///
/// All three KEM legs always execute regardless of individual errors,
/// ensuring each component provides its security guarantee.
pub fn full_hybrid_decapsulate(
    sk: &FullHybridPrivateKey,
    ct: &FullHybridCiphertext,
) -> crate::Result<HybridSharedSecret> {
    // Always run all three legs — no short-circuit.
    let spin_result = decapsulate(&sk.spin, &ct.spin_ct);

    // X25519
    let eph_public = XPublic::from(ct.x25519_ephemeral);
    let ss_x25519 = sk.x25519.diffie_hellman(&eph_public);

    // ML-KEM-768: reconstruct typed ciphertext from bytes
    let mlkem_ct = ml_kem::array::Array::try_from(ct.mlkem_ct.as_slice())
        .map_err(|_| crate::Error::DecapsulationFailed)?;
    let mlkem_result = sk.mlkem_dk.decapsulate(&mlkem_ct);

    // Propagate errors only after all legs complete
    let ss_spin = spin_result?;
    let mlkem_ss = mlkem_result.map_err(|_| crate::Error::DecapsulationFailed)?;

    let combined = full_hybrid_combine(&FullHybridTranscript {
        ss_spin: ss_spin.as_bytes(),
        ss_x25519: ss_x25519.as_bytes(),
        ss_mlkem: mlkem_ss.as_ref(),
        pk_spin: sk.spin_public.as_bytes(),
        pk_x25519: &sk.x25519_public.to_bytes(),
        ct_spin: ct.spin_ct.as_bytes(),
        ct_x25519: &ct.x25519_ephemeral,
        ct_mlkem: &ct.mlkem_ct,
    });

    Ok(HybridSharedSecret::from_bytes(combined))
}

/// Transcript material for the 3-way combiner.
struct FullHybridTranscript<'a> {
    ss_spin: &'a [u8],
    ss_x25519: &'a [u8],
    ss_mlkem: &'a [u8],
    pk_spin: &'a [u8],
    pk_x25519: &'a [u8],
    ct_spin: &'a [u8],
    ct_x25519: &'a [u8],
    ct_mlkem: &'a [u8],
}

/// 3-way combiner: SHAKE256 over all three shared secrets + public transcript
/// material (public keys and ciphertexts), per NIST SP 800-56Cr2 guidance.
fn full_hybrid_combine(t: &FullHybridTranscript<'_>) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(t.ss_spin);
    hasher.update(t.ss_x25519);
    hasher.update(t.ss_mlkem);
    hasher.update(t.pk_spin);
    hasher.update(t.pk_x25519);
    hasher.update(t.ct_spin);
    hasher.update(t.ct_x25519);
    hasher.update(t.ct_mlkem);
    hasher.update(b"qs-full-hybrid-v1");

    let mut combined = [0u8; 32];
    let mut reader = hasher.finalize_xof();
    reader.read_exact(&mut combined).expect("SHAKE read failed");
    combined
}

// --- Supporting types ---

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridCiphertext {
    pub spin_ct: Ciphertext,
    pub x25519_ephemeral: [u8; 32],
}

#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct HybridSharedSecret {
    bytes: [u8; 32],
}

impl HybridSharedSecret {
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self { bytes: b }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

// Small helper to get the public key from a Spin KeyPair (we expose it via the types module)
impl super::types::KeyPair {
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
}
