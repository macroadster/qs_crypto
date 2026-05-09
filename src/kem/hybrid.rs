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

// --- ML-KEM (Priority 2) Support ---

/// Extended hybrid KEM (Spin + X25519 + additional KDF hardening).
///
/// This is a 2-leg hybrid with an extra KDF pass for domain separation.
/// It does **not** include a real ML-KEM leg — that requires integrating
/// the `ml-kem` crate. The API is shaped so that a third KEM leg can be
/// added later with minimal change.
pub fn full_hybrid_generate_keypair(params: &Params) -> HybridKeyPair {
    hybrid_generate_keypair(params)
}

pub fn full_hybrid_encapsulate(pk: &HybridPublicKey) -> (HybridCiphertext, HybridSharedSecret) {
    let (base_ct, base_ss) = hybrid_encapsulate(pk);

    // Additional KDF pass for domain separation (placeholder for future ML-KEM leg)
    let mut hasher = Shake256::default();
    hasher.update(base_ss.as_bytes());
    hasher.update(b"qs-extended-hybrid-v0.2");

    let mut final_ss = [0u8; 32];
    let mut reader = hasher.finalize_xof();
    reader.read_exact(&mut final_ss).expect("SHAKE failed");

    (base_ct, HybridSharedSecret::from_bytes(final_ss))
}

pub fn full_hybrid_decapsulate(
    sk: &HybridPrivateKey,
    ct: &HybridCiphertext,
) -> crate::Result<HybridSharedSecret> {
    let base_ss = hybrid_decapsulate(sk, ct)?;

    let mut hasher = Shake256::default();
    hasher.update(base_ss.as_bytes());
    hasher.update(b"qs-extended-hybrid-v0.2");

    let mut final_ss = [0u8; 32];
    let mut reader = hasher.finalize_xof();
    reader.read_exact(&mut final_ss).expect("SHAKE failed");

    Ok(HybridSharedSecret::from_bytes(final_ss))
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
