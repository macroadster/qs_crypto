//! SpinAEAD — Hybrid Authenticated Encryption with Associated Data.
//!
//! ## Hybrid construction (v0.3 hardening)
//!
//! The AEAD now uses a **hybrid key derivation** that combines the novel
//! SpinSponge with SHAKE256, then encrypts with ChaCha20-Poly1305:
//!
//! ```text
//! spin_subkey  = SpinSponge(0x04 ‖ key ‖ nonce ‖ len(aad) ‖ aad).squeeze(32)
//! shake_subkey = SHAKE256(0x04 ‖ key ‖ nonce).finalize(32)
//! combined_key = spin_subkey ⊕ shake_subkey
//! chacha_nonce = SHAKE256("qs-aead-nonce" ‖ key ‖ nonce).finalize(12)
//!
//! (ciphertext, tag) = ChaCha20-Poly1305(combined_key, chacha_nonce, aad, plaintext)
//! ```
//!
//! This ensures confidentiality and authenticity hold even if the SpinSponge
//! permutation is completely broken — the SHAKE256 + ChaCha20-Poly1305 path
//! is independently sufficient. Conversely, if SHAKE256 were somehow weak,
//! the SpinSponge contribution protects the combined key.
//!
//! This mirrors the KEM hardening strategy (SHAKE256 for all internal
//! randomness) extended to the symmetric layer.

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use sha3::digest::{ExtendableOutput, Update};
use sha3::Shake256;
use std::io::Read;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::core::sponge::SpinSponge;
use crate::error::Error;
use crate::params::Params;

/// Ciphertext produced by [`encrypt`], containing the encrypted body
/// and a 128-bit authentication tag (Poly1305).
#[derive(Debug, Clone)]
pub struct AeadCiphertext {
    /// Encrypted payload.
    pub ciphertext: Vec<u8>,
    /// 128-bit authentication tag (Poly1305).
    pub tag: [u8; 16],
}

/// Derive the SpinSponge subkey contribution from (key, nonce, aad).
#[inline(never)]
fn derive_spin_subkey(key: &[u8; 32], nonce: &[u8; 16], aad: &[u8]) -> [u8; 32] {
    let mut sponge = SpinSponge::new(&Params::default());

    let mut key_input = Vec::with_capacity(3 + 32 + 16);
    // Versioned domain separator: [version=1, AEAD=0x04, QS-256=0x03]
    key_input.extend_from_slice(&[0x01, 0x04, 0x03]);
    key_input.extend_from_slice(key);
    key_input.extend_from_slice(nonce);
    sponge.absorb(&key_input);

    let mut aad_input = Vec::with_capacity(8 + aad.len());
    aad_input.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    aad_input.extend_from_slice(aad);
    sponge.absorb(&aad_input);

    sponge.permute();

    let out = sponge.squeeze_raw(32);
    sponge.zeroize();
    let mut subkey = [0u8; 32];
    subkey.copy_from_slice(&out);
    subkey
}

/// Derive the SHAKE256 subkey contribution from (key, nonce).
fn derive_shake_subkey(key: &[u8; 32], nonce: &[u8; 16]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    // Versioned domain separator: [version=1, AEAD=0x04, QS-256=0x03]
    hasher.update(&[0x01, 0x04, 0x03]);
    hasher.update(key);
    hasher.update(nonce);
    let mut reader = hasher.finalize_xof();
    let mut subkey = [0u8; 32];
    reader.read_exact(&mut subkey).expect("SHAKE256 read must not fail");
    subkey
}

/// Derive the 12-byte ChaCha20-Poly1305 nonce from our 16-byte nonce + key.
fn derive_chacha_nonce(key: &[u8; 32], nonce: &[u8; 16]) -> [u8; 12] {
    let mut hasher = Shake256::default();
    hasher.update(b"qs-aead-nonce");
    hasher.update(key);
    hasher.update(nonce);
    let mut reader = hasher.finalize_xof();
    let mut out = [0u8; 12];
    reader.read_exact(&mut out).expect("SHAKE256 read must not fail");
    out
}

/// Combine two subkeys via XOR. If either derivation is sound, the
/// combined key inherits that security.
fn combine_keys(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut combined = [0u8; 32];
    for i in 0..32 {
        combined[i] = a[i] ^ b[i];
    }
    combined
}

/// Encrypt `plaintext` with associated data using the hybrid
/// SpinSponge + SHAKE256 → ChaCha20-Poly1305 construction.
///
/// The security of the ciphertext and tag depends on
/// `max(SpinSponge, SHAKE256)` for key derivation and on
/// ChaCha20-Poly1305 for bulk encryption and authentication.
pub fn encrypt(key: &[u8; 32], nonce: &[u8; 16], aad: &[u8], plaintext: &[u8]) -> AeadCiphertext {
    let mut spin_sub = derive_spin_subkey(key, nonce, aad);
    let mut shake_sub = derive_shake_subkey(key, nonce);
    let mut combined = combine_keys(&spin_sub, &shake_sub);
    let chacha_nonce_bytes = derive_chacha_nonce(key, nonce);

    spin_sub.zeroize();
    shake_sub.zeroize();

    let cipher = ChaCha20Poly1305::new((&combined).into());
    combined.zeroize();

    let chacha_nonce = Nonce::from_slice(&chacha_nonce_bytes);

    // ChaCha20-Poly1305 encrypt with AAD
    let payload = chacha20poly1305::aead::Payload { msg: plaintext, aad };
    let ct_with_tag = cipher
        .encrypt(chacha_nonce, payload)
        .expect("ChaCha20-Poly1305 encryption must not fail");

    // chacha20poly1305 appends the 16-byte tag to the ciphertext
    let tag_start = ct_with_tag.len() - 16;
    let ciphertext = ct_with_tag[..tag_start].to_vec();
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&ct_with_tag[tag_start..]);

    AeadCiphertext { ciphertext, tag }
}

/// Decrypt and authenticate `ciphertext`. Returns `Error::AuthenticationFailed`
/// if the Poly1305 tag does not verify — no plaintext is released in that case.
pub fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; 16],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>, Error> {
    let mut spin_sub = derive_spin_subkey(key, nonce, aad);
    let mut shake_sub = derive_shake_subkey(key, nonce);
    let mut combined = combine_keys(&spin_sub, &shake_sub);
    let chacha_nonce_bytes = derive_chacha_nonce(key, nonce);

    spin_sub.zeroize();
    shake_sub.zeroize();

    let cipher = ChaCha20Poly1305::new((&combined).into());
    combined.zeroize();

    let chacha_nonce = Nonce::from_slice(&chacha_nonce_bytes);

    // Reassemble ciphertext ‖ tag for the chacha20poly1305 crate
    let mut ct_with_tag = Vec::with_capacity(ciphertext.len() + 16);
    ct_with_tag.extend_from_slice(ciphertext);
    ct_with_tag.extend_from_slice(tag);

    let payload = chacha20poly1305::aead::Payload {
        msg: &ct_with_tag,
        aad,
    };

    cipher
        .decrypt(chacha_nonce, payload)
        .map_err(|_| Error::AuthenticationFailed)
}

// ── SIV (Synthetic-IV) mode ────────────────────────────────────────

/// Ciphertext produced by [`encrypt_siv`], containing the synthetic IV,
/// encrypted body, and a 128-bit Poly1305 authentication tag.
///
/// Nonce reuse degrades to deterministic encryption (leaks equality
/// only) rather than XOR-of-plaintexts.
#[derive(Debug, Clone)]
pub struct SivCiphertext {
    /// 96-bit synthetic IV derived from `(key, aad, plaintext)`.
    pub siv: [u8; 12],
    /// Encrypted payload.
    pub ciphertext: Vec<u8>,
    /// 128-bit authentication tag (Poly1305).
    pub tag: [u8; 16],
}

/// Derive the 12-byte synthetic IV from `(combined_key, aad, plaintext)`.
///
/// The IV is plaintext-dependent, so reusing (key, nonce) with a
/// different plaintext still yields a unique ChaCha20 nonce.
fn derive_synthetic_nonce(combined_key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> [u8; 12] {
    let mut hasher = Shake256::default();
    hasher.update(b"qs-aead-siv");
    hasher.update(combined_key);
    hasher.update(&(aad.len() as u64).to_le_bytes());
    hasher.update(aad);
    hasher.update(plaintext);
    let mut reader = hasher.finalize_xof();
    let mut nonce = [0u8; 12];
    reader.read_exact(&mut nonce).expect("SHAKE256 read must not fail");
    nonce
}

/// Encrypt with SIV (Synthetic-IV) nonce-misuse resistance.
///
/// Same hybrid key derivation as [`encrypt`], but the ChaCha20-Poly1305
/// nonce is derived from `SHAKE256(combined_key ‖ aad ‖ plaintext)`
/// instead of from the external nonce alone.  If `(key, nonce)` is
/// reused, different plaintexts still get distinct ChaCha nonces —
/// the worst case is deterministic encryption (leaks equality only).
pub fn encrypt_siv(
    key: &[u8; 32],
    nonce: &[u8; 16],
    aad: &[u8],
    plaintext: &[u8],
) -> SivCiphertext {
    let mut spin_sub = derive_spin_subkey(key, nonce, aad);
    let mut shake_sub = derive_shake_subkey(key, nonce);
    let mut combined = combine_keys(&spin_sub, &shake_sub);

    spin_sub.zeroize();
    shake_sub.zeroize();

    let siv = derive_synthetic_nonce(&combined, aad, plaintext);

    let cipher = ChaCha20Poly1305::new((&combined).into());
    combined.zeroize();

    let chacha_nonce = Nonce::from_slice(&siv);
    let payload = chacha20poly1305::aead::Payload { msg: plaintext, aad };
    let ct_with_tag = cipher
        .encrypt(chacha_nonce, payload)
        .expect("ChaCha20-Poly1305 encryption must not fail");

    let tag_start = ct_with_tag.len() - 16;
    let ciphertext = ct_with_tag[..tag_start].to_vec();
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&ct_with_tag[tag_start..]);

    SivCiphertext { siv, ciphertext, tag }
}

/// Decrypt a SIV-mode ciphertext.  Returns `Error::AuthenticationFailed`
/// if the Poly1305 tag or the SIV binding check fails.
pub fn decrypt_siv(
    key: &[u8; 32],
    nonce: &[u8; 16],
    aad: &[u8],
    siv: &[u8; 12],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>, Error> {
    let mut spin_sub = derive_spin_subkey(key, nonce, aad);
    let mut shake_sub = derive_shake_subkey(key, nonce);
    let mut combined = combine_keys(&spin_sub, &shake_sub);

    spin_sub.zeroize();
    shake_sub.zeroize();

    let cipher = ChaCha20Poly1305::new((&combined).into());

    let chacha_nonce = Nonce::from_slice(siv);

    let mut ct_with_tag = Vec::with_capacity(ciphertext.len() + 16);
    ct_with_tag.extend_from_slice(ciphertext);
    ct_with_tag.extend_from_slice(tag);

    let payload = chacha20poly1305::aead::Payload {
        msg: &ct_with_tag,
        aad,
    };

    let plaintext = cipher
        .decrypt(chacha_nonce, payload)
        .map_err(|_| Error::AuthenticationFailed)?;

    // SIV binding: re-derive the synthetic nonce and verify it matches
    let expected_siv = derive_synthetic_nonce(&combined, aad, &plaintext);
    combined.zeroize();

    if expected_siv.ct_eq(siv).unwrap_u8() != 1 {
        return Err(Error::AuthenticationFailed);
    }

    Ok(plaintext)
}
