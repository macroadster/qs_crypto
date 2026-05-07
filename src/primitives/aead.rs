//! SpinAEAD — Authenticated Encryption with Associated Data.
//!
//! Duplex-mode sponge AEAD (same pattern as Ketje/Keyak):
//! the ciphertext is fed back into the sponge state so the
//! authentication tag covers the entire message.

use crate::error::Error;

/// Ciphertext produced by [`encrypt`], containing the encrypted body
/// and a 128-bit authentication tag.
#[derive(Debug, Clone)]
pub struct AeadCiphertext {
    /// Encrypted payload.
    pub ciphertext: Vec<u8>,
    /// 128-bit authentication tag.
    pub tag: [u8; 16],
}

/// Encrypt `plaintext` with associated data using the spin-glass sponge
/// in duplex mode.
pub fn encrypt(
    _key: &[u8; 32],
    _nonce: &[u8; 16],
    _aad: &[u8],
    _plaintext: &[u8],
) -> AeadCiphertext {
    todo!("Layer 1: SpinAEAD encrypt — duplex sponge with ciphertext feedback")
}

/// Decrypt and authenticate `ciphertext`. Returns `Error::AuthenticationFailed`
/// if the tag does not verify — no plaintext is released in that case.
pub fn decrypt(
    _key: &[u8; 32],
    _nonce: &[u8; 16],
    _aad: &[u8],
    _ciphertext: &[u8],
    _tag: &[u8; 16],
) -> Result<Vec<u8>, Error> {
    todo!("Layer 1: SpinAEAD decrypt — duplex sponge with constant-time tag check")
}