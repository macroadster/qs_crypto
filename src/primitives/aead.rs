//! SpinAEAD — Authenticated Encryption with Associated Data.
//!
//! Duplex-mode sponge AEAD (same pattern as Ketje/Keyak):
//! the ciphertext is fed back into the sponge state so the
//! authentication tag covers the entire message.

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::core::sponge::SpinSponge;
use crate::error::Error;
use crate::params::Params;

/// Block size for duplex streaming (matches SpinHash output size).
const BLOCK_SIZE: usize = 32;

/// Ciphertext produced by [`encrypt`], containing the encrypted body
/// and a 128-bit authentication tag.
#[derive(Debug, Clone)]
pub struct AeadCiphertext {
    /// Encrypted payload.
    pub ciphertext: Vec<u8>,
    /// 128-bit authentication tag.
    pub tag: [u8; 16],
}

/// Initialize a sponge with key, nonce, and associated data.
fn init_sponge(key: &[u8; 32], nonce: &[u8; 16], aad: &[u8]) -> SpinSponge {
    let mut sponge = SpinSponge::new(&Params::default());

    // Absorb domain separator ‖ key ‖ nonce
    let mut key_input = Vec::with_capacity(1 + 32 + 16);
    key_input.push(0x04); // domain separator
    key_input.extend_from_slice(key);
    key_input.extend_from_slice(nonce);
    sponge.absorb(&key_input);

    // Absorb length-prefixed AAD
    let mut aad_input = Vec::with_capacity(8 + aad.len());
    aad_input.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    aad_input.extend_from_slice(aad);
    sponge.absorb(&aad_input);

    // Extra permutation to separate AAD from payload
    sponge.permute();
    sponge
}

/// Encrypt `plaintext` with associated data using the spin-glass sponge
/// in duplex mode.
pub fn encrypt(key: &[u8; 32], nonce: &[u8; 16], aad: &[u8], plaintext: &[u8]) -> AeadCiphertext {
    let mut sponge = init_sponge(key, nonce, aad);

    // Duplex encryption: XOR keystream, then feed ciphertext back
    let mut ciphertext = Vec::with_capacity(plaintext.len());
    for chunk in plaintext.chunks(BLOCK_SIZE) {
        let keystream = sponge.squeeze(chunk.len());
        let ct_block: Vec<u8> = chunk
            .iter()
            .zip(keystream.iter())
            .map(|(&p, &k)| p ^ k)
            .collect();
        ciphertext.extend_from_slice(&ct_block);
        sponge.absorb(&ct_block);
    }

    // Squeeze authentication tag
    let tag_bytes = sponge.squeeze(16);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&tag_bytes);

    AeadCiphertext { ciphertext, tag }
}

/// Decrypt and authenticate `ciphertext`. Returns `Error::AuthenticationFailed`
/// if the tag does not verify — no plaintext is released in that case.
pub fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; 16],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>, Error> {
    let mut sponge = init_sponge(key, nonce, aad);

    // Duplex decryption: same keystream, feed CIPHERTEXT back (not plaintext)
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    for chunk in ciphertext.chunks(BLOCK_SIZE) {
        let keystream = sponge.squeeze(chunk.len());
        let pt_block: Vec<u8> = chunk
            .iter()
            .zip(keystream.iter())
            .map(|(&c, &k)| c ^ k)
            .collect();
        plaintext.extend_from_slice(&pt_block);
        sponge.absorb(chunk); // feed ciphertext, not plaintext
    }

    // Constant-time tag verification
    let expected = sponge.squeeze(16);
    let mut expected_tag = [0u8; 16];
    expected_tag.copy_from_slice(&expected);

    if expected_tag.ct_eq(tag).into() {
        Ok(plaintext)
    } else {
        plaintext.zeroize();
        Err(Error::AuthenticationFailed)
    }
}
