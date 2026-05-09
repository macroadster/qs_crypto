//! SpinKDF — key derivation function.
//!
//! HKDF-style extract-then-expand built on the sponge:
//! ```text
//! EXTRACT:  absorb(0x03 ‖ salt ‖ key) → squeeze(32) = prk
//! EXPAND:   absorb(prk ‖ info ‖ counter) → squeeze(32) per block
//! ```

use crate::core::sponge::SpinSponge;
use crate::params::Params;

/// Maximum output length: 255 × 32 = 8160 bytes (HKDF-style limit).
const MAX_OUTPUT_LEN: usize = 255 * 32;

/// Derive `length` bytes of key material.
///
/// Always uses the QS-256 sponge parameters regardless of the KEM
/// security level in use — the symmetric primitives operate at a
/// fixed strength.
///
/// # Panics
///
/// Panics if `length` exceeds 8160 bytes (255 expand blocks).
pub fn spin_kdf(key: &[u8], salt: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    assert!(
        length <= MAX_OUTPUT_LEN,
        "spin_kdf: requested {length} bytes exceeds maximum {MAX_OUTPUT_LEN}"
    );
    let params = Params::default();

    // ── EXTRACT ────────────────────────────────────────────────
    let mut extract = SpinSponge::new(&params);
    let mut extract_input = Vec::with_capacity(1 + salt.len() + key.len());
    extract_input.push(0x03); // domain separator
    extract_input.extend_from_slice(salt);
    extract_input.extend_from_slice(key);
    extract.absorb(&extract_input);
    let prk = extract.squeeze(32);

    // ── EXPAND ─────────────────────────────────────────────────
    // Each block uses a fresh sponge keyed by PRK (HKDF-Expand style):
    //   T(i) = Sponge(PRK ‖ T(i-1) ‖ info ‖ counter)
    let mut output = Vec::with_capacity(length);
    let mut prev_block: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;

    while output.len() < length {
        let mut expand = SpinSponge::new(&params);
        let mut expand_input = Vec::new();
        expand_input.extend_from_slice(&prk);
        expand_input.extend_from_slice(&prev_block);
        expand_input.extend_from_slice(info);
        expand_input.push(counter);
        expand.absorb(&expand_input);

        let block = expand.squeeze(32);
        output.extend_from_slice(&block);
        prev_block = block;
        counter = counter.wrapping_add(1);
    }

    output.truncate(length);
    output
}
