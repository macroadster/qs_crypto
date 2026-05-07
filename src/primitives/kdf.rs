//! SpinKDF — key derivation function.
//!
//! HKDF-style extract-then-expand built on the sponge:
//! ```text
//! EXTRACT:  absorb(0x03 ‖ salt ‖ key) → squeeze(32) = prk
//! EXPAND:   absorb(prk ‖ info ‖ counter) → squeeze(32) per block
//! ```

/// Derive `length` bytes of key material.
pub fn spin_kdf(
    _key: &[u8],
    _salt: &[u8],
    _info: &[u8],
    _length: usize,
) -> Vec<u8> {
    todo!("Layer 1: SpinKDF — extract-then-expand via sponge")
}