//! KEM decapsulation.
//!
//! 1. Recover noisy message m̃  = c₂ − σ*ᵀ · c₁
//! 2. Decode m' from m̃
//! 3. Re-encapsulate with m' and verify ciphertext matches (FO check)
//! 4. On mismatch → implicit rejection (return hash of sk ‖ ct)

use super::types::{Ciphertext, PrivateKey, SharedSecret};

/// Decapsulate a shared secret from `ct` using `sk`.
///
/// Implicit rejection: if the FO re-encapsulation check fails, a
/// deterministic but unrelated secret is returned (derived from sk ‖ ct)
/// so the caller cannot distinguish valid from invalid ciphertexts.
pub fn decapsulate(_sk: &PrivateKey, _ct: &Ciphertext) -> crate::Result<SharedSecret> {
    todo!("Layer 2: KEM decapsulation with implicit rejection")
}