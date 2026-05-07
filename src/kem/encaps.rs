//! KEM encapsulation.
//!
//! 1. Sample random coin m
//! 2. Derive deterministic blinding from m (Fujisaki-Okamoto)
//! 3. Compute ciphertext (c₁, c₂) encoding m under the public key
//! 4. Derive shared secret = SpinHash(0x11 ‖ m ‖ ct)

use super::types::{EncapsulationResult, PublicKey};

/// Encapsulate a fresh shared secret under `pk`.
///
/// Returns the ciphertext (to send to the key holder) and the shared
/// secret (kept locally). The FO transform makes this CCA2-secure.
pub fn encapsulate(_pk: &PublicKey) -> EncapsulationResult {
    todo!("Layer 2: KEM encapsulation with FO transform")
}