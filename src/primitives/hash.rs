//! SpinHash — cryptographic hash function.
//!
//! ```text
//! SpinHash(message) → 32-byte digest
//!     1. Initialize sponge
//!     2. Absorb(0x01 ‖ message)       // domain separator
//!     3. Squeeze(32)
//! ```

/// Compute a 32-byte hash of `data` using the spin-glass sponge.
pub fn spin_hash(_data: &[u8]) -> [u8; 32] {
    todo!("Layer 1: SpinHash — absorb with domain sep 0x01, squeeze 32 bytes")
}