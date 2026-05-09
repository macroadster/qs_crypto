//! SpinHash — cryptographic hash function.
//!
//! ```text
//! SpinHash(message) → 32-byte digest
//!     1. Initialize sponge
//!     2. Absorb(0x01 ‖ message)       // domain separator
//!     3. Squeeze(32)
//! ```

use crate::core::sponge::SpinSponge;
use crate::params::Params;

/// Compute a 32-byte hash of `data` using the spin-glass sponge.
///
/// Always uses the QS-256 sponge parameters regardless of the KEM
/// security level in use — the symmetric primitives operate at a
/// fixed strength.
pub fn spin_hash(data: &[u8]) -> [u8; 32] {
    let mut sponge = SpinSponge::new(&Params::default());

    let mut input = Vec::with_capacity(3 + data.len());
    // Versioned domain separator: [version=1, Hash=0x01, QS-256=0x03]
    input.extend_from_slice(&[0x01, 0x01, 0x03]);
    input.extend_from_slice(data);
    sponge.absorb(&input);

    let out = sponge.squeeze(32);
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&out);
    digest
}
