//! Key pair generation.
//!
//! 1. Sample random ground state σ* ∈ Z_q^N         (private key)
//! 2. Construct planted coupling matrix J with frustration noise
//! 3. Compute noisy public field h = J·σ* + e       (public key = (J, h))

use super::types::KeyPair;
use crate::params::Params;

/// Generate a fresh keypair for the given parameter set.
///
/// The private key is the planted ground state σ*. The public key
/// contains the coupling matrix J and the noisy observation h.
pub fn generate_keypair(_params: &Params) -> KeyPair {
    todo!("Layer 2: planted spin glass key generation")
}