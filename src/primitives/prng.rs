//! SpinPRNG — cryptographically secure pseudorandom number generator.
//!
//! Produces an unlimited byte stream from a seed by repeatedly
//! squeezing the sponge. Supports incremental reseeding.

use crate::core::sponge::SpinSponge;
use crate::params::Params;

/// A CSPRNG backed by the spin-glass sponge.
pub struct SpinPrng {
    #[allow(dead_code)]
    sponge: SpinSponge,
}

impl SpinPrng {
    /// Seed a new PRNG instance.
    ///
    /// Internally: absorbs `0x02 ‖ seed` into a fresh sponge.
    pub fn new(seed: &[u8]) -> Self {
        let _ = seed;
        Self {
            sponge: SpinSponge::new(&Params::default()),
        }
    }

    /// Seed a PRNG using explicit parameters.
    pub fn with_params(seed: &[u8], params: &Params) -> Self {
        let _ = seed;
        Self {
            sponge: SpinSponge::new(params),
        }
    }

    /// Generate `num_bytes` of pseudorandom output.
    pub fn next_bytes(&mut self, _num_bytes: usize) -> Vec<u8> {
        todo!("Layer 1: SpinPRNG — squeeze requested bytes")
    }

    /// Mix additional entropy into the PRNG state.
    pub fn reseed(&mut self, _entropy: &[u8]) {
        todo!("Layer 1: SpinPRNG — absorb additional entropy")
    }
}