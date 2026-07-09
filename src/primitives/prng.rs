//! SpinPRNG — cryptographically secure pseudorandom number generator.
//!
//! Produces an unlimited byte stream from a seed by repeatedly
//! squeezing the sponge. Supports incremental reseeding.

use crate::core::sponge::SpinSponge;
use crate::params::Params;

/// A CSPRNG backed by the spin-glass sponge.
pub struct SpinPrng {
    sponge: SpinSponge,
}

impl SpinPrng {
    /// Seed a new PRNG instance.
    ///
    /// Internally: absorbs `0x02 ‖ seed` into a fresh sponge.
    pub fn new(seed: &[u8]) -> Self {
        Self::with_params(seed, &Params::default())
    }

    /// Seed a PRNG using explicit parameters.
    pub fn with_params(seed: &[u8], params: &Params) -> Self {
        let mut sponge = SpinSponge::new(params);
        let mut input = Vec::with_capacity(3 + seed.len());
        // Versioned domain separator: [version=1, PRNG=0x02, QS-256=0x03]
        input.extend_from_slice(&[0x01, 0x02, 0x03]);
        input.extend_from_slice(seed);
        sponge.absorb(&input);
        Self { sponge }
    }

    /// Generate `num_bytes` of pseudorandom output.
    ///
    /// Uses the high-throughput streaming squeeze path. The output is
    /// public by definition (it *is* the random stream), so no
    /// constant-time barriers are needed.
    pub fn next_bytes(&mut self, num_bytes: usize) -> Vec<u8> {
        self.sponge.squeeze_streaming(num_bytes)
    }

    /// Fill `buf` with pseudorandom bytes (no allocation).
    ///
    /// Uses the high-throughput streaming squeeze path — same as
    /// [`next_bytes`] but writes directly into the caller's buffer.
    pub fn fill_bytes(&mut self, buf: &mut [u8]) {
        self.sponge.squeeze_streaming_into(buf);
    }

    /// Mix additional entropy into the PRNG state.
    pub fn reseed(&mut self, entropy: &[u8]) {
        self.sponge.absorb(entropy);
    }
}
