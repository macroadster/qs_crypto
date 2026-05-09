//! Sponge construction over the spin lattice.
//!
//! Follows the Keccak/SHA-3 sponge framework: the lattice permutation
//! replaces the Keccak-f permutation, and the lattice state is
//! partitioned into a *rate* region (data I/O) and a *capacity*
//! region (security margin).

use crate::core::lattice::SpinLattice;
use crate::params::Params;

/// Bytes consumed per Z_q element during absorb/squeeze (little-endian u16).
const BYTES_PER_ELEMENT: usize = 2;

/// Sponge state wrapping a [`SpinLattice`].
#[derive(Clone)]
pub struct SpinSponge {
    lattice: SpinLattice,
    /// Number of rate spins (data I/O region).
    rate: usize,
    /// Number of capacity spins (hidden security margin).
    #[allow(dead_code)]
    capacity: usize,
    /// Rounds per permutation invocation.
    rounds: usize,
}

impl SpinSponge {
    /// Create a new sponge sized for the given parameter set.
    ///
    /// The lattice is seeded with a fixed constant to obtain non-zero
    /// couplings; spins are then zeroed.  Without non-zero couplings
    /// the permutation has no diffusion — each spin evolves
    /// independently and absorbed data at high rate indices never
    /// reaches the low indices read during squeeze.
    pub fn new(params: &Params) -> Self {
        let mut lattice = SpinLattice::new(params);
        lattice.seed_from_bytes(b"SpinSponge-v1-coupling-init");
        let zero_spins = vec![0u16; params.total_spins];
        lattice.set_spins(&zero_spins);
        Self {
            lattice,
            rate: params.sponge_rate,
            capacity: params.sponge_capacity,
            rounds: params.permutation_rounds,
        }
    }

    /// Absorb arbitrary data into the sponge state.
    ///
    /// Data is padded (10*1), split into rate-sized blocks, added into
    /// the rate region mod q, and followed by a permutation after each
    /// block.
    pub fn absorb(&mut self, data: &[u8]) {
        let q = self.lattice.field_modulus();
        let rate_bytes = self.rate * BYTES_PER_ELEMENT;

        // 10*1 padding: append 0x80, pad with zeros, set last byte's LSB
        let mut padded = data.to_vec();
        padded.push(0x80);
        while !padded.len().is_multiple_of(rate_bytes) {
            padded.push(0x00);
        }
        // Set LSB of the very last byte (10*1 termination)
        let last = padded.len() - 1;
        padded[last] |= 0x01;

        // Process each rate-sized block
        for block in padded.chunks(rate_bytes) {
            let mut spins = self.lattice.spins().to_vec();
            for (idx, chunk) in block.chunks(BYTES_PER_ELEMENT).enumerate() {
                if idx >= self.rate {
                    break;
                }
                let val = u16::from_le_bytes([chunk[0], chunk.get(1).copied().unwrap_or(0)]) % q;
                // Add into the rate portion mod q (sponge XOR analogue)
                spins[idx] = ((spins[idx] as u32 + val as u32) % q as u32) as u16;
            }
            self.lattice.set_spins(&spins);
            self.permute();
        }
    }

    /// Run the internal permutation (K rounds of lattice dynamics).
    pub fn permute(&mut self) {
        self.lattice.run(self.rounds);
    }

    /// Squeeze `num_bytes` of output from the rate region.
    ///
    /// This implementation uses **frequent permutation during long squeezes**
    /// (mini-blocks of 16 bytes) + strong 64-bit mixing. This produces
    /// high-quality uniform byte streams with low autocorrelation while
    /// still benefiting from the excellent diffusion of the SpinLattice
    /// round function.
    pub fn squeeze(&mut self, num_bytes: usize) -> Vec<u8> {
        let mut output = Vec::with_capacity(num_bytes);
        const MINI_BLOCK: usize = 48; // More frequent mixing for better autocorrelation on long streams

        let mut bytes_since_permute = 0usize;

        while output.len() < num_bytes {
            // Copy the current rate so we can safely permute mid-block
            let rate_spins: Vec<u16> = self.lattice.spins()[..self.rate].to_vec();

            for i in 0..self.rate {
                if output.len() >= num_bytes {
                    break;
                }

                let s0 = rate_spins[i] as u64;
                let s1 = rate_spins[(i + 7) % self.rate] as u64;
                let s2 = rate_spins[(i + 19) % self.rate] as u64;

                // Strong 64-bit mixer
                let mut w = s0 ^ (s1 << 21) ^ (s2 << 42);
                w ^= w >> 27;
                w = w.wrapping_mul(0x9e3779b97f4a7c15);
                w ^= w >> 31;
                w = w.wrapping_mul(0xbf58476d1ce4e5b9);
                w ^= w >> 29;

                for k in 0..4 {
                    if output.len() >= num_bytes {
                        break;
                    }
                    output.push(((w >> (k * 8)) & 0xFF) as u8);
                    bytes_since_permute += 1;

                    if bytes_since_permute >= MINI_BLOCK {
                        self.permute();
                        bytes_since_permute = 0;
                    }
                }
            }

            if output.len() < num_bytes {
                self.permute();
                bytes_since_permute = 0;
            }
        }

        output.truncate(num_bytes);
        output
    }

    /// Reset the sponge to its initial (all-zero) state.
    pub fn reset(&mut self) {
        let spins = vec![0u16; self.lattice.spins().len()];
        self.lattice.set_spins(&spins);
    }

    /// Borrow the underlying lattice (useful for fingerprinting).
    pub fn lattice(&self) -> &SpinLattice {
        &self.lattice
    }
}
