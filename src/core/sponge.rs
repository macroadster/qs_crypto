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
    /// Reads the rate spins, encodes each as 2 little-endian bytes,
    /// permutes, and repeats until enough output has been produced.
    pub fn squeeze(&mut self, num_bytes: usize) -> Vec<u8> {
        let mut output = Vec::with_capacity(num_bytes);

        while output.len() < num_bytes {
            let spins = self.lattice.spins();
            for &spin in spins.iter().take(self.rate) {
                if output.len() >= num_bytes {
                    break;
                }
                let bytes = spin.to_le_bytes();
                output.push(bytes[0]);
                if output.len() < num_bytes {
                    output.push(bytes[1]);
                }
            }
            if output.len() < num_bytes {
                self.permute();
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
