//! Sponge construction over the spin lattice.
//!
//! Follows the Keccak/SHA-3 sponge framework: the lattice permutation
//! replaces the Keccak-f permutation, and the lattice state is
//! partitioned into a *rate* region (data I/O) and a *capacity*
//! region (security margin).

use crate::core::lattice::SpinLattice;
use crate::params::Params;

/// Sponge state wrapping a [`SpinLattice`].
pub struct SpinSponge {
    lattice: SpinLattice,
    /// Number of rate spins (data I/O region).
    #[allow(dead_code)]
    rate: usize,
    /// Number of capacity spins (hidden security margin).
    #[allow(dead_code)]
    capacity: usize,
    /// Rounds per permutation invocation.
    rounds: usize,
}

impl SpinSponge {
    /// Create a new sponge sized for the given parameter set.
    pub fn new(params: &Params) -> Self {
        Self {
            lattice: SpinLattice::new(params),
            rate: params.sponge_rate,
            capacity: params.sponge_capacity,
            rounds: params.permutation_rounds,
        }
    }

    /// Absorb arbitrary data into the sponge state.
    ///
    /// Data is padded, split into rate-sized blocks, XOR'd into the
    /// rate region, and followed by a permutation after each block.
    pub fn absorb(&mut self, _data: &[u8]) {
        todo!("Layer 0: sponge absorb — pad, XOR into rate, permute")
    }

    /// Run the internal permutation (K rounds of lattice dynamics).
    pub fn permute(&mut self) {
        self.lattice.run(self.rounds);
    }

    /// Squeeze `num_bytes` of output from the rate region.
    ///
    /// Reads the rate, encodes to bytes, permutes, and repeats until
    /// enough output has been produced.
    pub fn squeeze(&mut self, _num_bytes: usize) -> Vec<u8> {
        todo!("Layer 0: sponge squeeze — encode rate, permute, repeat")
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