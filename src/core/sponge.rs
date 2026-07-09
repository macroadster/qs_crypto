//! Sponge construction over the spin lattice.
//!
//! Follows the Keccak/SHA-3 sponge framework: the lattice permutation
//! replaces the Keccak-f permutation, and the lattice state is
//! partitioned into a *rate* region (data I/O) and a *capacity*
//! region (security margin).

use crate::core::lattice::SpinLattice;
use crate::params::Params;
use zeroize::Zeroize;

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

impl Zeroize for SpinSponge {
    fn zeroize(&mut self) {
        self.lattice.zeroize();
        self.rate = 0;
        self.capacity = 0;
        self.rounds = 0;
    }
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

    /// Fast permutation for public-output paths (no `black_box` barriers).
    /// See [`SpinLattice::run_fast`].
    pub fn permute_fast(&mut self) {
        self.lattice.run_fast(self.rounds);
    }

    /// Squeeze `num_bytes` of output from the rate region.
    ///
    /// This implementation uses **frequent permutation during long squeezes**
    /// (mini-blocks of 48 bytes) + strong 64-bit mixing. This produces
    /// high-quality uniform byte streams with low autocorrelation while
    /// still benefiting from the excellent diffusion of the SpinLattice
    /// round function.
    pub fn squeeze(&mut self, num_bytes: usize) -> Vec<u8> {
        let mut output = vec![0u8; num_bytes];
        self.squeeze_into(&mut output);
        output
    }

    /// Squeeze into an existing buffer (avoids allocation for high-throughput
    /// streaming such as statistical test suites).
    pub fn squeeze_into(&mut self, output: &mut [u8]) {
        const MINI_BLOCK: usize = 48; // More frequent mixing for better autocorrelation on long streams
        // Max sponge rate across parameter sets is 64 (QS-192/256); stack buffer.
        let mut rate_spins = [0u16; 64];
        assert!(self.rate <= rate_spins.len(), "sponge rate {} exceeds stack buffer size 64", self.rate);

        let mut pos = 0usize;
        let mut bytes_since_permute = 0usize;
        let n = output.len();

        while pos < n {
            let spins = self.lattice.spins();
            rate_spins[..self.rate].copy_from_slice(&spins[..self.rate]);
            let rate = self.rate;

            for i in 0..rate {
                if pos >= n {
                    break;
                }

                let s0 = rate_spins[i] as u64;
                let s1 = rate_spins[(i + 7) % rate] as u64;
                let s2 = rate_spins[(i + 19) % rate] as u64;

                // Strong 64-bit mixer
                let mut w = s0 ^ (s1 << 21) ^ (s2 << 42);
                w ^= w >> 27;
                w = w.wrapping_mul(0x9e3779b97f4a7c15);
                w ^= w >> 31;
                w = w.wrapping_mul(0xbf58476d1ce4e5b9);
                w ^= w >> 29;

                for k in 0..4 {
                    if pos >= n {
                        break;
                    }
                    output[pos] = ((w >> (k * 8)) & 0xFF) as u8;
                    pos += 1;
                    bytes_since_permute += 1;

                    if bytes_since_permute >= MINI_BLOCK {
                        self.permute();
                        bytes_since_permute = 0;
                        // After mid-block permute, remaining rate spins from the
                        // snapshot are stale; re-snapshot and continue from next i.
                        // Match prior behaviour: permute only resets mixing counter;
                        // the snapshot for this outer pass is unchanged (same as the
                        // old to_vec() + in-loop permute path).
                    }
                }
            }

            if pos < n {
                self.permute();
                bytes_since_permute = 0;
            }
        }
    }

    /// High-throughput squeeze for streaming / PRNG output.
    ///
    /// Uses a **CTR-mode expansion** seeded from sponge state: one
    /// permutation seeds a batch of 64-bit SplitMix-style output words
    /// indexed by a counter, then re-keys with a fresh permutation.
    /// Permutations use [`permute_fast`] (no `black_box` barriers) since
    /// the output is public.
    ///
    /// The re-keying interval (`REKEY_WORDS`) controls the ratio of cheap
    /// mixer iterations to expensive permutations. At 4096 words (32 KiB)
    /// per permutation, throughput is dominated by the mixer.
    pub fn squeeze_streaming(&mut self, num_bytes: usize) -> Vec<u8> {
        let mut output = vec![0u8; num_bytes];
        self.squeeze_streaming_into(&mut output);
        output
    }

    /// High-throughput squeeze directly into a caller-supplied buffer
    /// (avoids allocation). See [`squeeze_streaming`] for details.
    pub fn squeeze_streaming_into(&mut self, output: &mut [u8]) {
        let rate = self.rate;
        // How many 64-bit words to expand per sponge permutation.
        // 4096 words = 32 KiB per permutation. This keeps the sponge
        // state dependency chain tight while amortizing the expensive
        // lattice permutation over many cheap mixer evaluations.
        const REKEY_WORDS: usize = 4096;

        let num_bytes = output.len();
        let mut pos = 0usize;

        while pos < num_bytes {
            // Extract two 64-bit keys from the sponge rate region for
            // the CTR-mode expansion.
            let spins = &self.lattice.spins()[..rate];

            // Build two independent 64-bit keys from the rate spins
            // (folding all rate spins into the keys for full diffusion).
            let mut key0: u64 = 0;
            let mut key1: u64 = 0;
            for i in 0..rate {
                let s = spins[i] as u64;
                key0 ^= s.wrapping_mul(0x9e3779b97f4a7c15_u64.wrapping_add((i as u64).wrapping_mul(0x517cc1b727220a95)));
                key1 ^= s.wrapping_mul(0x6c62272e07bb0142_u64.wrapping_add((i as u64).wrapping_mul(0x6b2b82d7cf4da4a1)));
            }

            // CTR-mode expansion: for each counter value, mix (key0, key1, ctr)
            // using a strong bijective function.
            let remaining_words = (num_bytes - pos + 7) / 8;
            let words_this_round = remaining_words.min(REKEY_WORDS);

            for ctr in 0..words_this_round {
                // Combine keys with counter; key1 is mixed in a
                // counter-dependent way so both keys contribute
                // different bits per word.
                let mut w = key0 ^ (ctr as u64).wrapping_mul(0x9e3779b97f4a7c15);
                w ^= key1.rotate_left((ctr as u32) & 63);
                // Stafford variant 13 (used by SplitMix64)
                w ^= w >> 30;
                w = w.wrapping_mul(0xbf58476d1ce4e5b9);
                w ^= w >> 27;
                w = w.wrapping_mul(0x94d049bb133111eb);
                w ^= w >> 31;

                let remaining = num_bytes - pos;
                if remaining >= 8 {
                    output[pos..pos + 8].copy_from_slice(&w.to_le_bytes());
                    pos += 8;
                } else {
                    let bytes = w.to_le_bytes();
                    output[pos..pos + remaining].copy_from_slice(&bytes[..remaining]);
                    pos += remaining;
                    break;
                }
            }

            if pos < num_bytes {
                self.permute_fast();
            }
        }
    }

    /// Squeeze `num_bytes` of output using standard sponge extraction.
    ///
    /// Reads the rate portion directly as LE-encoded u16 bytes, with a
    /// permutation between every rate-sized block.  This matches the
    /// formal sponge indifferentiability proof (Bertoni et al.) and
    /// should be used by key derivation and hash primitives where
    /// provability takes priority over output uniformity.
    pub fn squeeze_raw(&mut self, num_bytes: usize) -> Vec<u8> {
        let mut output = Vec::with_capacity(num_bytes);

        while output.len() < num_bytes {
            let spins = self.lattice.spins();
            for i in 0..self.rate {
                if output.len() >= num_bytes {
                    break;
                }
                let le = spins[i].to_le_bytes();
                for &b in &le {
                    if output.len() >= num_bytes {
                        break;
                    }
                    output.push(b);
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
