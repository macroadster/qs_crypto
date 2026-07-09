//! Spin-glass-inspired lattice engine.
//!
//! Models a generalized Potts system on a triangular lattice over Z_q
//! with toroidal boundary conditions. The triangular topology introduces
//! geometric frustration. The synchronous update rule (neighbor mixing +
//! cubing S-box) serves as the permutation for the sponge construction.
//!
//! Update rule (synchronous, per round):
//! ```text
//!   h_eff(i) = Σ_j  J_ij · σ_j              (mod q)
//!   σ_i'     = (h_eff(i) + σ_i + rc_i)³     (mod q)
//! ```

use crate::core::reduce::{barrett_reduce_small, barrett_reduce_unsigned};
use crate::params::Params;
use core::hint::black_box;
use zeroize::Zeroize;

/// 6 neighbours per spin on the triangular lattice.
/// Directions: [East, West, North, South, NorthEast, SouthWest]
const NUM_NEIGHBORS: usize = 6;

/// Reverse direction lookup: E<->W, N<->S, NE<->SW.
#[allow(dead_code)]
pub(crate) const REVERSE_DIR: [usize; NUM_NEIGHBORS] = [1, 0, 3, 2, 5, 4];

/// Return the 6 neighbour coordinates for position `(r, c)` on an `n×n`
/// triangular lattice with toroidal (wrap-around) boundary conditions.
pub(crate) fn triangular_neighbors(
    r: usize,
    c: usize,
    n: usize,
) -> [(usize, usize); NUM_NEIGHBORS] {
    let up = if r == 0 { n - 1 } else { r - 1 };
    let down = (r + 1) % n;
    let left = if c == 0 { n - 1 } else { c - 1 };
    let right = (c + 1) % n;
    [
        (r, right),   // East
        (r, left),    // West
        (up, c),      // North
        (down, c),    // South
        (up, right),  // NorthEast (triangular diagonal)
        (down, left), // SouthWest (triangular diagonal)
    ]
}

/// SplitMix64 — fast, high-quality seed expansion.
fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e3779b97f4a7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}

/// An n×n triangular lattice of spins over Z_q.
#[derive(Clone)]
pub struct SpinLattice {
    /// Side length of the square lattice.
    n: usize,
    /// Field modulus.
    q: u16,
    /// Spin values — length n², each in [0, q).
    spins: Vec<u16>,
    /// Coupling constants for each edge in the triangular lattice.
    /// Stored as adjacency list: for each spin i, its 6 neighbour couplings.
    couplings: Vec<u16>,
    /// Pre-computed flat neighbor indices for each spin, avoiding
    /// repeated `triangular_neighbors` + coordinate→index math per step.
    neighbor_indices: Vec<[usize; NUM_NEIGHBORS]>,
    /// Pre-computed round constants `barrett_reduce((i * 2654435761) mod 2^64)`.
    round_constants: Vec<u16>,
    /// Scratch buffer reused across `step()`/`step_fast()` calls to
    /// avoid allocating a new `Vec<u16>` on every synchronous update.
    scratch: Vec<u16>,
}

impl Zeroize for SpinLattice {
    fn zeroize(&mut self) {
        self.spins.zeroize();
        self.couplings.zeroize();
        self.scratch.zeroize();
    }
}

impl SpinLattice {
    /// Create a new lattice from the given parameter set.
    /// All spins initialize to zero; couplings are unset.
    pub fn new(params: &Params) -> Self {
        let n = params.lattice_side;
        let total = n * n;
        // Pre-compute flat neighbor indices once.
        let mut neighbor_indices = Vec::with_capacity(total);
        for i in 0..total {
            let (r, c) = (i / n, i % n);
            let nbrs = triangular_neighbors(r, c, n);
            let mut flat = [0usize; NUM_NEIGHBORS];
            for (k, &(nr, nc)) in nbrs.iter().enumerate() {
                flat[k] = nr * n + nc;
            }
            neighbor_indices.push(flat);
        }
        // Pre-compute round constants: barrett_reduce_unsigned((i as u64) * 2654435761)
        let round_constants: Vec<u16> = (0..total)
            .map(|i| barrett_reduce_unsigned((i as u64).wrapping_mul(2654435761)))
            .collect();
        Self {
            n,
            q: params.q,
            spins: vec![0; total],
            couplings: vec![0; total * NUM_NEIGHBORS],
            neighbor_indices,
            round_constants,
            scratch: vec![0u16; total],
        }
    }

    /// Deterministically seed spin values and couplings from raw bytes.
    ///
    /// Uses FNV-1a to hash the input into a 64-bit seed, then SplitMix64
    /// to expand it across every spin and coupling.
    ///
    /// **Note:** FNV-1a and SplitMix64 are fast non-cryptographic
    /// functions. This is acceptable here because the seeding only
    /// sets initial lattice state and coupling constants — it is not
    /// used to derive key material. Cryptographic entropy enters
    /// through `getrandom` in the KEM and PAKE layers.
    pub fn seed_from_bytes(&mut self, data: &[u8]) {
        // FNV-1a hash of input → 64-bit seed
        let mut hash: u64 = 0xcbf29ce484222325;
        for &byte in data {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }

        let mut state = hash;

        for spin in &mut self.spins {
            *spin = barrett_reduce_unsigned(splitmix64(&mut state));
        }
        for coupling in &mut self.couplings {
            *coupling = barrett_reduce_unsigned(splitmix64(&mut state));
        }
    }

    /// Current spin configuration.
    pub fn spins(&self) -> &[u16] {
        &self.spins
    }

    /// Overwrite the spin configuration.
    pub fn set_spins(&mut self, spins: &[u16]) {
        assert_eq!(spins.len(), self.n * self.n, "spin vector length mismatch");
        self.spins.copy_from_slice(spins);
    }

    /// Borrow the coupling constants.
    pub fn couplings(&self) -> &[u16] {
        &self.couplings
    }

    /// Mutably borrow the coupling constants.
    pub fn couplings_mut(&mut self) -> &mut [u16] {
        &mut self.couplings
    }

    /// Execute one synchronous update step across all spins.
    ///
    /// For each spin *i*:
    /// 1. Compute effective field `h_eff = Σ_j J_ij · σ_j  (mod q)`
    /// 2. Mix: `t = h_eff + σ_i + rc_i  (mod q)`
    /// 3. S-box (nonlinearity): `σ_i' = t³  (mod q)`
    ///
    /// All updates are synchronous (computed from the previous state).
    /// Uses `black_box` barriers to prevent compiler-driven timing leaks —
    /// use [`step_fast`] when output is public (e.g. PRNG squeeze).
    #[inline(never)]
    pub fn step(&mut self) {
        let total = self.n * self.n;

        for i in 0..total {
            let nbrs = &self.neighbor_indices[i];

            // Effective field: linear mixing with neighbours.
            // black_box on each accumulation step prevents the compiler from
            // reordering or vectorizing in ways that could leak secret spin values.
            let mut h_eff: u64 = 0;
            for k in 0..NUM_NEIGHBORS {
                let j = nbrs[k];
                h_eff = black_box(barrett_reduce_unsigned(
                    h_eff + self.couplings[i * NUM_NEIGHBORS + k] as u64 * self.spins[j] as u64,
                ) as u64);
            }

            // Round constant (pre-computed).
            let rc = self.round_constants[i] as u64;
            let mixed =
                black_box(barrett_reduce_unsigned(h_eff + self.spins[i] as u64 + rc)) as u64;

            // Nonlinear S-box: cubing in Z_q (a permutation since gcd(3, q-1)=1).
            // black_box around each intermediate prevents the compiler from fusing
            // branch prediction or algebraic simplifications that could leak timing.
            let sq = barrett_reduce_unsigned(black_box(mixed) * black_box(mixed)) as u64;
            let cube = barrett_reduce_unsigned(black_box(sq) * black_box(mixed)) as u64;
            self.scratch[i] = black_box(cube) as u16;
        }

        std::mem::swap(&mut self.spins, &mut self.scratch);
    }

    /// Fast variant of [`step`] without `black_box` timing barriers.
    ///
    /// Produces identical mathematical results but allows the compiler
    /// to vectorize, reorder, and fully optimize the inner loop.
    /// **Must only be used when the lattice output is public** (e.g.
    /// PRNG byte-stream generation), never for secret key material.
    ///
    /// Performance optimisations vs [`step`]:
    /// - No `black_box` barriers → compiler can vectorize and reorder
    /// - Batch-accumulates all 6 neighbor products before reducing
    ///   (each product < Q² ≈ 11M, sum of 6 < 67M < 2^27)
    /// - Uses [`barrett_reduce_small`] (single 64-bit multiply) instead
    ///   of `barrett_reduce_unsigned` (u128 two-step)
    /// - Pre-computed round constants and neighbor indices
    #[inline(never)]
    pub fn step_fast(&mut self) {
        let total = self.n * self.n;
        let spins = &self.spins;
        let couplings = &self.couplings;

        for i in 0..total {
            let nbrs = &self.neighbor_indices[i];
            let coupling_base = i * NUM_NEIGHBORS;

            // Accumulate h_eff as sum of 6 products.
            // Each product: coupling[k] * spin[j] < 3329 × 3329 = 11_082_241
            // Sum of 6: < 6 × 11_082_241 = 66_493_446 < 2^27 = 134_217_728
            let mut h_acc: u32 = 0;
            for k in 0..NUM_NEIGHBORS {
                h_acc += couplings[coupling_base + k] as u32 * spins[nbrs[k]] as u32;
            }
            // Single Barrett reduce of the entire sum.
            let h_eff = barrett_reduce_small(h_acc) as u32;

            // Round constant: pre-reduced.
            let rc = self.round_constants[i] as u32;

            // Mix: h_eff + spin[i] + rc < 3329 × 3 = 9987 < 2^27
            let mixed = barrett_reduce_small(h_eff + spins[i] as u32 + rc) as u32;

            // S-box: cube mod q. mixed < 3329, sq = mixed² < 3329² = 11_082_241 < 2^27
            let sq = barrett_reduce_small(mixed * mixed) as u32;
            // cube: sq * mixed < 3329 × 3329 < 2^27
            let cube = barrett_reduce_small(sq * mixed);
            self.scratch[i] = cube;
        }

        std::mem::swap(&mut self.spins, &mut self.scratch);
    }

    /// Execute `rounds` update steps (constant-time, for secret data).
    pub fn run(&mut self, rounds: usize) {
        for _ in 0..rounds {
            self.step();
        }
    }

    /// Execute `rounds` fast update steps (public data only — see [`step_fast`]).
    pub fn run_fast(&mut self, rounds: usize) {
        for _ in 0..rounds {
            self.step_fast();
        }
    }

    /// Compute the Hamiltonian H(σ) of the current configuration.
    ///
    /// `H(σ) = −Σ_{(i,j)} J_ij · σ_i · σ_j  (mod q)`
    ///
    /// Each undirected edge is counted once (when `i < j`).
    pub fn energy(&self) -> i64 {
        let total = self.n * self.n;
        let mut energy: i64 = 0;

        for i in 0..total {
            let nbrs = &self.neighbor_indices[i];
            for k in 0..NUM_NEIGHBORS {
                let j = nbrs[k];
                if i < j {
                    let t = barrett_reduce_unsigned(
                        black_box(self.couplings[i * NUM_NEIGHBORS + k] as u64)
                            * black_box(self.spins[i] as u64),
                    ) as u64;
                    let contrib = barrett_reduce_unsigned(t * black_box(self.spins[j] as u64));
                    energy = energy.wrapping_sub(black_box(contrib) as i64);
                }
            }
        }
        energy
    }

    pub fn lattice_side(&self) -> usize {
        self.n
    }

    pub fn field_modulus(&self) -> u16 {
        self.q
    }
}
