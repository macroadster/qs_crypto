//! Spin glass lattice engine.
//!
//! Models a generalized Potts system on a triangular lattice over Z_q
//! with toroidal boundary conditions. The triangular topology introduces
//! geometric frustration — the foundation of spin glass hardness.
//!
//! Update rule (synchronous, per round):
//! ```text
//!   h_eff(i) = Σ_j  J_ij · σ_j              (mod q)
//!   σ_i'     = (h_eff(i) + σ_i + rc_i)³     (mod q)
//! ```

use crate::params::Params;

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
}

impl SpinLattice {
    /// Create a new lattice from the given parameter set.
    /// All spins initialize to zero; couplings are unset.
    pub fn new(params: &Params) -> Self {
        let n = params.lattice_side;
        let total = n * n;
        Self {
            n,
            q: params.q,
            spins: vec![0; total],
            couplings: vec![0; total * NUM_NEIGHBORS],
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

        let q = self.q as u64;
        let mut state = hash;

        for spin in &mut self.spins {
            *spin = (splitmix64(&mut state) % q) as u16;
        }
        for coupling in &mut self.couplings {
            *coupling = (splitmix64(&mut state) % q) as u16;
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
    pub fn step(&mut self) {
        let n = self.n;
        let q = self.q as u64;
        let total = n * n;
        let mut new_spins = vec![0u16; total];

        for (i, out) in new_spins.iter_mut().enumerate() {
            let (r, c) = (i / n, i % n);
            let nbrs = triangular_neighbors(r, c, n);

            // Effective field: linear mixing with neighbours
            let mut h_eff: u64 = 0;
            for (k, &(nr, nc)) in nbrs.iter().enumerate() {
                let j = nr * n + nc;
                h_eff = (h_eff
                    + self.couplings[i * NUM_NEIGHBORS + k] as u64 * self.spins[j] as u64)
                    % q;
            }

            // Position-dependent round constant (breaks spatial symmetry)
            let rc = (i as u64).wrapping_mul(2654435761) % q;

            // Mix current spin + effective field + round constant
            let mixed = (h_eff + self.spins[i] as u64 + rc) % q;

            // Nonlinear S-box: cubing in Z_q (a permutation since gcd(3, q-1)=1)
            let sq = mixed * mixed % q;
            let cube = sq * mixed % q;
            *out = cube as u16;
        }

        self.spins = new_spins;
    }

    /// Execute `rounds` update steps.
    pub fn run(&mut self, rounds: usize) {
        for _ in 0..rounds {
            self.step();
        }
    }

    /// Compute the Hamiltonian H(σ) of the current configuration.
    ///
    /// `H(σ) = −Σ_{(i,j)} J_ij · σ_i · σ_j  (mod q)`
    ///
    /// Each undirected edge is counted once (when `i < j`).
    pub fn energy(&self) -> i64 {
        let n = self.n;
        let q = self.q as u64;
        let total = n * n;
        let mut energy: i64 = 0;

        for i in 0..total {
            let (r, c) = (i / n, i % n);
            let nbrs = triangular_neighbors(r, c, n);
            for (k, &(nr, nc)) in nbrs.iter().enumerate() {
                let j = nr * n + nc;
                if i < j {
                    let contrib =
                        self.couplings[i * NUM_NEIGHBORS + k] as u64 * self.spins[i] as u64 % q
                            * self.spins[j] as u64
                            % q;
                    energy = energy.wrapping_sub(contrib as i64);
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
