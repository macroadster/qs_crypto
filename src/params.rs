/// Prime field modulus shared by all parameter sets.
/// Matches Kyber (ML-KEM) for compatibility with existing noise analysis.
pub const FIELD_MODULUS: u16 = 3329;

/// Target security level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    /// 128-bit security — 12×12 lattice (144 spins)
    QS128,
    /// 192-bit security — 14×14 lattice (196 spins)
    QS192,
    /// 256-bit security — 16×16 lattice (256 spins), default
    QS256,
}

impl SecurityLevel {
    pub fn to_byte(self) -> u8 {
        match self {
            SecurityLevel::QS128 => 0x01,
            SecurityLevel::QS192 => 0x02,
            SecurityLevel::QS256 => 0x03,
        }
    }

    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(SecurityLevel::QS128),
            0x02 => Some(SecurityLevel::QS192),
            0x03 => Some(SecurityLevel::QS256),
            _ => None,
        }
    }
}

/// Complete parameter set governing all layers of the library.
#[derive(Debug, Clone)]
pub struct Params {
    pub security_level: SecurityLevel,
    /// Prime field modulus (3329)
    pub q: u16,
    /// Lattice side length (n)
    pub lattice_side: usize,
    /// Total spins N = n²
    pub total_spins: usize,
    /// Sponge rate — number of spins exposed during absorb/squeeze
    pub sponge_rate: usize,
    /// Sponge capacity — hidden spins providing security margin
    pub sponge_capacity: usize,
    /// Permutation rounds per sponge invocation (K ≥ 2n)
    pub permutation_rounds: usize,
    /// Centered Binomial Distribution parameter for LWE noise
    pub cbd_eta: u8,
    /// CBD parameter for frustration noise during coupling construction
    pub frustration_eta: u8,
}

impl Params {
    pub fn from_security_level(level: SecurityLevel) -> Self {
        match level {
            SecurityLevel::QS128 => Self {
                security_level: level,
                q: FIELD_MODULUS,
                lattice_side: 12,
                total_spins: 144,
                sponge_rate: 48,
                sponge_capacity: 96,
                permutation_rounds: 24,
                cbd_eta: 2,
                frustration_eta: 3,
            },
            SecurityLevel::QS192 => Self {
                security_level: level,
                q: FIELD_MODULUS,
                lattice_side: 14,
                total_spins: 196,
                sponge_rate: 64,
                sponge_capacity: 132,
                permutation_rounds: 28,
                cbd_eta: 2,
                frustration_eta: 3,
            },
            SecurityLevel::QS256 => Self {
                security_level: level,
                q: FIELD_MODULUS,
                lattice_side: 16,
                total_spins: 256,
                sponge_rate: 64,
                sponge_capacity: 192,
                permutation_rounds: 32,
                cbd_eta: 2,
                frustration_eta: 3,
            },
        }
    }
}

impl Params {
    /// Number of random coin bytes used internally by the KEM FO transform.
    pub fn coin_bytes(&self) -> usize {
        match self.security_level {
            SecurityLevel::QS128 => 16,
            SecurityLevel::QS192 => 24,
            SecurityLevel::QS256 => 32,
        }
    }
}

impl Default for Params {
    fn default() -> Self {
        Self::from_security_level(SecurityLevel::QS256)
    }
}
