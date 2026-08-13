//! Product lattice adapter (`qs_crypto::SpinLattice`) behind feature `spin-lattice`.
//!
//! Sample = domain-separated SHAKE of post-evolution spins. Timing never enters
//! the seed path (S3). Uses `run_fast` because sample bytes are research-public
//! here (PRNG-seed material after isolation gate), not secret lattice keys.

use crate::{
    absorb_lp, parse_rounds, EvolutionSpec, Result, SpinBackend, SpinBackendError, SpinSample,
};
use qs_crypto::core::lattice::SpinLattice;
use qs_crypto::params::{Params, SecurityLevel};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

/// Wrap [`SpinLattice`] as a [`SpinBackend`].
///
/// Defaults to QS128 for research speed; override via constructor.
pub struct SpinLatticeBackend {
    level: SecurityLevel,
    lattice: Option<SpinLattice>,
    rounds: usize,
    prepared: bool,
    evolved: bool,
}

impl Default for SpinLatticeBackend {
    fn default() -> Self {
        Self::new(SecurityLevel::QS128)
    }
}

impl SpinLatticeBackend {
    pub fn new(level: SecurityLevel) -> Self {
        Self {
            level,
            lattice: None,
            rounds: 0,
            prepared: false,
            evolved: false,
        }
    }

    pub fn security_level(&self) -> SecurityLevel {
        self.level
    }
}

impl SpinBackend for SpinLatticeBackend {
    fn backend_id(&self) -> &str {
        match self.level {
            SecurityLevel::QS128 => "classical-spinlattice-qs128-v1",
            SecurityLevel::QS192 => "classical-spinlattice-qs192-v1",
            SecurityLevel::QS256 => "classical-spinlattice-qs256-v1",
        }
    }

    fn prepare(&mut self, spec: &EvolutionSpec, secret: &[u8]) -> Result<()> {
        let params = Params::from_security_level(self.level);
        let default_rounds = params.permutation_rounds;
        self.rounds = parse_rounds(&spec.schedule_id, default_rounds);

        let mut lattice = SpinLattice::new(&params);
        // Seed from secret ‖ program_hash so program identity affects state.
        let mut seed_mat = Vec::with_capacity(secret.len() + 32);
        seed_mat.extend_from_slice(secret);
        seed_mat.extend_from_slice(&spec.program_hash);
        lattice.seed_from_bytes(&seed_mat);

        self.lattice = Some(lattice);
        self.prepared = true;
        self.evolved = false;
        Ok(())
    }

    fn evolve(&mut self) -> Result<()> {
        if !self.prepared {
            return Err(SpinBackendError::NotPrepared);
        }
        let lattice = self
            .lattice
            .as_mut()
            .ok_or(SpinBackendError::NotPrepared)?;
        // Public sample path → fast steps (identical math, no black_box tax).
        lattice.run_fast(self.rounds);
        self.evolved = true;
        Ok(())
    }

    fn measure(&mut self) -> Result<SpinSample> {
        if !self.prepared || !self.evolved {
            return Err(SpinBackendError::NotPrepared);
        }
        let lattice = self
            .lattice
            .as_ref()
            .ok_or(SpinBackendError::NotPrepared)?;
        let spins = lattice.spins();
        let mut raw = Vec::with_capacity(spins.len() * 2);
        for &s in spins {
            raw.extend_from_slice(&s.to_le_bytes());
        }
        let mut h = Shake256::default();
        h.update(b"spinlattice-sample-v1");
        absorb_lp(&mut h, &raw);
        let mut bytes = vec![0u8; 32];
        h.finalize_xof().read(&mut bytes);
        Ok(SpinSample { bytes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        derive_spinprng_seed, isolation_session, EnvelopeGate, EvolutionMode, EvolutionSpec,
        FixedMeter, IsolationProfile, IsolationVerdict, ReleasePolicy,
    };

    fn lattice_spec() -> EvolutionSpec {
        EvolutionSpec {
            backend_id: "classical-spinlattice-qs128-v1".into(),
            program_hash: [9u8; 32],
            schedule_id: "rounds=8".into(),
            mode: EvolutionMode::DeterministicClassical,
        }
    }

    #[test]
    fn lattice_determinism() {
        let spec = lattice_spec();
        let secret = b"lattice-secret";
        let mut a = SpinLatticeBackend::default();
        let mut b = SpinLatticeBackend::default();
        a.prepare(&spec, secret).unwrap();
        b.prepare(&spec, secret).unwrap();
        a.evolve().unwrap();
        b.evolve().unwrap();
        assert_eq!(a.measure().unwrap(), b.measure().unwrap());
    }

    #[test]
    fn lattice_secret_sensitivity() {
        let spec = lattice_spec();
        let mut a = SpinLatticeBackend::default();
        let mut b = SpinLatticeBackend::default();
        a.prepare(&spec, b"aaa").unwrap();
        b.prepare(&spec, b"bbb").unwrap();
        a.evolve().unwrap();
        b.evolve().unwrap();
        assert_ne!(a.measure().unwrap(), b.measure().unwrap());
    }

    #[test]
    fn lattice_seed_hygiene_ignores_timing() {
        let spec = lattice_spec();
        let mut backend = SpinLatticeBackend::default();
        let mut meter = FixedMeter { wall_ns: 100 };
        let gate = EnvelopeGate;
        let profile = IsolationProfile {
            spec_fingerprint: spec.fingerprint(),
            baseline_p50_ns: 1000,
            baseline_p95_ns: 5000,
            baseline_iqr_ns: 500,
            margin_ns: 1000,
            iqr_factor: 0.0,
        };
        let q1 = isolation_session(
            &mut backend,
            &mut meter,
            &gate,
            &spec,
            b"stable",
            &profile,
            ReleasePolicy::Abort,
        )
        .unwrap();
        let mut backend2 = SpinLatticeBackend::default();
        let mut meter2 = FixedMeter {
            wall_ns: 9_999_999,
        };
        // Inflated timing but still under p95+huge margin? Use loose p95 so Clean.
        let profile2 = IsolationProfile {
            spec_fingerprint: spec.fingerprint(),
            baseline_p50_ns: 1,
            baseline_p95_ns: u128::MAX / 4,
            baseline_iqr_ns: 0,
            margin_ns: 0,
            iqr_factor: 0.0,
        };
        let q2 = isolation_session(
            &mut backend2,
            &mut meter2,
            &gate,
            &spec,
            b"stable",
            &profile2,
            ReleasePolicy::Abort,
        )
        .unwrap();
        assert_eq!(q1.bytes, q2.bytes);
        assert!(q1.isolation && q2.isolation);
        assert_eq!(q1.verdict, IsolationVerdict::Clean);
        // Also equal to direct derive from same sample path
        let mut b3 = SpinLatticeBackend::default();
        b3.prepare(&spec, b"stable").unwrap();
        b3.evolve().unwrap();
        let sample = b3.measure().unwrap();
        assert_eq!(q1.bytes, derive_spinprng_seed(&spec, &sample));
    }
}
