//! Work-scaled classical mock — deterministic sample + tunable CPU burn.
//!
//! Used for empirical isolation-gate experiments without linking product
//! `qs_crypto`. Sample bytes are independent of how long `evolve` burns (S1).

use crate::{
    absorb_lp, absorb_str, parse_rounds, EvolutionSpec, Result, SpinBackend, SpinBackendError,
    SpinSample,
};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use std::hint::black_box;

/// Deterministic sample + `rounds` of SHAKE work in `evolve`.
///
/// `schedule_id` may contain `rounds=N` (default 50_000).
#[derive(Default)]
pub struct BusyMockBackend {
    prepared: bool,
    evolved: bool,
    secret: Vec<u8>,
    program_hash: [u8; 32],
    schedule_id: String,
    rounds: usize,
}

impl BusyMockBackend {
    pub fn with_default_rounds(rounds: usize) -> Self {
        Self {
            rounds,
            ..Default::default()
        }
    }
}

impl SpinBackend for BusyMockBackend {
    fn backend_id(&self) -> &str {
        "busy-mock-v1"
    }

    fn prepare(&mut self, spec: &EvolutionSpec, secret: &[u8]) -> Result<()> {
        self.secret = secret.to_vec();
        self.program_hash = spec.program_hash;
        self.schedule_id = spec.schedule_id.clone();
        // Prefer schedule_id rounds=; else constructor default.
        let parsed = parse_rounds(&spec.schedule_id, 0);
        if parsed > 0 {
            self.rounds = parsed;
        } else if self.rounds == 0 {
            self.rounds = 50_000;
        }
        self.prepared = true;
        self.evolved = false;
        Ok(())
    }

    fn evolve(&mut self) -> Result<()> {
        if !self.prepared {
            return Err(SpinBackendError::NotPrepared);
        }
        // CPU burn that does not feed the sample path.
        let mut acc = [0u8; 32];
        for i in 0..self.rounds {
            let mut h = Shake256::default();
            h.update(b"busy-mock-burn-v1");
            h.update(&i.to_le_bytes());
            h.update(black_box(&acc));
            h.finalize_xof().read(&mut acc);
            black_box(acc);
        }
        self.evolved = true;
        Ok(())
    }

    fn measure(&mut self) -> Result<SpinSample> {
        if !self.prepared || !self.evolved {
            return Err(SpinBackendError::NotPrepared);
        }
        // Sample depends only on secret + program + schedule string — not burn count
        // as a timing field, and not wall_ns. (Rounds in schedule_id are part of the
        // evolution program identity, so they *are* in the domain.)
        let mut h = Shake256::default();
        h.update(b"busy-mock-sample-v1");
        absorb_lp(&mut h, &self.secret);
        absorb_lp(&mut h, &self.program_hash);
        absorb_str(&mut h, &self.schedule_id);
        let mut bytes = vec![0u8; 32];
        h.finalize_xof().read(&mut bytes);
        Ok(SpinSample { bytes })
    }
}
