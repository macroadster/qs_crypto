//! Quantum job backend sketch (research simulation — no real QPU).
//!
//! Device trait + sim live in [`crate::quantum_device`]. This module keeps the
//! original [`JobStats`] type and re-exports the stable research surface.
//!
//! ```text
//! prepare  → build job (circuit/program id + secret domain)
//! evolve   → QuantumDevice::run_job (queue + shots)
//! measure  → extractor on shot histogram → SpinSample
//! ```
//!
//! - **Crypto channel:** histogram → SHAKE sample (S4). Never queue/wall (S3).
//! - **Observer channel:** external wall meter + [`JobStats`].
//!
//! This is **not** a claim of QKD, device-independent crypto, or IND-CPA from
//! timing. Isolation remains a heuristic sensor (S2).

use crate::{EvolutionMode, EvolutionSpec};

/// Public-safe job metadata (observer channel). Never absorb into SpinPRNG seed.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct JobStats {
    pub queue_ms: u32,
    pub shot_count: u32,
    /// Research proxy in \[0, 1\].
    pub fidelity_proxy: f32,
    pub job_id: String,
}

pub use crate::quantum_device::{
    sample_from_histogram, DeviceSpinBackend, QuantumDevice, QuantumJobRequest, QuantumJobResult,
    QuantumSimBackend, SimulatedQuantumDevice, VendorStubDevice,
};

/// Helper: recommended EvolutionSpec for the simulator.
pub fn quantum_sim_spec(shots: usize, queue_ms: u32, program_hash: [u8; 32]) -> EvolutionSpec {
    EvolutionSpec {
        backend_id: "qpu-sim-v1".into(),
        program_hash,
        schedule_id: format!("shots={shots},queue_ms={queue_ms},bins=16"),
        mode: EvolutionMode::PhysicalShots,
    }
}
