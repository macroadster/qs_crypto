//! Vendor-neutral quantum device surface (research).
//!
//! Real cloud/on-prem QPUs implement [`QuantumDevice`]. Research code stays on
//! [`SpinBackend`] via [`DeviceSpinBackend`], which never puts queue/fidelity
//! into the hardness seed (S1/S3).
//!
//! ```text
//! QuantumDevice::run_job  →  QuantumJobResult { histogram, stats }
//! DeviceSpinBackend       →  SpinBackend (prepare/evolve/measure)
//! derive_spinprng_seed    ←  histogram only (not JobStats)
//! ```

use crate::{
    absorb_lp, parse_schedule_u64, parse_shots, quantum_backend::JobStats, EvolutionSpec, Result,
    SpinBackend, SpinBackendError, SpinSample,
};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use std::hint::black_box;
use std::thread;
use std::time::Duration;

/// Job submitted to a quantum device / simulator.
#[derive(Clone, Debug)]
pub struct QuantumJobRequest {
    pub program_hash: [u8; 32],
    pub schedule_id: String,
    pub shots: u32,
    pub bins: usize,
    /// Simulated or requested queue budget (ms); vendors may ignore.
    pub queue_ms: u32,
    /// Domain material for deterministic sims (not sent to real hardware as-is).
    pub secret_domain: Vec<u8>,
    pub physical_noise: bool,
}

/// Result of a completed job (crypto channel = histogram; observer = stats).
#[derive(Clone, Debug)]
pub struct QuantumJobResult {
    pub histogram: Vec<u32>,
    pub stats: JobStats,
}

/// Vendor / simulator capability.
pub trait QuantumDevice {
    fn device_id(&self) -> &str;

    /// Submit circuit/program and gather shot outcomes.
    fn run_job(&mut self, req: &QuantumJobRequest) -> Result<QuantumJobResult>;
}

// ---------------------------------------------------------------------------
// Simulated device (local CPU histogram)
// ---------------------------------------------------------------------------

/// Local shot simulator used by research demos (no network, no QPU).
#[derive(Clone, Debug)]
pub struct SimulatedQuantumDevice {
    physical_noise_default: bool,
    job_counter: u64,
}

impl Default for SimulatedQuantumDevice {
    fn default() -> Self {
        Self {
            physical_noise_default: false,
            job_counter: 0,
        }
    }
}

impl SimulatedQuantumDevice {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_physical_noise(mut self, on: bool) -> Self {
        self.physical_noise_default = on;
        self
    }
}

impl QuantumDevice for SimulatedQuantumDevice {
    fn device_id(&self) -> &str {
        "qpu-sim-device-v1"
    }

    fn run_job(&mut self, req: &QuantumJobRequest) -> Result<QuantumJobResult> {
        if req.queue_ms > 0 {
            thread::sleep(Duration::from_millis(req.queue_ms as u64));
        }

        self.job_counter = self.job_counter.wrapping_add(1);
        let job_id = format!("qsim-{}", self.job_counter);
        let noise = req.physical_noise || self.physical_noise_default;
        let bins = req.bins.clamp(2, 256);
        let shots = req.shots.max(1) as usize;

        let mut hist = vec![0u32; bins];
        let mut fidelity_acc: u64 = 0;

        for i in 0..shots {
            let mut h = Shake256::default();
            h.update(b"qpu-sim-shot-v1");
            absorb_lp(&mut h, &req.secret_domain);
            absorb_lp(&mut h, &req.program_hash);
            absorb_lp(&mut h, req.schedule_id.as_bytes());
            h.update(&(i as u64).to_le_bytes());
            let mut out = [0u8; 16];
            h.finalize_xof().read(&mut out);

            if noise {
                let mut n = [0u8; 8];
                let _ = getrandom::getrandom(&mut n);
                for (a, b) in out.iter_mut().zip(n.iter().cycle()) {
                    *a ^= *b;
                }
            }

            let bin = (u64::from_le_bytes(out[0..8].try_into().unwrap()) as usize) % bins;
            hist[bin] = hist[bin].saturating_add(1);
            fidelity_acc = fidelity_acc.wrapping_add(out[8] as u64);
            black_box(bin);
        }

        let fidelity_proxy = ((fidelity_acc / shots as u64) as f32) / 255.0;
        Ok(QuantumJobResult {
            histogram: hist,
            stats: JobStats {
                queue_ms: req.queue_ms,
                shot_count: shots as u32,
                fidelity_proxy,
                job_id,
            },
        })
    }
}

// ---------------------------------------------------------------------------
// Vendor stub (documents integration surface; always errors until configured)
// ---------------------------------------------------------------------------

/// Placeholder for a real cloud/on-prem backend (IBM, IonQ, Braket, …).
///
/// Implements the trait so call sites can be written before credentials exist.
#[derive(Clone, Debug, Default)]
pub struct VendorStubDevice {
    pub vendor_name: String,
}

impl VendorStubDevice {
    pub fn new(vendor_name: impl Into<String>) -> Self {
        Self {
            vendor_name: vendor_name.into(),
        }
    }
}

impl QuantumDevice for VendorStubDevice {
    fn device_id(&self) -> &str {
        "qpu-vendor-stub-v1"
    }

    fn run_job(&mut self, _req: &QuantumJobRequest) -> Result<QuantumJobResult> {
        let _ = &self.vendor_name;
        Err(SpinBackendError::Backend(
            "VendorStubDevice: no real QPU configured (research stub only)",
        ))
    }
}

// ---------------------------------------------------------------------------
// SpinBackend adapter over any QuantumDevice
// ---------------------------------------------------------------------------

/// Adapts a [`QuantumDevice`] into the isolation [`SpinBackend`] pipeline.
#[derive(Clone, Debug)]
pub struct DeviceSpinBackend<D: QuantumDevice> {
    device: D,
    backend_id_override: Option<String>,
    prepared: bool,
    evolved: bool,
    secret: Vec<u8>,
    program_hash: [u8; 32],
    schedule_id: String,
    shots: u32,
    queue_ms: u32,
    bins: usize,
    physical_noise: bool,
    last_result: Option<QuantumJobResult>,
}

impl<D: QuantumDevice> DeviceSpinBackend<D> {
    pub fn new(device: D) -> Self {
        Self {
            device,
            backend_id_override: None,
            prepared: false,
            evolved: false,
            secret: Vec::new(),
            program_hash: [0u8; 32],
            schedule_id: String::new(),
            shots: 1024,
            queue_ms: 0,
            bins: 16,
            physical_noise: false,
            last_result: None,
        }
    }

    /// Override `backend_id` in EvolutionSpec seed domain (default: device_id).
    pub fn with_backend_id(mut self, id: impl Into<String>) -> Self {
        self.backend_id_override = Some(id.into());
        self
    }

    pub fn with_physical_noise(mut self, on: bool) -> Self {
        self.physical_noise = on;
        self
    }

    pub fn device(&self) -> &D {
        &self.device
    }

    pub fn device_mut(&mut self) -> &mut D {
        &mut self.device
    }

    pub fn last_job_stats(&self) -> Option<&JobStats> {
        self.last_result.as_ref().map(|r| &r.stats)
    }

    pub fn histogram(&self) -> Option<&[u32]> {
        self.last_result.as_ref().map(|r| r.histogram.as_slice())
    }
}

impl<D: QuantumDevice> SpinBackend for DeviceSpinBackend<D> {
    fn backend_id(&self) -> &str {
        self.backend_id_override
            .as_deref()
            .unwrap_or_else(|| self.device.device_id())
    }

    fn prepare(&mut self, spec: &EvolutionSpec, secret: &[u8]) -> Result<()> {
        self.secret = secret.to_vec();
        self.program_hash = spec.program_hash;
        self.schedule_id = spec.schedule_id.clone();
        self.shots = parse_shots(&spec.schedule_id, 1024).max(1) as u32;
        self.queue_ms =
            parse_schedule_u64(&spec.schedule_id, "queue_ms", 0).min(u32::MAX as u64) as u32;
        self.bins = parse_schedule_u64(&spec.schedule_id, "bins", self.bins as u64) as usize;
        self.bins = self.bins.clamp(2, 256);
        self.prepared = true;
        self.evolved = false;
        self.last_result = None;
        Ok(())
    }

    fn evolve(&mut self) -> Result<()> {
        if !self.prepared {
            return Err(SpinBackendError::NotPrepared);
        }
        let req = QuantumJobRequest {
            program_hash: self.program_hash,
            schedule_id: self.schedule_id.clone(),
            shots: self.shots,
            bins: self.bins,
            queue_ms: self.queue_ms,
            secret_domain: self.secret.clone(),
            physical_noise: self.physical_noise,
        };
        let result = self.device.run_job(&req)?;
        self.last_result = Some(result);
        self.evolved = true;
        Ok(())
    }

    fn measure(&mut self) -> Result<SpinSample> {
        if !self.prepared || !self.evolved {
            return Err(SpinBackendError::NotPrepared);
        }
        let result = self
            .last_result
            .as_ref()
            .ok_or(SpinBackendError::NotPrepared)?;
        Ok(sample_from_histogram(
            &self.secret,
            &self.program_hash,
            &result.histogram,
        ))
    }
}

/// Crypto-channel extractor: histogram only (S3/S4).
pub fn sample_from_histogram(
    secret: &[u8],
    program_hash: &[u8; 32],
    histogram: &[u32],
) -> SpinSample {
    let mut h = Shake256::default();
    h.update(b"qpu-sim-sample-v1");
    absorb_lp(&mut h, secret);
    absorb_lp(&mut h, program_hash);
    h.update(&(histogram.len() as u64).to_le_bytes());
    for &c in histogram {
        h.update(&c.to_le_bytes());
    }
    let mut bytes = vec![0u8; 32];
    h.finalize_xof().read(&mut bytes);
    SpinSample { bytes }
}

/// Convenience: simulated device already labeled as research SpinBackend id.
pub type QuantumSimBackend = DeviceSpinBackend<SimulatedQuantumDevice>;

impl QuantumSimBackend {
    pub fn simulated() -> Self {
        // Keep backend_id stable with earlier research (`qpu-sim-v1`).
        DeviceSpinBackend::new(SimulatedQuantumDevice::default()).with_backend_id("qpu-sim-v1")
    }
}

impl Default for QuantumSimBackend {
    fn default() -> Self {
        Self::simulated()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        derive_spinprng_seed, isolation_session, EnvelopeGate, EvolutionMode, EvolutionSpec,
        FixedMeter, IsolationProfile, ReleasePolicy,
    };

    fn spec() -> EvolutionSpec {
        EvolutionSpec {
            backend_id: "qpu-sim-v1".into(),
            program_hash: [0x51; 32],
            schedule_id: "shots=128,queue_ms=0,bins=8".into(),
            mode: EvolutionMode::PhysicalShots,
        }
    }

    #[test]
    fn device_adapter_matches_sample_extractor() {
        let mut backend = QuantumSimBackend::default();
        let s = spec();
        backend.prepare(&s, b"dev").unwrap();
        backend.evolve().unwrap();
        let sample = backend.measure().unwrap();
        let hist = backend.histogram().unwrap();
        assert_eq!(
            sample,
            sample_from_histogram(b"dev", &s.program_hash, hist)
        );
    }

    #[test]
    fn vendor_stub_errors() {
        let mut backend = DeviceSpinBackend::new(VendorStubDevice::new("example-vendor"));
        let s = spec();
        backend.prepare(&s, b"x").unwrap();
        assert!(matches!(
            backend.evolve(),
            Err(SpinBackendError::Backend(_))
        ));
    }

    #[test]
    fn device_seed_stable_session() {
        let mut backend = QuantumSimBackend::default();
        let s = spec();
        let profile = IsolationProfile {
            spec_fingerprint: s.fingerprint(),
            baseline_p50_ns: 1,
            baseline_p95_ns: u128::MAX / 4,
            baseline_iqr_ns: 0,
            margin_ns: 0,
            iqr_factor: 0.0,
        };
        let q = isolation_session(
            &mut backend,
            &mut FixedMeter { wall_ns: 10 },
            &EnvelopeGate,
            &s,
            b"stable",
            &profile,
            ReleasePolicy::Abort,
        )
        .unwrap();
        assert!(q.isolation);
        let mut b2 = QuantumSimBackend::default();
        b2.prepare(&s, b"stable").unwrap();
        b2.evolve().unwrap();
        let sample = b2.measure().unwrap();
        assert_eq!(q.bytes, derive_spinprng_seed(&s, &sample));
    }
}
