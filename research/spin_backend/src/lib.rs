//! Research interfaces: SpinBackend + ObserverMeter + IsolationGate.
//!
//! # Rules (see OBSERVER_ISOLATION.md)
//! - **S1:** Timing/jitter is a meter for substrate observers, not key material.
//! - **S3:** SpinPRNG seed derivation never includes [`TimingReport`] for hardness.
//! - **S4:** Only [`SpinSample`] feeds the hardness seed path.
//! - **S5:** Network MITM ≠ process observer.
//!
//! Product `qs_crypto::SpinPrng` can consume [`QualifiedSeed::bytes`] later;
//! this crate does not depend on `qs_crypto` yet.

#![forbid(unsafe_code)]

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use std::time::Instant;

// ---------------------------------------------------------------------------
// Hash helpers — length-prefixed absorbs (avoid field concatenation ambiguity)
// ---------------------------------------------------------------------------

/// Absorb `data` as `u64le(len) ‖ data`.
fn absorb_lp(h: &mut impl Update, data: &[u8]) {
    h.update(&(data.len() as u64).to_le_bytes());
    h.update(data);
}

/// Absorb a UTF-8 string length-prefixed.
fn absorb_str(h: &mut impl Update, s: &str) {
    absorb_lp(h, s.as_bytes());
}

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// How reproducible the backend is expected to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvolutionMode {
    /// Same secret+spec ⇒ same SpinSample (classical / Trin deterministic).
    DeterministicClassical,
    /// Physical shots / noise; sample not bit-stable.
    PhysicalShots,
}

/// What evolution was scheduled (must be hashed into the seed domain).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvolutionSpec {
    pub backend_id: String,
    /// Hash or stable id of program / lattice params / circuit.
    pub program_hash: [u8; 32],
    /// Free-form schedule id (rounds, shots, …) included in fingerprint.
    pub schedule_id: String,
    pub mode: EvolutionMode,
}

impl EvolutionSpec {
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut h = Shake256::default();
        // Domain label is a fixed string (no length needed); all variable fields use LP.
        h.update(b"qs-evol-spec-v1");
        absorb_str(&mut h, &self.backend_id);
        absorb_lp(&mut h, &self.program_hash);
        absorb_str(&mut h, &self.schedule_id);
        h.update(&[self.mode as u8]);
        let mut out = [0u8; 32];
        h.finalize_xof().read(&mut out);
        out
    }
}

/// Opaque sample that may feed SpinPRNG (crypto channel only).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpinSample {
    pub bytes: Vec<u8>,
}

/// External meter output — never mixed into hardness seed (S1/S3).
#[derive(Clone, Debug)]
pub struct TimingReport {
    pub label: String,
    pub wall_ns: u128,
    /// Optional host load proxy (0 if unused).
    pub load_hint: u32,
}

/// Baseline envelope for isolation checks.
#[derive(Clone, Debug)]
pub struct IsolationProfile {
    pub spec_fingerprint: [u8; 32],
    pub baseline_p50_ns: u128,
    pub baseline_p95_ns: u128,
    pub baseline_iqr_ns: u128,
    /// Absolute slack above p95.
    pub margin_ns: u128,
    /// `iqr_factor * baseline_iqr` allowed; use 0 to ignore IQR rule.
    pub iqr_factor: f64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IsolationVerdict {
    Clean,
    SuspectObserver,
    Inconclusive,
    BackendError,
}

/// What to do when the gate is not Clean.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReleasePolicy {
    /// No seed returned.
    Abort,
    /// Seed from OS entropy; `isolation=false`.
    ReseedOsUnqualified,
    /// Use SpinSample anyway; `isolation=false` (debug only).
    AllowUnqualified,
}

/// Seed material for product SpinPRNG + isolation metadata.
#[derive(Clone, Debug)]
pub struct QualifiedSeed {
    pub bytes: Vec<u8>,
    /// True only if verdict was Clean and sample path was used.
    pub isolation: bool,
    pub verdict: IsolationVerdict,
    pub report: TimingReport,
    pub backend_id: String,
}

#[derive(Debug)]
pub enum SpinBackendError {
    NotPrepared,
    Backend(&'static str),
    /// [`WallClockMeter::stop`] without a matching [`WallClockMeter::start`].
    MeterNotRunning,
    /// OS entropy source failed (unqualified reseed path).
    Entropy(&'static str),
    IsolationAbort {
        verdict: IsolationVerdict,
        report: TimingReport,
    },
}

impl std::fmt::Display for SpinBackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotPrepared => write!(f, "backend not prepared"),
            Self::Backend(s) => write!(f, "backend: {s}"),
            Self::MeterNotRunning => {
                write!(f, "meter stop without start (or double-stop)")
            }
            Self::Entropy(s) => write!(f, "entropy: {s}"),
            Self::IsolationAbort { verdict, report } => {
                write!(
                    f,
                    "isolation abort ({verdict:?}), wall_ns={}",
                    report.wall_ns
                )
            }
        }
    }
}

impl std::error::Error for SpinBackendError {}

pub type Result<T> = std::result::Result<T, SpinBackendError>;

// ---------------------------------------------------------------------------
// Traits
// ---------------------------------------------------------------------------

/// Quantum / Trin / classical evolution backend.
pub trait SpinBackend {
    fn backend_id(&self) -> &str;

    fn prepare(&mut self, spec: &EvolutionSpec, secret: &[u8]) -> Result<()>;

    fn evolve(&mut self) -> Result<()>;

    fn measure(&mut self) -> Result<SpinSample>;
}

/// External wall-clock meter (F1 / S1). Must not alter classical samples.
pub trait ObserverMeter {
    fn start(&mut self, label: &str);

    /// End the interval started by [`ObserverMeter::start`].
    ///
    /// Returns [`SpinBackendError::MeterNotRunning`] if stop is called without a
    /// live start (including double-stop). Implementations must not silently
    /// invent a zero duration.
    fn stop(&mut self, label: &str) -> Result<TimingReport>;
}

pub trait IsolationGate {
    fn gate(&self, report: &TimingReport, profile: &IsolationProfile) -> IsolationVerdict;
}

// ---------------------------------------------------------------------------
// Default meter + gate
// ---------------------------------------------------------------------------

/// Process wall-clock meter around evolve+measure.
#[derive(Default)]
pub struct WallClockMeter {
    start: Option<Instant>,
    label: String,
}

impl ObserverMeter for WallClockMeter {
    fn start(&mut self, label: &str) {
        self.label = label.to_string();
        self.start = Some(Instant::now());
    }

    fn stop(&mut self, label: &str) -> Result<TimingReport> {
        let started = self.start.take().ok_or(SpinBackendError::MeterNotRunning)?;
        let wall_ns = started.elapsed().as_nanos();
        Ok(TimingReport {
            label: if label.is_empty() {
                self.label.clone()
            } else {
                label.to_string()
            },
            wall_ns,
            load_hint: 0,
        })
    }
}

/// Simple p95 + IQR envelope gate.
#[derive(Default)]
pub struct EnvelopeGate;

impl IsolationGate for EnvelopeGate {
    fn gate(&self, report: &TimingReport, profile: &IsolationProfile) -> IsolationVerdict {
        if profile.baseline_p95_ns == 0 && profile.baseline_p50_ns == 0 {
            return IsolationVerdict::Inconclusive;
        }
        let limit = profile.baseline_p95_ns.saturating_add(profile.margin_ns);
        if report.wall_ns > limit {
            return IsolationVerdict::SuspectObserver;
        }
        if profile.iqr_factor > 0.0 && profile.baseline_iqr_ns > 0 {
            // Single-sample proxy: deviation from p50 vs allowed IQR band.
            let dev = report.wall_ns.abs_diff(profile.baseline_p50_ns);
            let allow = (profile.baseline_iqr_ns as f64 * profile.iqr_factor) as u128;
            if dev > allow.saturating_add(profile.margin_ns) {
                return IsolationVerdict::SuspectObserver;
            }
        }
        IsolationVerdict::Clean
    }
}

// ---------------------------------------------------------------------------
// Seed derivation (crypto channel only)
// ---------------------------------------------------------------------------

/// Domain-separated seed bytes from sample — **no timing fields** (S3).
///
/// Encoding: `domain ‖ LP(backend_id) ‖ LP(program_hash) ‖ LP(schedule_id) ‖ LP(sample)`.
pub fn derive_spinprng_seed(spec: &EvolutionSpec, sample: &SpinSample) -> Vec<u8> {
    let mut h = Shake256::default();
    h.update(b"qs-spinprng-v1");
    absorb_str(&mut h, &spec.backend_id);
    absorb_lp(&mut h, &spec.program_hash);
    absorb_str(&mut h, &spec.schedule_id);
    absorb_lp(&mut h, &sample.bytes);
    let mut out = vec![0u8; 32];
    h.finalize_xof().read(&mut out);
    out
}

/// Unqualified seed from OS entropy (`getrandom`), domain-separated.
fn derive_os_unqualified_seed(tag: &[u8]) -> Result<Vec<u8>> {
    let mut entropy = [0u8; 32];
    getrandom::getrandom(&mut entropy).map_err(|_| SpinBackendError::Entropy("getrandom failed"))?;

    let mut h = Shake256::default();
    h.update(b"qs-spinprng-unqualified-v1");
    absorb_lp(&mut h, tag);
    absorb_lp(&mut h, &entropy);
    let mut buf = vec![0u8; 32];
    h.finalize_xof().read(&mut buf);
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Session helper
// ---------------------------------------------------------------------------

/// Run evolve+measure under external meter; gate; derive seed per policy.
pub fn isolation_session<B, M, G>(
    backend: &mut B,
    meter: &mut M,
    gate: &G,
    spec: &EvolutionSpec,
    secret: &[u8],
    profile: &IsolationProfile,
    policy: ReleasePolicy,
) -> Result<QualifiedSeed>
where
    B: SpinBackend,
    M: ObserverMeter,
    G: IsolationGate,
{
    backend.prepare(spec, secret)?;
    meter.start("evolve+measure");
    backend.evolve()?;
    let sample = match backend.measure() {
        Ok(s) => s,
        Err(e) => {
            // Best-effort stop; prefer the backend error if both fail.
            let _ = meter.stop("evolve+measure");
            return Err(e);
        }
    };
    let report = meter.stop("evolve+measure")?;

    // Spec fingerprint mismatch → inconclusive (profile for different program).
    if profile.spec_fingerprint != spec.fingerprint() && profile.spec_fingerprint != [0u8; 32] {
        return finish_policy(
            policy,
            IsolationVerdict::Inconclusive,
            report,
            spec,
            &sample,
            backend.backend_id(),
        );
    }

    let verdict = gate.gate(&report, profile);
    finish_policy(
        policy,
        verdict,
        report,
        spec,
        &sample,
        backend.backend_id(),
    )
}

fn finish_policy(
    policy: ReleasePolicy,
    verdict: IsolationVerdict,
    report: TimingReport,
    spec: &EvolutionSpec,
    sample: &SpinSample,
    backend_id: &str,
) -> Result<QualifiedSeed> {
    match verdict {
        IsolationVerdict::Clean => Ok(QualifiedSeed {
            bytes: derive_spinprng_seed(spec, sample),
            isolation: true,
            verdict,
            report,
            backend_id: backend_id.to_string(),
        }),
        IsolationVerdict::BackendError => Err(SpinBackendError::Backend("backend error verdict")),
        other => match policy {
            ReleasePolicy::Abort => Err(SpinBackendError::IsolationAbort {
                verdict: other,
                report,
            }),
            ReleasePolicy::ReseedOsUnqualified => Ok(QualifiedSeed {
                bytes: derive_os_unqualified_seed(b"reseed-os")?,
                isolation: false,
                verdict: other,
                report,
                backend_id: backend_id.to_string(),
            }),
            ReleasePolicy::AllowUnqualified => Ok(QualifiedSeed {
                bytes: derive_spinprng_seed(spec, sample),
                isolation: false,
                verdict: other,
                report,
                backend_id: backend_id.to_string(),
            }),
        },
    }
}

// ---------------------------------------------------------------------------
// Classical mock backend (interface tests)
// ---------------------------------------------------------------------------

/// Deterministic classical stub: sample = SHAKE(LP fields).
/// Does not model real spin glass; only freezes the interface.
#[derive(Default)]
pub struct ClassicalMockBackend {
    prepared: bool,
    secret: Vec<u8>,
    program_hash: [u8; 32],
    schedule_id: String,
    evolved: bool,
}

impl SpinBackend for ClassicalMockBackend {
    fn backend_id(&self) -> &str {
        "classical-mock-v1"
    }

    fn prepare(&mut self, spec: &EvolutionSpec, secret: &[u8]) -> Result<()> {
        self.secret = secret.to_vec();
        self.program_hash = spec.program_hash;
        self.schedule_id = spec.schedule_id.clone();
        self.prepared = true;
        self.evolved = false;
        Ok(())
    }

    fn evolve(&mut self) -> Result<()> {
        if !self.prepared {
            return Err(SpinBackendError::NotPrepared);
        }
        self.evolved = true;
        Ok(())
    }

    fn measure(&mut self) -> Result<SpinSample> {
        if !self.prepared || !self.evolved {
            return Err(SpinBackendError::NotPrepared);
        }
        let mut h = Shake256::default();
        h.update(b"classical-mock-sample-v1");
        absorb_lp(&mut h, &self.secret);
        absorb_lp(&mut h, &self.program_hash);
        absorb_str(&mut h, &self.schedule_id);
        let mut bytes = vec![0u8; 32];
        h.finalize_xof().read(&mut bytes);
        Ok(SpinSample { bytes })
    }
}

/// Meter that returns a fixed wall_ns (for gate unit tests).
pub struct FixedMeter {
    pub wall_ns: u128,
}

impl ObserverMeter for FixedMeter {
    fn start(&mut self, _label: &str) {}
    fn stop(&mut self, label: &str) -> Result<TimingReport> {
        Ok(TimingReport {
            label: label.to_string(),
            wall_ns: self.wall_ns,
            load_hint: 0,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_spec() -> EvolutionSpec {
        EvolutionSpec {
            backend_id: "classical-mock-v1".into(),
            program_hash: [7u8; 32],
            schedule_id: "rounds=32".into(),
            mode: EvolutionMode::DeterministicClassical,
        }
    }

    fn loose_profile(spec: &EvolutionSpec) -> IsolationProfile {
        IsolationProfile {
            spec_fingerprint: spec.fingerprint(),
            baseline_p50_ns: 1_000_000,
            baseline_p95_ns: 5_000_000,
            baseline_iqr_ns: 500_000,
            margin_ns: 50_000_000,
            iqr_factor: 0.0,
        }
    }

    #[test]
    fn t1_classical_determinism() {
        let spec = test_spec();
        let secret = b"test-secret";
        let mut a = ClassicalMockBackend::default();
        let mut b = ClassicalMockBackend::default();
        a.prepare(&spec, secret).unwrap();
        b.prepare(&spec, secret).unwrap();
        a.evolve().unwrap();
        b.evolve().unwrap();
        assert_eq!(a.measure().unwrap(), b.measure().unwrap());
    }

    #[test]
    fn t2_meter_non_interference() {
        let spec = test_spec();
        let secret = b"secret-2";
        let mut backend = ClassicalMockBackend::default();
        backend.prepare(&spec, secret).unwrap();
        backend.evolve().unwrap();
        let s1 = backend.measure().unwrap();

        let mut backend2 = ClassicalMockBackend::default();
        let mut meter = WallClockMeter::default();
        meter.start("x");
        backend2.prepare(&spec, secret).unwrap();
        backend2.evolve().unwrap();
        let s2 = backend2.measure().unwrap();
        meter.stop("x").unwrap();
        assert_eq!(s1, s2);
    }

    #[test]
    fn t3_gate_clean() {
        let gate = EnvelopeGate;
        let profile = IsolationProfile {
            spec_fingerprint: [0u8; 32],
            baseline_p50_ns: 1000,
            baseline_p95_ns: 2000,
            baseline_iqr_ns: 200,
            margin_ns: 100,
            iqr_factor: 0.0,
        };
        let report = TimingReport {
            label: "t".into(),
            wall_ns: 1500,
            load_hint: 0,
        };
        assert_eq!(gate.gate(&report, &profile), IsolationVerdict::Clean);
    }

    #[test]
    fn t4_gate_suspect() {
        let gate = EnvelopeGate;
        let profile = IsolationProfile {
            spec_fingerprint: [0u8; 32],
            baseline_p50_ns: 1000,
            baseline_p95_ns: 2000,
            baseline_iqr_ns: 200,
            margin_ns: 0,
            iqr_factor: 0.0,
        };
        let report = TimingReport {
            label: "t".into(),
            wall_ns: 9000,
            load_hint: 0,
        };
        assert_eq!(
            gate.gate(&report, &profile),
            IsolationVerdict::SuspectObserver
        );
    }

    #[test]
    fn t5_seed_hygiene_ignores_timing() {
        let spec = test_spec();
        let sample = SpinSample {
            bytes: vec![1, 2, 3, 4],
        };
        let s1 = derive_spinprng_seed(&spec, &sample);
        let s2 = derive_spinprng_seed(&spec, &sample);
        assert_eq!(s1, s2);
        assert_eq!(s1.len(), 32);
    }

    #[test]
    fn t6_policy_abort() {
        let spec = test_spec();
        let mut backend = ClassicalMockBackend::default();
        let mut meter = FixedMeter { wall_ns: 99_000_000 };
        let gate = EnvelopeGate;
        let mut profile = loose_profile(&spec);
        profile.baseline_p95_ns = 1000;
        profile.margin_ns = 0;
        profile.iqr_factor = 0.0;
        let err = isolation_session(
            &mut backend,
            &mut meter,
            &gate,
            &spec,
            b"sec",
            &profile,
            ReleasePolicy::Abort,
        )
        .unwrap_err();
        match err {
            SpinBackendError::IsolationAbort {
                verdict: IsolationVerdict::SuspectObserver,
                ..
            } => {}
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn t7_clean_session_seed_stable() {
        let spec = test_spec();
        let mut backend = ClassicalMockBackend::default();
        let mut meter = FixedMeter { wall_ns: 1000 };
        let gate = EnvelopeGate;
        let profile = IsolationProfile {
            spec_fingerprint: spec.fingerprint(),
            baseline_p50_ns: 1000,
            baseline_p95_ns: 5000,
            baseline_iqr_ns: 500,
            margin_ns: 1000,
            iqr_factor: 0.0,
        };
        let q = isolation_session(
            &mut backend,
            &mut meter,
            &gate,
            &spec,
            b"stable-secret",
            &profile,
            ReleasePolicy::Abort,
        )
        .unwrap();
        assert!(q.isolation);
        assert_eq!(q.verdict, IsolationVerdict::Clean);

        let mut backend2 = ClassicalMockBackend::default();
        let mut meter2 = FixedMeter { wall_ns: 2000 };
        let q2 = isolation_session(
            &mut backend2,
            &mut meter2,
            &gate,
            &spec,
            b"stable-secret",
            &profile,
            ReleasePolicy::Abort,
        )
        .unwrap();
        assert_eq!(q.bytes, q2.bytes);
    }

    #[test]
    fn length_prefix_disambiguates_adjacent_fields() {
        // Without LP, backend_id="ab"+schedule="c" can collide with "a"+"bc"
        // when only those fields are concatenated. Fingerprint also has fixed
        // program_hash between them; still LP both ends.
        let mut a = EvolutionSpec {
            backend_id: "ab".into(),
            program_hash: [0u8; 32],
            schedule_id: "c".into(),
            mode: EvolutionMode::DeterministicClassical,
        };
        let mut b = EvolutionSpec {
            backend_id: "a".into(),
            program_hash: [0u8; 32],
            schedule_id: "bc".into(),
            mode: EvolutionMode::DeterministicClassical,
        };
        assert_ne!(a.fingerprint(), b.fingerprint());

        // Sample path: secrets that would glue ambiguously
        a.backend_id = "x".into();
        b.backend_id = "x".into();
        a.schedule_id = "s".into();
        b.schedule_id = "s".into();
        let s_ab = SpinSample {
            bytes: b"ab".to_vec(),
        };
        // derive uses LP(sample) so "a"||"b" encoding differs from bare concat games
        let seed1 = derive_spinprng_seed(&a, &s_ab);
        let seed2 = derive_spinprng_seed(
            &a,
            &SpinSample {
                bytes: b"a".to_vec(),
            },
        );
        assert_ne!(seed1, seed2);

        // Classical mock: secret "ab" vs longer with same trailing schedule
        let mut m1 = ClassicalMockBackend::default();
        let mut m2 = ClassicalMockBackend::default();
        let spec = test_spec();
        m1.prepare(&spec, b"ab").unwrap();
        m2.prepare(&spec, b"a").unwrap();
        m1.evolve().unwrap();
        m2.evolve().unwrap();
        // Different secrets ⇒ different samples (LP makes length part of input)
        assert_ne!(m1.measure().unwrap(), m2.measure().unwrap());
    }

    #[test]
    fn wall_clock_double_stop_errors() {
        let mut m = WallClockMeter::default();
        m.start("t");
        m.stop("t").unwrap();
        match m.stop("t") {
            Err(SpinBackendError::MeterNotRunning) => {}
            other => panic!("expected MeterNotRunning, got {other:?}"),
        }
    }

    #[test]
    fn wall_clock_stop_without_start_errors() {
        let mut m = WallClockMeter::default();
        assert!(matches!(
            m.stop("t"),
            Err(SpinBackendError::MeterNotRunning)
        ));
    }

    #[test]
    fn os_unqualified_uses_fresh_entropy() {
        let a = derive_os_unqualified_seed(b"reseed-os").unwrap();
        let b = derive_os_unqualified_seed(b"reseed-os").unwrap();
        assert_eq!(a.len(), 32);
        assert_ne!(a, b, "getrandom should make successive unqualified seeds differ");
    }
}
