//! Baseline construction for [`IsolationProfile`](crate::IsolationProfile).
//!
//! Collect wall samples under controlled conditions, then build a percentile
//! envelope. Timing stays on the observer channel only (S1/S3).

use crate::{
    isolation_session, EnvelopeGate, EvolutionSpec, IsolationProfile, IsolationVerdict,
    ReleasePolicy, Result, SpinBackend, SpinBackendError, WallClockMeter,
};

/// Percentile in \[0, 100\] over a **sorted** slice (nearest-rank).
pub fn percentile_sorted(sorted: &[u128], pct: f64) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let p = pct.clamp(0.0, 100.0) / 100.0;
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

/// Interquartile range = p75 − p25 on a sorted slice.
pub fn iqr_sorted(sorted: &[u128]) -> u128 {
    let p75 = percentile_sorted(sorted, 75.0);
    let p25 = percentile_sorted(sorted, 25.0);
    p75.saturating_sub(p25)
}

/// Knobs for data-driven absolute margin above p95 (research-grade).
///
/// ```text
/// margin = max(floor_ns,
///              p95_fraction * p95,
///              spread_mult * max(iqr, p95 − p50))
/// ```
#[derive(Clone, Copy, Debug)]
pub struct AdaptiveMargin {
    /// Never thinner than this (ns).
    pub floor_ns: u128,
    /// Fraction of p95 (e.g. `1.0/6.0`).
    pub p95_fraction: f64,
    /// Multiplier on the idle spread proxy `max(iqr, p95 - p50)`.
    pub spread_mult: f64,
}

impl Default for AdaptiveMargin {
    fn default() -> Self {
        Self {
            floor_ns: 2_000_000, // 2 ms
            p95_fraction: 1.0 / 6.0,
            spread_mult: 3.0,
        }
    }
}

/// Absolute margin from sorted wall samples (idle calibration only).
pub fn adaptive_margin_ns(samples_ns: &[u128], knobs: AdaptiveMargin) -> u128 {
    if samples_ns.is_empty() {
        return knobs.floor_ns;
    }
    let mut sorted = samples_ns.to_vec();
    sorted.sort_unstable();
    let p50 = percentile_sorted(&sorted, 50.0);
    let p95 = percentile_sorted(&sorted, 95.0);
    let iqr = iqr_sorted(&sorted);
    let upper_spread = p95.saturating_sub(p50).max(iqr);

    // Cap the absolute floor so a multi-ms floor cannot swamp sub-ms evolutions
    // (else short SpinLattice runs never trip Suspect under load).
    let effective_floor = knobs
        .floor_ns
        .min(p95.saturating_mul(2).max(100_000)); // ≥100 µs, ≤2·p95

    let from_p95 = ((p95 as f64) * knobs.p95_fraction.max(0.0)) as u128;
    let from_spread = ((upper_spread as f64) * knobs.spread_mult.max(0.0)) as u128;
    effective_floor.max(from_p95).max(from_spread)
}

/// Build an [`IsolationProfile`] from raw wall_ns samples for `spec`.
pub fn profile_from_samples(
    spec: &EvolutionSpec,
    samples_ns: &[u128],
    margin_ns: u128,
    iqr_factor: f64,
) -> IsolationProfile {
    let mut sorted = samples_ns.to_vec();
    sorted.sort_unstable();
    IsolationProfile {
        spec_fingerprint: spec.fingerprint(),
        baseline_p50_ns: percentile_sorted(&sorted, 50.0),
        baseline_p95_ns: percentile_sorted(&sorted, 95.0),
        baseline_iqr_ns: iqr_sorted(&sorted),
        margin_ns,
        iqr_factor,
    }
}

/// Like [`profile_from_samples`] but margin from [`adaptive_margin_ns`].
pub fn profile_from_samples_adaptive(
    spec: &EvolutionSpec,
    samples_ns: &[u128],
    knobs: AdaptiveMargin,
    iqr_factor: f64,
) -> IsolationProfile {
    let margin = adaptive_margin_ns(samples_ns, knobs);
    profile_from_samples(spec, samples_ns, margin, iqr_factor)
}

/// Run `n` isolation sessions with [`WallClockMeter`], collecting `wall_ns`.
///
/// Uses a permissive gate + `AllowUnqualified` so samples are always returned;
/// only the timing channel is retained for baseline math.
pub fn collect_wall_samples<B>(
    backend: &mut B,
    spec: &EvolutionSpec,
    secret: &[u8],
    n: usize,
) -> Result<Vec<u128>>
where
    B: SpinBackend,
{
    collect_wall_samples_warmed(backend, spec, secret, 0, n)
}

/// Like [`collect_wall_samples`] but discards `warmup` leading runs (cold start).
pub fn collect_wall_samples_warmed<B>(
    backend: &mut B,
    spec: &EvolutionSpec,
    secret: &[u8],
    warmup: usize,
    n: usize,
) -> Result<Vec<u128>>
where
    B: SpinBackend,
{
    if n == 0 {
        return Ok(Vec::new());
    }
    let gate = EnvelopeGate;
    // Profile that never aborts (inconclusive if zeros).
    let permissive = IsolationProfile {
        spec_fingerprint: [0u8; 32],
        baseline_p50_ns: 0,
        baseline_p95_ns: 0,
        baseline_iqr_ns: 0,
        margin_ns: 0,
        iqr_factor: 0.0,
    };
    let total = warmup.saturating_add(n);
    let mut out = Vec::with_capacity(n);
    for i in 0..total {
        let mut meter = WallClockMeter::default();
        let q = isolation_session(
            backend,
            &mut meter,
            &gate,
            spec,
            secret,
            &permissive,
            ReleasePolicy::AllowUnqualified,
        )?;
        if i >= warmup {
            out.push(q.report.wall_ns);
        }
    }
    Ok(out)
}

/// Collect samples and build a profile in one step.
pub fn calibrate_profile<B>(
    backend: &mut B,
    spec: &EvolutionSpec,
    secret: &[u8],
    n: usize,
    margin_ns: u128,
    iqr_factor: f64,
) -> Result<IsolationProfile>
where
    B: SpinBackend,
{
    let samples = collect_wall_samples(backend, spec, secret, n)?;
    if samples.len() < 3 {
        return Err(SpinBackendError::Backend(
            "need at least 3 wall samples to calibrate",
        ));
    }
    Ok(profile_from_samples(spec, &samples, margin_ns, iqr_factor))
}

/// Calibrate with [`AdaptiveMargin`] (preferred for live experiments).
pub fn calibrate_profile_adaptive<B>(
    backend: &mut B,
    spec: &EvolutionSpec,
    secret: &[u8],
    n: usize,
    knobs: AdaptiveMargin,
    iqr_factor: f64,
) -> Result<IsolationProfile>
where
    B: SpinBackend,
{
    calibrate_profile_adaptive_warmed(backend, spec, secret, 3, n, knobs, iqr_factor)
}

/// Adaptive calibrate with explicit warmup discard count.
pub fn calibrate_profile_adaptive_warmed<B>(
    backend: &mut B,
    spec: &EvolutionSpec,
    secret: &[u8],
    warmup: usize,
    n: usize,
    knobs: AdaptiveMargin,
    iqr_factor: f64,
) -> Result<IsolationProfile>
where
    B: SpinBackend,
{
    let samples = collect_wall_samples_warmed(backend, spec, secret, warmup, n)?;
    if samples.len() < 3 {
        return Err(SpinBackendError::Backend(
            "need at least 3 wall samples to calibrate",
        ));
    }
    Ok(profile_from_samples_adaptive(
        spec, &samples, knobs, iqr_factor,
    ))
}

/// Convenience: one live session under `profile` with [`WallClockMeter`].
pub fn live_session<B>(
    backend: &mut B,
    spec: &EvolutionSpec,
    secret: &[u8],
    profile: &IsolationProfile,
    policy: ReleasePolicy,
) -> Result<crate::QualifiedSeed>
where
    B: SpinBackend,
{
    let mut meter = WallClockMeter::default();
    isolation_session(
        backend,
        &mut meter,
        &EnvelopeGate,
        spec,
        secret,
        profile,
        policy,
    )
}

/// Run `n` live sessions; return verdict histogram (Clean / Suspect / other).
pub fn verdict_histogram<B>(
    backend: &mut B,
    spec: &EvolutionSpec,
    secret: &[u8],
    profile: &IsolationProfile,
    n: usize,
) -> Result<(usize, usize, usize)>
where
    B: SpinBackend,
{
    let mut clean = 0usize;
    let mut suspect = 0usize;
    let mut other = 0usize;
    for _ in 0..n {
        match live_session(
            backend,
            spec,
            secret,
            profile,
            ReleasePolicy::AllowUnqualified,
        ) {
            Ok(q) => match q.verdict {
                IsolationVerdict::Clean => clean += 1,
                IsolationVerdict::SuspectObserver => suspect += 1,
                _ => other += 1,
            },
            Err(SpinBackendError::IsolationAbort { verdict, .. }) => match verdict {
                IsolationVerdict::SuspectObserver => suspect += 1,
                IsolationVerdict::Clean => clean += 1,
                _ => other += 1,
            },
            Err(e) => return Err(e),
        }
    }
    Ok((clean, suspect, other))
}
