//! Research-only bridge: isolation-qualified seeds → product [`SpinPrng`].
//!
//! Gated on `feature = "spin-lattice"` (pulls optional `qs_crypto` path dep).
//! **Does not modify** the product crate; call sites remain in research until
//! an explicit product review wires a public API.

use crate::{IsolationVerdict, QualifiedSeed, ReleasePolicy, SpinBackendError};
use qs_crypto::params::Params;
use qs_crypto::primitives::prng::SpinPrng;

/// Whether product PRNG construction may use non-Clean isolation outcomes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProductSeedPolicy {
    /// Only `isolation == true` (Clean path).
    RequireIsolation,
    /// Allow unqualified sample path (`isolation == false`) — debug / research.
    AllowUnqualified,
    /// OS-unqualified reseeds allowed; still rejects Abort (no bytes).
    AllowOsUnqualified,
}

/// Product PRNG plus isolation metadata from the research gate.
pub struct IsolationAwarePrng {
    pub prng: SpinPrng,
    pub isolation: bool,
    pub verdict: IsolationVerdict,
    pub backend_id: String,
}

impl std::fmt::Debug for IsolationAwarePrng {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IsolationAwarePrng")
            .field("isolation", &self.isolation)
            .field("verdict", &self.verdict)
            .field("backend_id", &self.backend_id)
            .field("prng", &"SpinPrng{..}")
            .finish()
    }
}

/// Build a product [`SpinPrng`] from a [`QualifiedSeed`] under policy.
///
/// Seed bytes are consumed as-is by `SpinPrng::new` / `with_params` — timing
/// fields from the gate never enter the product sponge (S3 held upstream).
pub fn spinprng_from_qualified(
    seed: &QualifiedSeed,
    policy: ProductSeedPolicy,
) -> Result<IsolationAwarePrng, SpinBackendError> {
    spinprng_from_qualified_with_params(seed, policy, &Params::default())
}

/// Same as [`spinprng_from_qualified`] with explicit product [`Params`].
pub fn spinprng_from_qualified_with_params(
    seed: &QualifiedSeed,
    policy: ProductSeedPolicy,
    params: &Params,
) -> Result<IsolationAwarePrng, SpinBackendError> {
    match policy {
        ProductSeedPolicy::RequireIsolation => {
            if !seed.isolation {
                return Err(SpinBackendError::Backend(
                    "product seed requires isolation-qualified Clean path",
                ));
            }
        }
        ProductSeedPolicy::AllowUnqualified => {}
        ProductSeedPolicy::AllowOsUnqualified => {
            // OS reseed path sets isolation=false; sample AllowUnqualified too.
            // Reject only empty seeds.
        }
    }
    if seed.bytes.is_empty() {
        return Err(SpinBackendError::Backend("empty qualified seed"));
    }

    let prng = SpinPrng::with_params(&seed.bytes, params);
    Ok(IsolationAwarePrng {
        prng,
        isolation: seed.isolation,
        verdict: seed.verdict,
        backend_id: seed.backend_id.clone(),
    })
}

/// Map a research [`ReleasePolicy`] to a product seed policy (conservative).
pub fn product_policy_from_release(r: ReleasePolicy) -> ProductSeedPolicy {
    match r {
        ReleasePolicy::Abort => ProductSeedPolicy::RequireIsolation,
        ReleasePolicy::ReseedOsUnqualified => ProductSeedPolicy::AllowOsUnqualified,
        ReleasePolicy::AllowUnqualified => ProductSeedPolicy::AllowUnqualified,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        isolation_session, BusyMockBackend, EnvelopeGate, EvolutionMode, EvolutionSpec, FixedMeter,
        IsolationProfile, IsolationVerdict, ReleasePolicy,
    };

    fn busy_spec() -> EvolutionSpec {
        EvolutionSpec {
            backend_id: "busy-mock-v1".into(),
            program_hash: [0x2a; 32],
            schedule_id: "rounds=200".into(),
            mode: EvolutionMode::DeterministicClassical,
        }
    }

    #[test]
    fn clean_seed_drives_product_prng() {
        let spec = busy_spec();
        let mut backend = BusyMockBackend::default();
        let profile = IsolationProfile {
            spec_fingerprint: spec.fingerprint(),
            baseline_p50_ns: 1000,
            baseline_p95_ns: 5000,
            baseline_iqr_ns: 0,
            margin_ns: 1000,
            iqr_factor: 0.0,
        };
        let q = isolation_session(
            &mut backend,
            &mut FixedMeter { wall_ns: 1000 },
            &EnvelopeGate,
            &spec,
            b"product-bridge-secret",
            &profile,
            ReleasePolicy::Abort,
        )
        .unwrap();
        assert!(q.isolation);

        let mut aware =
            spinprng_from_qualified(&q, ProductSeedPolicy::RequireIsolation).unwrap();
        assert!(aware.isolation);
        assert_eq!(aware.verdict, IsolationVerdict::Clean);
        let a = aware.prng.next_bytes(32);
        let mut aware2 =
            spinprng_from_qualified(&q, ProductSeedPolicy::RequireIsolation).unwrap();
        let b = aware2.prng.next_bytes(32);
        assert_eq!(a, b, "same qualified seed ⇒ same product stream prefix");
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn require_isolation_rejects_unqualified() {
        let q = QualifiedSeed {
            bytes: vec![1; 32],
            isolation: false,
            verdict: IsolationVerdict::SuspectObserver,
            report: crate::TimingReport::wall_only("x", 1),
            backend_id: "busy-mock-v1".into(),
        };
        assert!(matches!(
            spinprng_from_qualified(&q, ProductSeedPolicy::RequireIsolation),
            Err(SpinBackendError::Backend(_))
        ));
        assert!(spinprng_from_qualified(&q, ProductSeedPolicy::AllowUnqualified).is_ok());
    }
}
