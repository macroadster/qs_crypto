//! Research demo: IsolationGate → QualifiedSeed → product SpinPrng stream.
//!
//! Requires `--features spin-lattice` (optional path dep on qs_crypto).
//! Does **not** change the product crate public API.
//!
//! ```bash
//! cargo run --example qualified_prng_demo --release --features spin-lattice
//! ```

use spin_backend::{
    isolation_session, spinprng_from_qualified, BusyMockBackend, EnvelopeGate, EvolutionMode,
    EvolutionSpec, FixedMeter, IsolationProfile, IsolationVerdict, ProductSeedPolicy,
    QuantumSimBackend, ReleasePolicy, SpinBackend,
};

fn main() {
    println!("=== qualified_prng_demo — research bridge to product SpinPrng ===\n");
    println!("S3: seed bytes only (no timing). S2: isolation is heuristic.\n");

    // --- Busy mock, Clean path ---
    let spec = EvolutionSpec {
        backend_id: "busy-mock-v1".into(),
        program_hash: [0x2a; 32],
        schedule_id: "rounds=500".into(),
        mode: EvolutionMode::DeterministicClassical,
    };
    let mut backend = BusyMockBackend::default();
    let profile = IsolationProfile {
        spec_fingerprint: spec.fingerprint(),
        baseline_p50_ns: 1_000,
        baseline_p95_ns: 10_000,
        baseline_iqr_ns: 0,
        margin_ns: 1_000,
        iqr_factor: 0.0,
    };
    let q = isolation_session(
        &mut backend,
        &mut FixedMeter { wall_ns: 1_200 },
        &EnvelopeGate,
        &spec,
        b"qualified-prng-demo-secret",
        &profile,
        ReleasePolicy::Abort,
    )
    .expect("clean session");

    println!("1) BusyMock Clean session");
    println!("   isolation={} verdict={:?}", q.isolation, q.verdict);
    println!("   seed[0..8]={:02x?}", &q.bytes[..8]);

    let mut aware = spinprng_from_qualified(&q, ProductSeedPolicy::RequireIsolation)
        .expect("product PRNG");
    let stream = aware.prng.next_bytes(16);
    println!(
        "   SpinPrng stream[0..16]={:02x?}  (backend_id={})",
        stream, aware.backend_id
    );

    // --- RequireIsolation rejects Suspect ---
    println!("\n2) RequireIsolation rejects unqualified seed");
    let suspect = spin_backend::QualifiedSeed {
        bytes: q.bytes.clone(),
        isolation: false,
        verdict: IsolationVerdict::SuspectObserver,
        report: spin_backend::TimingReport::wall_only("hot", 99_000_000),
        backend_id: q.backend_id.clone(),
    };
    match spinprng_from_qualified(&suspect, ProductSeedPolicy::RequireIsolation) {
        Err(e) => println!("   expected error: {e}"),
        Ok(_) => println!("   BUG: should reject"),
    }
    let mut loose =
        spinprng_from_qualified(&suspect, ProductSeedPolicy::AllowUnqualified).unwrap();
    println!(
        "   AllowUnqualified still streams: {:02x?}",
        &loose.prng.next_bytes(8)
    );

    // --- Quantum sim → product (deterministic) ---
    println!("\n3) QuantumSimBackend → product SpinPrng");
    let mut qbe = QuantumSimBackend::default();
    let qspec = EvolutionSpec {
        backend_id: qbe.backend_id().into(),
        program_hash: [0x51; 32],
        schedule_id: "shots=512,queue_ms=0,bins=8".into(),
        mode: EvolutionMode::PhysicalShots,
    };
    let qprofile = IsolationProfile {
        spec_fingerprint: qspec.fingerprint(),
        baseline_p50_ns: 1,
        baseline_p95_ns: u128::MAX / 4,
        baseline_iqr_ns: 0,
        margin_ns: 0,
        iqr_factor: 0.0,
    };
    let qq = isolation_session(
        &mut qbe,
        &mut FixedMeter { wall_ns: 500 },
        &EnvelopeGate,
        &qspec,
        b"quantum-product-secret",
        &qprofile,
        ReleasePolicy::Abort,
    )
    .expect("quantum clean");
    let mut qprng = spinprng_from_qualified(&qq, ProductSeedPolicy::RequireIsolation).unwrap();
    println!(
        "   isolation={} stream[0..8]={:02x?}",
        qprng.isolation,
        &qprng.prng.next_bytes(8)
    );
    if let Some(st) = qbe.last_job_stats() {
        println!(
            "   JobStats (observer only): shots={} fidelity={:.3}",
            st.shot_count, st.fidelity_proxy
        );
    }

    println!("\nDone. Product crate unchanged; research-only bridge.");
}
