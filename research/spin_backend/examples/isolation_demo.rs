//! Multi-scenario demo of SpinBackend + ObserverMeter + IsolationGate.
//!
//! Shows what the architecture is *for*: isolation-qualified SpinPRNG seeds,
//! observer detection via timing (meter only), and policies when the gate fails.
//!
//! ```bash
//! cargo run --example isolation_demo
//! ```

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use spin_backend::{
    derive_spinprng_seed, isolation_session, ClassicalMockBackend, EnvelopeGate, EvolutionMode,
    EvolutionSpec, FixedMeter, IsolationProfile, IsolationVerdict, QualifiedSeed, ReleasePolicy,
    SpinBackend, SpinBackendError, WallClockMeter,
};

const SECRET: &[u8] = b"demo-secret-material";
const SECRET_B: &[u8] = b"other-party-secret!!";

fn main() {
    banner("spin_backend isolation demo");
    println!("Rules: S1 meter≠key · S3 seed ignores wall_ns · S5 process observer ≠ network MITM\n");

    let spec = demo_spec();
    let gate = EnvelopeGate;

    // Tight synthetic profile so we can force Clean vs Suspect without real load.
    // (Real wall-clock is noisy; FixedMeter makes the story deterministic.)
    let profile = IsolationProfile {
        spec_fingerprint: spec.fingerprint(),
        baseline_p50_ns: 1_000,
        baseline_p95_ns: 2_000,
        baseline_iqr_ns: 400,
        margin_ns: 500,
        iqr_factor: 0.0,
    };

    println!("EvolutionSpec");
    println!("  backend_id:    {}", spec.backend_id);
    println!("  schedule_id:   {}", spec.schedule_id);
    println!("  mode:          {:?}", spec.mode);
    println!(
        "  program_hash:  {}",
        hex_preview(&spec.program_hash[..8])
    );
    println!("IsolationProfile (synthetic, tight)");
    println!(
        "  p50={}ns  p95={}ns  margin={}ns  ⇒ Clean if wall_ns ≤ {}\n",
        profile.baseline_p50_ns,
        profile.baseline_p95_ns,
        profile.margin_ns,
        profile.baseline_p95_ns + profile.margin_ns
    );

    // ------------------------------------------------------------------
    section(1, "Clean path — unperturbed run releases isolation-qualified seed");
    let clean = run_session(
        &spec,
        SECRET,
        &profile,
        FixedMeter { wall_ns: 1_200 },
        ReleasePolicy::Abort,
        &gate,
    );
    match &clean {
        Ok(q) => {
            print_qualified(q);
            let stream = squeeze_prng_preview(&q.bytes, 16);
            println!("  SpinPRNG-shaped stream (SHAKE preview): {}", hex_preview(&stream));
            println!("  → product would: SpinPrng::new(&q.bytes).next_bytes(n)");
        }
        Err(e) => println!("  unexpected error: {e}"),
    }

    // ------------------------------------------------------------------
    section(
        2,
        "Simulated observer — wall_ns far above baseline (Abort policy)",
    );
    println!("  Injecting wall_ns=50_000 (≫ p95+margin) via FixedMeter…");
    match run_session(
        &spec,
        SECRET,
        &profile,
        FixedMeter { wall_ns: 50_000 },
        ReleasePolicy::Abort,
        &gate,
    ) {
        Ok(q) => println!("  unexpected Ok: isolation={}", q.isolation),
        Err(SpinBackendError::IsolationAbort { verdict, report }) => {
            println!("  verdict:   {verdict:?}");
            println!("  wall_ns:   {}  (meter saw coupling / load)", report.wall_ns);
            println!("  policy:    Abort → no seed bytes released");
            println!("  meaning:   possible process observer; refuse isolation claim");
        }
        Err(e) => println!("  unexpected error: {e}"),
    }

    // ------------------------------------------------------------------
    section(
        3,
        "Same observer load — ReseedOsUnqualified (degraded, isolation=false)",
    );
    match run_session(
        &spec,
        SECRET,
        &profile,
        FixedMeter { wall_ns: 50_000 },
        ReleasePolicy::ReseedOsUnqualified,
        &gate,
    ) {
        Ok(q) => {
            print_qualified(&q);
            println!("  note: seed is NOT from SpinSample under isolation claim");
            println!("  note: still must not fold wall_ns into a 'hardness' KDF");
        }
        Err(e) => println!("  unexpected error: {e}"),
    }

    // ------------------------------------------------------------------
    section(
        4,
        "S3 seed hygiene — different wall_ns, same secret ⇒ same crypto seed",
    );
    let s_fast = run_session(
        &spec,
        SECRET,
        &profile,
        FixedMeter { wall_ns: 800 },
        ReleasePolicy::Abort,
        &gate,
    )
    .expect("clean");
    let s_slow = run_session(
        &spec,
        SECRET,
        &profile,
        FixedMeter { wall_ns: 2_400 }, // still ≤ p95+margin=2500
        ReleasePolicy::Abort,
        &gate,
    )
    .expect("clean");
    println!("  wall_ns: {} vs {}", s_fast.report.wall_ns, s_slow.report.wall_ns);
    println!("  seed A:  {}", hex_preview(&s_fast.bytes));
    println!("  seed B:  {}", hex_preview(&s_slow.bytes));
    println!(
        "  equal:   {}  (timing must not change hardness seed)",
        s_fast.bytes == s_slow.bytes
    );

    // ------------------------------------------------------------------
    section(5, "Different secret ⇒ different seed (crypto channel works)");
    let other = run_session(
        &spec,
        SECRET_B,
        &profile,
        FixedMeter { wall_ns: 1_200 },
        ReleasePolicy::Abort,
        &gate,
    )
    .expect("clean");
    println!("  secret A seed: {}", hex_preview(&s_fast.bytes));
    println!("  secret B seed: {}", hex_preview(&other.bytes));
    println!("  equal:         {}", s_fast.bytes == other.bytes);

    // ------------------------------------------------------------------
    section(6, "AllowUnqualified under load — sample seed, but isolation=false");
    match run_session(
        &spec,
        SECRET,
        &profile,
        FixedMeter { wall_ns: 50_000 },
        ReleasePolicy::AllowUnqualified,
        &gate,
    ) {
        Ok(q) => {
            print_qualified(&q);
            let from_sample = {
                let mut b = ClassicalMockBackend::default();
                b.prepare(&spec, SECRET).unwrap();
                b.evolve().unwrap();
                derive_spinprng_seed(&spec, &b.measure().unwrap())
            };
            println!(
                "  matches pure sample seed: {}  (debug path only)",
                q.bytes == from_sample
            );
        }
        Err(e) => println!("  unexpected error: {e}"),
    }

    // ------------------------------------------------------------------
    section(7, "Live WallClockMeter — one real evolve+measure timing sample");
    let live_profile = IsolationProfile {
        spec_fingerprint: spec.fingerprint(),
        // Loose so CI/demo machines don't false-trip.
        baseline_p50_ns: 1_000,
        baseline_p95_ns: 50_000_000,
        baseline_iqr_ns: 1_000_000,
        margin_ns: 100_000_000,
        iqr_factor: 0.0,
    };
    let mut backend = ClassicalMockBackend::default();
    let mut wall = WallClockMeter::default();
    match isolation_session(
        &mut backend,
        &mut wall,
        &gate,
        &spec,
        SECRET,
        &live_profile,
        ReleasePolicy::Abort,
    ) {
        Ok(q) => {
            print_qualified(&q);
            println!("  (live wall clock; profile intentionally loose)");
        }
        Err(e) => println!("  live session: {e}"),
    }

    // ------------------------------------------------------------------
    section(8, "What this is / is not");
    println!(
        "  IS:     interface for quantum|Trin|classical → SpinSample → SpinPRNG seed\n\
         \x20         + external jitter meter as isolation / process-observer gate\n\
         \x20 IS NOT: network MITM detector, or 'jitter in the KDF makes\n\
         \x20         encryption stronger'\n\
         \x20 NEXT:   SpinLatticeBackend / TrinBackend adapters; product SpinPrng::new"
    );
    println!();
}

fn demo_spec() -> EvolutionSpec {
    EvolutionSpec {
        backend_id: "classical-mock-v1".into(),
        program_hash: *b"0123456789abcdef0123456789abcdef",
        schedule_id: "demo-rounds=8".into(),
        mode: EvolutionMode::DeterministicClassical,
    }
}

fn run_session(
    spec: &EvolutionSpec,
    secret: &[u8],
    profile: &IsolationProfile,
    meter: FixedMeter,
    policy: ReleasePolicy,
    gate: &EnvelopeGate,
) -> Result<QualifiedSeed, SpinBackendError> {
    let mut backend = ClassicalMockBackend::default();
    let mut meter = meter;
    isolation_session(&mut backend, &mut meter, gate, spec, secret, profile, policy)
}

fn print_qualified(q: &QualifiedSeed) {
    println!("  backend:    {}", q.backend_id);
    println!("  verdict:    {:?}", q.verdict);
    println!("  isolation:  {}", q.isolation);
    println!("  wall_ns:    {}", q.report.wall_ns);
    println!("  seed:       {}", hex_preview(&q.bytes));
    if q.verdict == IsolationVerdict::Clean && q.isolation {
        println!("  status:     isolation-qualified SpinPRNG seed OK");
    } else {
        println!("  status:     not isolation-qualified");
    }
}

/// Stand-in for product SpinPRNG squeeze (no qs_crypto dep in this research crate).
fn squeeze_prng_preview(seed: &[u8], n: usize) -> Vec<u8> {
    let mut h = Shake256::default();
    h.update(b"demo-spinprng-stream-v1");
    h.update(&(seed.len() as u64).to_le_bytes());
    h.update(seed);
    let mut out = vec![0u8; n];
    h.finalize_xof().read(&mut out);
    out
}

fn hex_preview(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn banner(title: &str) {
    println!("{}", "=".repeat(72));
    println!("{title}");
    println!("{}", "=".repeat(72));
}

fn section(n: u32, title: &str) {
    println!("── [{n}] {title}");
}
