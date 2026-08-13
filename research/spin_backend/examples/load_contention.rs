//! Empirical isolation-gate experiment under CPU contention.
//!
//! 1. Calibrate an [`IsolationProfile`] on idle runs ([`AdaptiveMargin`]).
//! 2. Confirm idle sessions stay **Clean**.
//! 3. Spawn worker threads that burn CPU, re-run sessions, report Suspect rate.
//! 4. Assert seed bytes identical idle vs load (S3).
//!
//! This is a **heuristic sensor demo**, not a cryptographic proof (S2).
//!
//! ```bash
//! cargo run --example load_contention --release
//! cargo run --example load_contention --release -- --trin
//! cargo run --example load_contention --release --features spin-lattice -- --lattice
//! cargo run --example load_contention --release --features spin-lattice -- --all
//! cargo run --example load_contention --release -- --quantum
//! ```

use spin_backend::{
    calibrate_profile_adaptive, live_session, AdaptiveMargin, BusyMockBackend, EvolutionMode,
    EvolutionSpec, IsolationProfile, IsolationVerdict, QuantumSimBackend, ReleasePolicy,
    SpinBackend, TrinBackend,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[cfg(feature = "spin-lattice")]
use spin_backend::SpinLatticeBackend;

const SECRET: &[u8] = b"load-contention-secret";
const BASELINE_N: usize = 21;
const PROBE_N: usize = 15;
const BUSY_ROUNDS: usize = 80_000;
/// QS128 lattice steps — target tens of ms wall so load contention is visible.
#[cfg(feature = "spin-lattice")]
const LATTICE_ROUNDS: usize = 12_288;
/// Simulated QPU shots (CPU histogram work ≈ tens of ms in release).
const QUANTUM_SHOTS: usize = 48_000;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let modes = parse_modes(&args);

    println!("=== load_contention — IsolationGate under CPU load ===\n");
    println!("S1: wall time is a meter only · S2: heuristic, not a reduction");
    println!(
        "Modes: busy={} lattice={} trin={} quantum={}\n",
        modes.busy, modes.lattice, modes.trin, modes.quantum
    );

    if modes.busy {
        println!("── Backend: BusyMockBackend (rounds={BUSY_ROUNDS}) ──");
        let spec = EvolutionSpec {
            backend_id: "busy-mock-v1".into(),
            program_hash: [0x42; 32],
            schedule_id: format!("rounds={BUSY_ROUNDS}"),
            mode: EvolutionMode::DeterministicClassical,
        };
        let mut backend = BusyMockBackend::default();
        run_harness(&mut backend, &spec, "busy");
    }

    if modes.lattice {
        #[cfg(feature = "spin-lattice")]
        {
            println!("── Backend: SpinLatticeBackend QS128 (rounds={LATTICE_ROUNDS}) ──");
            let mut backend = SpinLatticeBackend::default();
            let spec = EvolutionSpec {
                backend_id: backend.backend_id().into(),
                program_hash: [0x4c; 32],
                schedule_id: format!("rounds={LATTICE_ROUNDS}"),
                mode: EvolutionMode::DeterministicClassical,
            };
            run_harness(&mut backend, &spec, "lattice");
        }
        #[cfg(not(feature = "spin-lattice"))]
        {
            println!(
                "── SpinLatticeBackend requested but feature off ──\n\
                 Rebuild with:\n\
                   cargo run --example load_contention --release --features spin-lattice -- --lattice\n"
            );
        }
    }

    if modes.trin {
        println!("── Backend: TrinBackend (external process) ──");
        match TrinBackend::discover() {
            Ok(mut backend) if backend.available() => {
                let spec = EvolutionSpec {
                    backend_id: "trin-v1".into(),
                    program_hash: [0x71; 32],
                    schedule_id: "spin_sample.trin".into(),
                    mode: EvolutionMode::DeterministicClassical,
                };
                run_harness(&mut backend, &spec, "trin");
            }
            _ => {
                println!("   trin not available (install ~/.local/bin/trin or set TRIN=)\n");
            }
        }
    }

    if modes.quantum {
        println!("── Backend: QuantumSimBackend (shots={QUANTUM_SHOTS}, queue_ms=0) ──");
        let mut backend = QuantumSimBackend::default();
        let spec = EvolutionSpec {
            backend_id: backend.backend_id().into(),
            program_hash: [0x51; 32],
            schedule_id: format!("shots={QUANTUM_SHOTS},queue_ms=0,bins=16"),
            mode: EvolutionMode::PhysicalShots,
        };
        run_harness(&mut backend, &spec, "quantum");
        if let Some(st) = backend.last_job_stats() {
            println!(
                "  last JobStats: job_id={} shots={} queue_ms={} fidelity_proxy={:.4}\n",
                st.job_id, st.shot_count, st.queue_ms, st.fidelity_proxy
            );
        }
    }

    if !modes.busy && !modes.lattice && !modes.trin && !modes.quantum {
        println!("No modes selected. Try --busy, --lattice, --trin, --quantum, or --all");
        std::process::exit(2);
    }

    println!("Done.");
}

#[derive(Debug)]
struct Modes {
    busy: bool,
    lattice: bool,
    trin: bool,
    quantum: bool,
}

fn parse_modes(args: &[String]) -> Modes {
    if args.is_empty() {
        return Modes {
            busy: true,
            lattice: false,
            trin: false,
            quantum: false,
        };
    }
    if args.iter().any(|a| a == "--all") {
        return Modes {
            busy: true,
            lattice: true,
            trin: true,
            quantum: true,
        };
    }
    let lattice = args.iter().any(|a| a == "--lattice");
    let trin = args.iter().any(|a| a == "--trin");
    let busy = args.iter().any(|a| a == "--busy");
    let quantum = args.iter().any(|a| a == "--quantum");
    if !busy && !lattice && !trin && !quantum {
        return Modes {
            busy: true,
            lattice: false,
            trin: false,
            quantum: false,
        };
    }
    Modes {
        busy,
        lattice,
        trin,
        quantum,
    }
}

fn run_harness<B: SpinBackend>(backend: &mut B, spec: &EvolutionSpec, label: &str) {
    let knobs = AdaptiveMargin::default();
    println!("  calibrating baseline ({BASELINE_N} idle runs, adaptive margin)…");
    let profile = calibrate_profile_adaptive(
        backend,
        spec,
        SECRET,
        BASELINE_N,
        knobs,
        0.0, // p95+margin only for this demo
    )
    .expect("calibrate");

    println!(
        "  p50={:.3}ms  p95={:.3}ms  iqr={:.3}ms  margin={:.3}ms  clean_if_wall≤{:.3}ms",
        ns_ms(profile.baseline_p50_ns),
        ns_ms(profile.baseline_p95_ns),
        ns_ms(profile.baseline_iqr_ns),
        ns_ms(profile.margin_ns),
        ns_ms(profile.baseline_p95_ns + profile.margin_ns),
    );

    println!("  idle probes ({PROBE_N})…");
    let idle = probe(backend, spec, &profile, PROBE_N);
    print_hist("  idle", &idle);

    println!(
        "  contended probes ({PROBE_N}, {} burn threads)…",
        n_workers()
    );
    let stop = Arc::new(AtomicBool::new(false));
    let workers = spawn_burners(stop.clone());
    thread::sleep(Duration::from_millis(200));
    let hot = probe(backend, spec, &profile, PROBE_N);
    stop.store(true, Ordering::SeqCst);
    for w in workers {
        let _ = w.join();
    }
    print_hist("  load", &hot);

    println!("  interpretation ({label}):");
    println!(
        "    Idle Clean rate:   {:.0}%",
        100.0 * idle.clean as f64 / idle.total.max(1) as f64
    );
    println!(
        "    Load Suspect rate: {:.0}%",
        100.0 * hot.suspect as f64 / hot.total.max(1) as f64
    );
    if idle.clean == idle.total && hot.suspect > 0 {
        println!("    → Gate separates idle vs contended substrate (heuristic success).");
    } else if hot.suspect == 0 {
        println!("    → No Suspect under load (quiet host, loose margin, or short work).");
    } else if idle.suspect > 0 {
        println!("    → Idle flaky; raise AdaptiveMargin::floor_ns / spread_mult.");
    }

    if let (Some(a), Some(b)) = (idle.first_seed.as_ref(), hot.first_seed.as_ref()) {
        let ok = a == b;
        // Deterministic backends must match. Physical noise backends will not —
        // only assert when both seeds present and backend is bit-stable.
        println!("    Seed hygiene idle==load: {ok} (required for det. backends — S3)");
        if !ok && label != "quantum-noise" {
            // QuantumSim without physical_noise is deterministic → must match.
            if label == "quantum" || label == "busy" || label == "lattice" || label == "trin" {
                println!("    BUG: timing must not affect seed bytes.");
                std::process::exit(1);
            }
        }
    }
    println!();
}

struct Hist {
    clean: usize,
    suspect: usize,
    other: usize,
    total: usize,
    first_seed: Option<Vec<u8>>,
    walls_ms: Vec<f64>,
}

fn probe<B: SpinBackend>(
    backend: &mut B,
    spec: &EvolutionSpec,
    profile: &IsolationProfile,
    n: usize,
) -> Hist {
    let mut h = Hist {
        clean: 0,
        suspect: 0,
        other: 0,
        total: n,
        first_seed: None,
        walls_ms: Vec::with_capacity(n),
    };
    for _ in 0..n {
        match live_session(
            backend,
            spec,
            SECRET,
            profile,
            ReleasePolicy::AllowUnqualified,
        ) {
            Ok(q) => {
                h.walls_ms.push(ns_ms(q.report.wall_ns));
                if h.first_seed.is_none() {
                    h.first_seed = Some(q.bytes.clone());
                }
                match q.verdict {
                    IsolationVerdict::Clean => h.clean += 1,
                    IsolationVerdict::SuspectObserver => h.suspect += 1,
                    _ => h.other += 1,
                }
            }
            Err(e) => {
                eprintln!("  session error: {e}");
                h.other += 1;
            }
        }
    }
    h
}

fn print_hist(label: &str, h: &Hist) {
    let min = h.walls_ms.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = h.walls_ms.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    println!(
        "{label}: Clean={} Suspect={} other={}  wall_ms=[{min:.3} .. {max:.3}]",
        h.clean, h.suspect, h.other
    );
}

fn n_workers() -> usize {
    thread::available_parallelism()
        .map(|n| n.get().saturating_mul(2))
        .unwrap_or(8)
}

fn spawn_burners(stop: Arc<AtomicBool>) -> Vec<thread::JoinHandle<()>> {
    let n = n_workers();
    (0..n)
        .map(|_| {
            let stop = stop.clone();
            thread::spawn(move || {
                let mut x = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    x = x.wrapping_mul(0x5DEECE66D).wrapping_add(0xB);
                    std::hint::black_box(x);
                }
            })
        })
        .collect()
}

fn ns_ms(ns: u128) -> f64 {
    ns as f64 / 1_000_000.0
}
