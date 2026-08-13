//! PRNG quality evaluation harness (research).
//!
//! **Objects under test (SUT)**
//! - **SUT-A** — product `SpinPrng` from a fixed ASCII seed label
//! - **SUT-B** — product `SpinPrng` from isolation-qualified seed bytes
//!   (`spin_backend` Clean path → `spinprng_from_qualified`)
//! - **SUT-C** — product `SpinPrng` from OS entropy (32 bytes)
//!
//! This harness runs an **extended internal** battery only. It is **not** a
//! substitute for dieharder / NIST STS / TestU01 BigCrush. See QUALITY_RESULTS.md.
//!
//! ```bash
//! cargo run --release --manifest-path research/prng_quality/Cargo.toml
//! cargo run --release --manifest-path research/prng_quality/Cargo.toml -- --mib 64
//! ```

use qs_crypto::params::{Params, SecurityLevel};
use qs_crypto::primitives::prng::SpinPrng;
use spin_backend::{
    isolation_session, spinprng_from_qualified, BusyMockBackend, EnvelopeGate, EvolutionMode,
    EvolutionSpec, FixedMeter, IsolationProfile, ProductSeedPolicy, ReleasePolicy,
};
use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let mib = parse_usize(&args, "--mib", 32);
    let out_dir = parse_string(&args, "--out-dir", "research/prng_quality/out");

    println!("=== prng_quality — SpinPrng evaluation (internal battery) ===\n");
    println!("SUT-A: SpinPrng(fixed label)");
    println!("SUT-B: SpinPrng(isolation-qualified seed via spin_backend)");
    println!("SUT-C: SpinPrng(OS 32-byte entropy)\n");
    println!("Stream size: {mib} MiB per SUT\n");

    fs::create_dir_all(&out_dir).expect("out dir");
    let nbytes = mib * 1024 * 1024;
    let params = Params::from_security_level(SecurityLevel::QS256);

    // --- Produce seeds ---
    let seed_a = b"prng-quality-sut-a-v1".as_slice();
    let seed_b = isolation_seed_bytes();
    let mut seed_c = [0u8; 32];
    getrandom_fill(&mut seed_c);

    println!("Seeds:");
    println!("  A label: {:?}", std::str::from_utf8(seed_a).unwrap_or("?"));
    println!("  B qualified[0..8]: {:02x?}", &seed_b[..8.min(seed_b.len())]);
    println!("  C os[0..8]:        {:02x?}", &seed_c[..8]);
    println!();

    // --- Generate streams ---
    let stream_a = gen_stream("SUT-A", seed_a, &params, nbytes);
    let stream_b = gen_stream("SUT-B", &seed_b, &params, nbytes);
    let stream_c = gen_stream("SUT-C", &seed_c, &params, nbytes);

    // Same seed bytes must yield identical streams (product determinism).
    let stream_b2 = gen_stream("SUT-B-replay", &seed_b, &params, 4096);
    let mut prng_check = SpinPrng::with_params(&seed_b, &params);
    let check = prng_check.next_bytes(4096);
    assert_eq!(stream_b2, check, "SpinPrng not deterministic for fixed seed");
    println!("Determinism: SUT-B replay match ✓\n");

    // Isolation seed ≠ ASCII label seed (different domain) — streams should differ.
    let streams_differ = stream_a[..64] != stream_b[..64];
    println!(
        "SUT-A vs SUT-B first 64 bytes differ: {} (expected true)\n",
        streams_differ
    );

    // --- Internal battery ---
    let reports = [
        ("SUT-A", evaluate(&stream_a)),
        ("SUT-B", evaluate(&stream_b)),
        ("SUT-C", evaluate(&stream_c)),
    ];

    println!("=== Internal battery results ({mib} MiB) ===\n");
    println!(
        "{:<8} {:>10} {:>12} {:>10} {:>10} {:>10} {:>8}",
        "SUT", "byte_χ²", "bit_ones", "serial_r", "lag8_r", "entropy", "verdict"
    );
    for (name, r) in &reports {
        println!(
            "{:<8} {:>10.1} {:>12.6} {:>10.4} {:>10.4} {:>10.4} {:>8}",
            name,
            r.byte_chi2,
            r.bit_ones,
            r.serial_corr,
            r.lag8_corr,
            r.byte_entropy,
            if r.pass { "PASS" } else { "FAIL" }
        );
    }

    let all_pass = reports.iter().all(|(_, r)| r.pass);
    println!(
        "\nInternal extended battery: {}",
        if all_pass { "ALL PASS" } else { "SOME FAIL" }
    );
    println!(
        "Note: PASS here only rules out gross bias. It does NOT claim dieharder/BigCrush quality.\n"
    );

    // Write streams for optional external tools
    write_bin(&out_dir, "sut_a_spinprng.bin", &stream_a);
    write_bin(&out_dir, "sut_b_isolation.bin", &stream_b);
    write_bin(&out_dir, "sut_c_os_seed.bin", &stream_c);

    // Markdown fragment for results
    let md_path = PathBuf::from(&out_dir).join("internal_battery.md");
    let mut md = String::new();
    md.push_str(&format!(
        "# Internal battery run\n\nDate: {}\nMiB/SUT: {mib}\n\n",
        chrono_like_date()
    ));
    md.push_str("| SUT | byte χ² | bit ones | serial r | lag8 r | entropy | verdict |\n");
    md.push_str("|-----|---------|----------|----------|--------|---------|--------|\n");
    for (name, r) in &reports {
        md.push_str(&format!(
            "| {name} | {:.1} | {:.6} | {:.4} | {:.4} | {:.4} | {} |\n",
            r.byte_chi2,
            r.bit_ones,
            r.serial_corr,
            r.lag8_corr,
            r.byte_entropy,
            if r.pass { "PASS" } else { "FAIL" }
        ));
    }
    md.push_str("\nStreams written next to this file for dieharder/NIST when Docker is available.\n");
    fs::write(&md_path, md).expect("write md");
    println!("Wrote {md_path:?}");
    println!("Streams in {out_dir}/ for external suites:");
    println!("  dieharder -a -g 201 -f {out_dir}/sut_a_spinprng.bin");
    println!("  (prefer multi-GiB / streaming to avoid file rewind artifacts)\n");

    if !all_pass {
        std::process::exit(1);
    }
}

fn isolation_seed_bytes() -> Vec<u8> {
    let spec = EvolutionSpec {
        backend_id: "busy-mock-v1".into(),
        program_hash: [0x51; 32],
        schedule_id: "rounds=2000".into(),
        mode: EvolutionMode::DeterministicClassical,
    };
    let mut backend = BusyMockBackend::default();
    let profile = IsolationProfile {
        spec_fingerprint: spec.fingerprint(),
        baseline_p50_ns: 1_000,
        baseline_p95_ns: 50_000_000,
        baseline_iqr_ns: 0,
        margin_ns: 50_000_000,
        iqr_factor: 0.0,
    };
    let q = isolation_session(
        &mut backend,
        &mut FixedMeter { wall_ns: 10_000 },
        &EnvelopeGate,
        &spec,
        b"prng-quality-isolation-secret-v1",
        &profile,
        ReleasePolicy::Abort,
    )
    .expect("isolation Clean session");
    assert!(q.isolation, "expected isolation-qualified seed");
    // Ensure product path accepts it
    let _ = spinprng_from_qualified(&q, ProductSeedPolicy::RequireIsolation).expect("product");
    q.bytes
}

fn gen_stream(label: &str, seed: &[u8], params: &Params, nbytes: usize) -> Vec<u8> {
    let t0 = Instant::now();
    let mut prng = SpinPrng::with_params(seed, params);
    // Generate in chunks to keep peak memory reasonable for large mib
    let chunk = 4 * 1024 * 1024;
    let mut out = Vec::with_capacity(nbytes);
    while out.len() < nbytes {
        let n = (nbytes - out.len()).min(chunk);
        out.extend_from_slice(&prng.next_bytes(n));
    }
    let elapsed = t0.elapsed();
    let mib_s = (nbytes as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64().max(1e-9);
    println!(
        "  {label}: {} MiB in {:.2?} ({:.1} MiB/s)",
        nbytes / (1024 * 1024),
        elapsed,
        mib_s
    );
    out
}

#[derive(Debug)]
struct BatteryReport {
    byte_chi2: f64,
    bit_ones: f64,
    serial_corr: f64,
    lag8_corr: f64,
    byte_entropy: f64,
    pass: bool,
}

fn evaluate(data: &[u8]) -> BatteryReport {
    let (byte_chi2, bit_ones) = chi2_and_monobit(data);
    let serial_corr = lag_corr_bits(data, 1);
    let lag8_corr = lag_corr_bits(data, 8);
    let byte_entropy = shannon_entropy_bytes(data);

    // Thresholds: catch gross failures only (aligned with stats --quick spirit).
    // χ² 255 df: critical ~350 at p≈0.001
    let byte_ok = byte_chi2 < 350.0;
    let bit_ok = (bit_ones - 0.5).abs() < 0.002;
    let serial_ok = serial_corr.abs() < 0.02;
    let lag8_ok = lag8_corr.abs() < 0.02;
    let entropy_ok = byte_entropy > 7.95; // ideal 8.0

    BatteryReport {
        byte_chi2,
        bit_ones,
        serial_corr,
        lag8_corr,
        byte_entropy,
        pass: byte_ok && bit_ok && serial_ok && lag8_ok && entropy_ok,
    }
}

fn chi2_and_monobit(data: &[u8]) -> (f64, f64) {
    let n = data.len() as f64;
    let mut counts = [0u64; 256];
    let mut ones = 0u64;
    for &b in data {
        counts[b as usize] += 1;
        ones += b.count_ones() as u64;
    }
    let expected = n / 256.0;
    let mut chi2 = 0.0;
    for &c in &counts {
        let d = c as f64 - expected;
        chi2 += d * d / expected;
    }
    let bit_ones = ones as f64 / (n * 8.0);
    (chi2, bit_ones)
}

/// Bit-level lag correlation (Pearson on ±1 bits). Near 0 for good PRNG.
fn lag_corr_bits(data: &[u8], lag_bits: usize) -> f64 {
    if data.len() < 16 {
        return 0.0;
    }
    // Sample up to 2M bit pairs for speed
    let max_pairs = 2_000_000usize;
    let total_bits = data.len() * 8;
    if lag_bits >= total_bits {
        return 0.0;
    }
    let n_pairs = (total_bits - lag_bits).min(max_pairs);
    let mut sum_xy = 0i64;
    for i in 0..n_pairs {
        let a = bit_at(data, i);
        let b = bit_at(data, i + lag_bits);
        // map 0→-1, 1→+1
        let xa = if a { 1i64 } else { -1 };
        let xb = if b { 1i64 } else { -1 };
        sum_xy += xa * xb;
    }
    sum_xy as f64 / n_pairs as f64
}

fn bit_at(data: &[u8], bit_idx: usize) -> bool {
    let byte = data[bit_idx / 8];
    let off = 7 - (bit_idx % 8);
    ((byte >> off) & 1) == 1
}

fn shannon_entropy_bytes(data: &[u8]) -> f64 {
    let n = data.len() as f64;
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let mut h = 0.0;
    for &c in &counts {
        if c == 0 {
            continue;
        }
        let p = c as f64 / n;
        h -= p * p.log2();
    }
    h
}

fn write_bin(dir: &str, name: &str, data: &[u8]) {
    let path = PathBuf::from(dir).join(name);
    fs::write(&path, data).expect("write bin");
}

fn getrandom_fill(buf: &mut [u8]) {
    getrandom::getrandom(buf).expect("OS entropy for SUT-C seed");
}

fn parse_usize(args: &[String], flag: &str, default: usize) -> usize {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn parse_string(args: &[String], flag: &str, default: &str) -> String {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| default.to_string())
}

fn chrono_like_date() -> String {
    // Avoid extra dep: local date via command-ish from env or fixed
    std::process::Command::new("date")
        .arg("+%Y-%m-%d")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown-date".into())
}
