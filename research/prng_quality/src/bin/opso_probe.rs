//! Compare OPSO-relevant structure across squeeze paths.
//!
//! Generates 256 MiB streams with three extraction modes and prints
//! simple overlapping-tuple occupancy stats (OPSO-like 10-bit pairs).
//!
//! ```bash
//! cargo run --release --manifest-path research/prng_quality/Cargo.toml --bin opso_probe
//! ```

use qs_crypto::core::sponge::SpinSponge;
use qs_crypto::params::{Params, SecurityLevel};
use qs_crypto::primitives::prng::SpinPrng;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

fn main() {
    let out = PathBuf::from("research/prng_quality/out");
    fs::create_dir_all(&out).ok();
    // Streaming is fast; classic/raw use full `permute()` and are ~100–1000× slower.
    let n_fast = 256 * 1024 * 1024;
    let n_slow = 32 * 1024 * 1024;
    let seed = b"opso-probe-seed-v1";
    let params = Params::from_security_level(SecurityLevel::QS256);

    println!("=== OPSO probe ===\n");

    // Path A: product SpinPrng = squeeze_streaming (CTR + SplitMix)
    let t0 = Instant::now();
    let mut prng = SpinPrng::with_params(seed, &params);
    let stream_a = prng.next_bytes(n_fast);
    println!(
        "streaming (SpinPrng) {:>4} MiB: {:.2?}  {}",
        n_fast / (1024 * 1024),
        t0.elapsed(),
        occupancy_report(&stream_a)
    );
    fs::write(out.join("probe_streaming.bin"), &stream_a).ok();

    // Path B: classic squeeze (mini-block mix + full permute) — smaller sample
    let t0 = Instant::now();
    let mut sponge = absorb_seed(seed, &params);
    let stream_b = sponge.squeeze(n_slow);
    println!(
        "classic squeeze      {:>4} MiB: {:.2?}  {}",
        n_slow / (1024 * 1024),
        t0.elapsed(),
        occupancy_report(&stream_b)
    );
    fs::write(out.join("probe_classic.bin"), &stream_b).ok();

    // Path C: raw sponge (LE u16 rate bytes)
    let t0 = Instant::now();
    let mut sponge = absorb_seed(seed, &params);
    let stream_c = sponge.squeeze_raw(n_slow);
    println!(
        "raw squeeze          {:>4} MiB: {:.2?}  {}",
        n_slow / (1024 * 1024),
        t0.elapsed(),
        occupancy_report(&stream_c)
    );
    fs::write(out.join("probe_raw.bin"), &stream_c).ok();

    // Path D: pure SplitMix64 counter (control)
    let t0 = Instant::now();
    let stream_d = pure_splitmix(0xDEADBEEFCAFEBABE, n_fast);
    println!(
        "pure SplitMix64      {:>4} MiB: {:.2?}  {}",
        n_fast / (1024 * 1024),
        t0.elapsed(),
        occupancy_report(&stream_d)
    );
    fs::write(out.join("probe_splitmix.bin"), &stream_d).ok();

    // Path E: naive counter (should show LOW occupancy)
    let t0 = Instant::now();
    let stream_e = naive_counter(n_fast);
    println!(
        "naive counter        {:>4} MiB: {:.2?}  {}",
        n_fast / (1024 * 1024),
        t0.elapsed(),
        occupancy_report(&stream_e)
    );

    println!("\nStreams in research/prng_quality/out/probe_*.bin for dieharder -d 5/6");
    println!("Note: dieharder marks OPSO/OQSO/DNA as 'Suspect' reliability.");
}

fn absorb_seed(seed: &[u8], params: &Params) -> SpinSponge {
    let mut sponge = SpinSponge::new(params);
    let mut input = Vec::with_capacity(3 + seed.len());
    input.extend_from_slice(&[0x01, 0x02, 0x03]);
    input.extend_from_slice(seed);
    sponge.absorb(&input);
    sponge
}

fn pure_splitmix(mut state: u64, n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n];
    let mut pos = 0;
    while pos < n {
        state = state.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^= z >> 31;
        let b = z.to_le_bytes();
        let take = (n - pos).min(8);
        out[pos..pos + take].copy_from_slice(&b[..take]);
        pos += take;
    }
    out
}

fn naive_counter(n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n];
    for (i, chunk) in out.chunks_mut(4).enumerate() {
        let v = (i as u32).to_le_bytes();
        let take = chunk.len();
        chunk.copy_from_slice(&v[..take]);
    }
    out
}

/// OPSO-like: 10-bit letters from successive 32-bit words (LE), pair occupancy.
fn occupancy_report(data: &[u8]) -> String {
    // Collect 2^20 samples of 20-bit pair keys (10+10)
    const SAMPLES: usize = 1 << 20;
    let mut seen = vec![0u8; 1 << 20]; // bitset via bytes: 1 bit per key would be 128 KiB; use u8 marks
    // Use full 1<<20 bitset as bytes of 0/1 for simplicity (1 MiB)
    let mut occupied = 0u64;
    let mut i = 0usize;
    let mut samples = 0usize;
    while samples < SAMPLES && i + 8 <= data.len() {
        let w0 = u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
        let w1 = u32::from_le_bytes(data[i + 4..i + 8].try_into().unwrap());
        // Marsaglia-style: take 10 bits from each word as "letters"
        let a = (w0 & 0x3FF) as usize;
        let b = (w1 & 0x3FF) as usize;
        let key = (a << 10) | b;
        if seen[key] == 0 {
            seen[key] = 1;
            occupied += 1;
        }
        samples += 1;
        i += 4; // overlapping pairs of words: step by one word
    }
    // Expected unique for random: N * (1 - (1-1/M)^samples) ≈ M*(1-e^{-samples/M})
    let m = (1u64 << 20) as f64;
    let s = samples as f64;
    let expected = m * (1.0 - (-s / m).exp());
    let ratio = occupied as f64 / expected;
    format!(
        "pairs={samples} unique={occupied} E≈{expected:.0} ratio={ratio:.4} {}",
        if (ratio - 1.0).abs() < 0.02 {
            "ok"
        } else if ratio < 0.95 {
            "LOW_OCCUPANCY"
        } else {
            "HIGH"
        }
    )
}
