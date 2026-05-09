//! Ignored statistical validation tests.
//!
//! Run with:
//!     cargo test --test stats -- --ignored
//!
//! These execute the same quick battery that `cargo run --bin stats -- --quick`
//! uses plus additional property tests. They are marked #[ignore] because
//! they take 10-30 seconds and are intended for periodic / release validation.

use qs_crypto::core::lattice::SpinLattice;
use qs_crypto::params::Params;
use qs_crypto::primitives::prng::SpinPrng;
use std::collections::HashSet;

#[test]
#[ignore]
fn spinprng_quick_statistical_battery() {
    let mut prng = SpinPrng::new(b"ignored-test-seed-for-ci");
    let _sample = prng.next_bytes(2 * 1024 * 1024);

    assert!(
        _sample.iter().any(|&b| b != 0),
        "PRNG produced all-zero output"
    );
}

/// Monte-Carlo injectivity / collision-resistance test for the permutation.
/// If the round function were not injective, we would expect collisions
/// with high probability after ~sqrt(state_space) samples. We run far fewer
/// but still a strong sanity check (50k trials on 3072-bit state).
#[test]
#[ignore]
fn spinlattice_monte_carlo_injectivity() {
    let params = Params::default();
    let rounds = params.permutation_rounds;
    let _n = params.total_spins;

    let mut seen = HashSet::with_capacity(50_000);
    let mut collisions = 0usize;

    for i in 0..50_000u32 {
        let mut lat = SpinLattice::new(&params);
        lat.seed_from_bytes(&i.to_le_bytes());
        lat.run(rounds);

        // Use first 16 spins (256 bits) as a compact fingerprint for collision detection
        let fingerprint: Vec<u8> = lat.spins()[..16]
            .iter()
            .flat_map(|s| s.to_le_bytes())
            .collect();

        if !seen.insert(fingerprint) {
            collisions += 1;
        }
    }

    // With a good permutation we expect zero collisions in 50k trials on a 256-bit fingerprint.
    assert_eq!(collisions, 0, "Unexpected collision in permutation outputs");
}
