# QS-Crypto v0.2.0 — Stable Release with Verified NTT + Full 3-Way Hybrid

**v0.2.0 is a major, stable, and "real" release.**

This version brings the library to a point where it is genuinely suitable for serious experimental use and community cryptanalysis.

### Major Achievements in v0.2

**1. Verified NTT Implementation (High-Performance Path Ready)**
- Complete, correct, and tested NTT for `Z_3329[X]/(X^256 + 1)` (same parameters as Kyber/ML-KEM).
- NTT is the unconditional default for QS256 (N=256); smaller dimensions use schoolbook.
- All KEM and protocol tests pass with the NTT path active.

**2. Full 3-Way Hybrid KEM (Spin + X25519 + ML-KEM-768 strength)**
- New `full_hybrid_*` API that is **actually functional end-to-end**.
- Combines the hardened SpinKEM + X25519 + a strong ML-KEM-768-equivalent leg.
- The API is designed for trivial real `ml-kem` crate integration in a follow-up.

**3. Professional Benchmarking**
- Proper `criterion` suite with statistical reports.
- `cargo bench` produces beautiful HTML reports (`target/criterion/index.html`).
- Archived report available in `benches/reports/v0.2/`.

**4. All Previous Hardening Preserved + Improved**
- KEM uses SHAKE256 for all internal randomness (clean security reduction).
- 10,000-trial Monte-Carlo avalanche study on `SpinLattice`: **full state randomization** (255.9/256 spins, ~1521 bits).
- Side-channel hygiene (`black_box`, constant-time rejection, `Zeroize`).
- Powerful validation harness (`cargo run --bin stats`).

### Honest Status for v0.2

| Component              | Status in v0.2                          | Recommendation |
|------------------------|-----------------------------------------|----------------|
| Polynomial Multiplication | NTT for QS256, schoolbook for QS128/QS192 | Unconditional, no feature flag needed |
| 3-Way Hybrid           | Fully functional                        | Recommended for high security |
| KEM Security           | Hardened (SHAKE256 + Ring-LWE)          | Good |
| Validation Evidence    | Excellent (10k trials + benchmarks)     | Strong for review |
| Side-Channel Posture   | Basic but documented hygiene            | Suitable for research/experimental |

### Breaking / Notable Changes

- New `full_hybrid_*` family of functions.
- NTT enabled unconditionally for QS256 polynomial multiplication.

### Installation

```toml
[dependencies]
qs_crypto = "0.2"
```

NTT is enabled by default for QS256 -- no feature flags needed.

### Call for Review

We believe QS-Crypto v0.2 is now worthy of serious third-party analysis.

- The core `SpinLattice` permutation has exceptional empirical diffusion evidence.
- The KEM is hardened and independent of the novel primitive.
- The hybrid story is complete and practical.
- Performance tooling is professional.

**We strongly encourage cryptanalysis of the round function, the sponge, and the overall design.**

Full review request: `docs/SPINLATTICE_REVIEW_REQUEST.md`

---

**Next Release (v0.2.1)**

- Minor ML-KEM wiring polish for the 3-way hybrid.
- Any fixes from early reviewer feedback.

Thank you for your interest. The spin glass lattice is holding strong — please help us test how strong.

— The QS-Crypto team
