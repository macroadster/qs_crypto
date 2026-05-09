# SpinLattice: A Frustrated Triangular-Lattice Permutation with Full Empirical Avalanche

**Request for Cryptanalysis and Community Feedback**

**Version:** QS-Crypto v0.1 (post-2026 hardening pass)  
**Primary Authors:** [TBD]  
**Date:** April 2026

---

## TL;DR

We present **SpinLattice**, a novel cryptographic permutation based on synchronous dynamics of a generalized Potts model on a toroidal triangular lattice over the prime field $\mathbb{Z}_{3329}$. 

After the design-specified 32 rounds on the QS-256 parameter set ($n=16$, 256 spins), a single-spin change produces **complete state randomization**:

- **10,000 independent Monte-Carlo trials**
- Mean **255.9 / 256 spins** differ in the output
- Mean **~1,521 bits** flip (out of 3,072)
- Range across trials: **[253, 256]** spins flipped

These results constitute **full diffusion and near-ideal avalanche**. We believe this round function is worthy of serious third-party analysis.

The permutation powers a full research cryptographic stack (sponge → hash/PRNG/KDF/AEAD → protocols) plus a hardened Ring-LWE KEM (all internal randomness now derived from SHAKE256, so the KEM security reduction is independent of the novel primitive).

We provide a first-class statistical validation binary (`cargo run --bin stats`) and reproducible ignored tests.

We invite the community to analyze the round function, the sponge construction, and the overall design.

---

## The Permutation

**SpinLattice** models a frustrated triangular lattice of spins $\sigma_i \in \mathbb{Z}_q$ ($q = 3329$).

Each round consists of:
1. Synchronous computation of the effective local field $h_\text{eff}(i) = \sum_{j \in \text{neighbors}} J_{ij} \cdot \sigma_j \pmod{q}$
2. Nonlinear update $\sigma'_i = (h_\text{eff}(i) + \sigma_i + rc_i)^3 \pmod{q}$

The triangular topology introduces geometric frustration. The cubing map is a bijection over $\mathbb{Z}_q$ (since $\gcd(3, q-1)=1$). Position-dependent round constants break symmetry.

The design uses $K = 2n$ rounds (diameter of the torus), which the empirical data shows is sufficient for full diffusion.

---

## Key Empirical Result (Reproducible)

**Command:**
```bash
cargo run --bin stats -- --permutation --trials 10000
```

**Result (QS-256, 32 rounds, 10,000 trials):**

```
avg_spin_diff=255.9/256 (100.0%)
avg_bit_diff=1520.7
range=[253,256] → excellent (full avalanche)
```

**Interpretation**
- A local change of ≈12 bits completely randomizes a 3072-bit state.
- Bit-level avalanche is extremely close to the information-theoretic ideal (1536 bits).
- Variance is minimal — the behavior is stable across widely different starting states.

Additional quick battery (`--quick`) confirms:
- Excellent byte uniformity after whitening (chi-squared passes on multi-megabyte streams)
- The permutation itself passes strong injectivity sampling (50k trials, zero collisions on 256-bit fingerprints)

All results are obtained from the public `qs_crypto` crate and can be reproduced by anyone with a standard Rust toolchain.

---

## Library Architecture & Hardening Status

The current library (post-hardening) consists of four layers:

| Layer | Component                          | Status / Security Basis                          |
|-------|------------------------------------|--------------------------------------------------|
| 0     | SpinLattice + SpinSponge           | Novel permutation (strong empirical evidence)   |
| 1     | SpinHash / SpinPRNG / SpinKDF / SpinAEAD | Research primitives built on the sponge        |
| 2     | Ring-LWE KEM + Fujisaki-Okamoto    | **Hardened** — all coins from SHAKE256 + OS     |
| 3     | PAKE, Double Ratchet, Session      | Standard constructions                          |

**Important clarification:** The KEM's IND-CCA2 security reduces to Ring-LWE + SHAKE256. It does **not** depend on the strength of the SpinLattice permutation. The novel primitive is used only for the symmetric layer and the visual fingerprinting mechanism.

---

## What We Are Asking For

We welcome analysis on any of the following:

1. **Cryptanalysis of the round function**
   - Differential and linear properties of the cubic S-box + linear mixing step
   - Algebraic attacks exploiting the structure of the coupling graph or the cubing map
   - Quantum attacks (Grover, quantum annealing considerations for spin glasses)
   - Any weakness in the 32-round diffusion on the specific parameter sets

2. **Sponge security**
   - Indifferentiability arguments or bounds in the random-permutation model
   - Concrete capacity requirements given the observed statistical behavior
   - Side-channel analysis of the current implementation

3. **Protocol-level issues**
   - Any interaction problems between the KEM (now standard) and the experimental symmetric primitives
   - Forward secrecy or PAKE properties when built on top of the sponge

4. **Implementation / side-channel**
   - Constant-time audit of `step()`, polynomial arithmetic, and the new whitening code in `squeeze()`
   - Suggestions for further hardening (masking, etc.)

**Preferred contact channels:** GitHub issues on the `qs_crypto` repository, pqc-forum, or direct email (TBD).

---

## Provided Tools for Reviewers

The repository ships with powerful, self-contained validation tooling:

- `cargo run --bin stats -- --permutation --trials N` — Monte-Carlo avalanche study
- `cargo run --bin stats -- --quick` — Fast uniformity + diffusion battery
- `cargo run --bin stats -- --raw-spins` — Dump full lattice states after K rounds (ideal for algebraic work)
- `cargo run --bin stats -- --megabytes M --streams K` — Generate large `.bin` files for dieharder / NIST STS / TestU01
- `cargo test --test stats -- --ignored` — Reproducible property tests (including Monte-Carlo injectivity)

We strongly encourage reviewers to run these commands themselves before forming conclusions.

---

## Current Limitations (Being Honest)

- **Byte extraction / whitening** in the sponge is still an engineering task. While uniformity now passes our internal battery, long-range autocorrelation on raw `SpinPrng` output is not yet ideal. We are iterating on the output formatter.
- The symmetric primitives (`spin_*`) remain **experimental**. For high-value data we recommend hybrid constructions (e.g., Spin-derived key material fed into AES-GCM or ChaCha20-Poly1305).
- No formal proof or computer-assisted verification of the permutation properties yet exists.
- Side-channel resistance has not been formally validated (basic precautions such as `Zeroize`, constant-time rejection, and `black_box` hints are present).

---

## How to Get Started

```bash
git clone <repo>
cd qs_crypto
cargo test
cargo run --bin stats -- --quick
cargo run --bin stats -- --permutation --trials 5000   # quick local confirmation
```

For serious review we recommend generating ≥100 MiB streams and running the full external test suites.

---

## Conclusion

The SpinLattice round function exhibits **full empirical diffusion and avalanche** after the design number of rounds, at a level rarely seen in unaudited custom primitives. Combined with a now-hardened Ring-LWE KEM and clean protocol layers, we believe the library has reached the point where it merits serious external cryptanalysis.

We are not claiming production readiness. We are claiming that the core novel component has earned the right to be taken seriously and examined carefully.

We look forward to your feedback, attacks, improvements, and questions.

**The spin glass lattice holds — but we want you to try to break it.**

---

*Reproducibility note: All numbers above were obtained with `qs_crypto` at the commit corresponding to this document. The validation binary and ignored tests are part of the main crate and require only a standard Rust 1.75+ environment.*
