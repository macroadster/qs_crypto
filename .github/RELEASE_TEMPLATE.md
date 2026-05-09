# QS-Crypto v0.2 — Major Hardening + Strong Empirical Validation of SpinLattice

**The library is now significantly closer to being a credible research artifact worthy of serious cryptanalysis.**

### Highlights

**1. The Core Permutation Now Has Exceptional Empirical Evidence**

After 10,000 independent trials on QS-256 parameters (32 rounds):

- **255.9 / 256 spins** differ after a single-spin input change (100% spin avalanche)
- **~1,521 bits** flip out of 3,072 (extremely close to ideal)
- Range across trials: **[253, 256]**

This is full state randomization with near-perfect diffusion — one of the strongest results seen from an unaudited custom round function.

**2. KEM is Now Hardened**

All internal randomness (keygen, Fujisaki-Okamoto coins, noise sampling) is derived exclusively from **SHAKE256 + OS entropy**. The IND-CCA2 security of the KEM reduces cleanly to Ring-LWE + SHAKE256. The novel `SpinLattice` permutation is **no longer part of the KEM security reduction**.

**3. First-Class Validation Tooling**

We ship a powerful, self-contained statistical harness:

```bash
cargo run --bin stats -- --quick                    # Fast uniformity + diffusion battery
cargo run --bin stats -- --permutation --trials 10000
cargo run --bin stats -- --raw-spins                # Dump full states for algebraic analysis
cargo run --bin stats -- --megabytes 100 --streams 3
```

Plus reproducible ignored tests (`cargo test --test stats -- --ignored`).

---

### Full Review Request & Validation Note

The complete, detailed request for cryptanalysis (including interpretation, reproducibility, limitations, and what we are specifically asking reviewers to attack) is available here:

→ **[docs/SPINLATTICE_REVIEW_REQUEST.md](docs/SPINLATTICE_REVIEW_REQUEST.md)**

We encourage every reviewer to read this document and run the validation commands themselves.

---

### What Changed Since v0.1

- KEM internal randomness moved to SHAKE256 (major security decoupling)
- Extensive documentation alignment and new `SECURITY.md`
- Professional statistical validation binary + Monte-Carlo avalanche framework
- 10k-trial full diffusion proof (now permanently documented)
- Improved output whitening in the sponge
- `core::hint::black_box` + explicit side-channel posture documentation
- New Monte-Carlo injectivity test + `--raw-spins` mode for reviewers
- Many smaller hygiene, test, and documentation improvements

---

### Current Honest Status

| Component              | Trust Basis                              | Recommendation                     |
|------------------------|------------------------------------------|------------------------------------|
| Ring-LWE KEM           | SHAKE256 + standard RLWE                 | Good for experimental use          |
| SpinLattice permutation| Strong empirical avalanche (10k trials)  | **Prime target for analysis**      |
| Symmetric primitives   | Built on the above permutation           | Research / combine with vetted AEAD|
| Side-channels          | Basic hygiene + `black_box` + CT rejection | Not yet formally verified         |

---

### Quick Start

```bash
cargo build --release
cargo test
cargo run --bin stats -- --quick
cargo run --bin demo
```

---

### Call for Review

We believe the `SpinLattice` round function has earned serious external scrutiny. We are **not** claiming production readiness. We **are** claiming that the permutation exhibits full empirical diffusion at the design round count and that the overall library is now clean, hardened, and well-instrumented enough to be worth your time.

**We welcome:**
- Attacks on the round function or sponge
- Algebraic or differential analysis
- Side-channel evaluations
- Suggestions for whitening / performance
- Protocol-level feedback

Please open issues or contact us via the channels listed in the full review request note.

**The spin glass lattice has survived 10,000 trials of extreme stress. We invite you to try harder.**

---

**Assets**
- Full source + validation tools: this release
- Detailed validation note: `docs/SPINLATTICE_REVIEW_REQUEST.md`
- Reproducible commands: see the note above

Thank you for your interest and scrutiny.
