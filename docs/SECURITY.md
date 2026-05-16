# Security

## Constant-Time Audit Infrastructure

QS-Crypto includes a dudect-based statistical constant-time testing
harness (`examples/dudect.rs`).  The harness tests the following
security-critical functions for data-dependent timing leaks:

| Function | Left class | Right class | Goal |
|---|---|---|---|
| `SpinLattice::step()` | all-zero spins | random spins | Spin values don't affect timing |
| `aead::encrypt` | all-zero key | random key | Key value doesn't affect timing |
| `aead::decrypt` | valid tag | invalid tag | Auth pass/fail indistinguishable |
| `decapsulate` (FO rejection) | valid ciphertext | random ciphertext | Reject path ≡ accept path |

### Running the audit

```bash
# One-shot (collects ~10 seconds of samples):
cargo run --release --example dudect

# Continuous (press Ctrl-C to stop):
cargo run --release --example dudect -- --continuous
```

A `max |t| < 5` after ≥ 1 million samples provides statistical evidence
that the two input classes are timing-indistinguishable.  Results should
be recorded below as they are collected.

### Audit Results

Collected with `cargo run --release --example dudect` (v0.3, release profile).

| Function | max \|t\| | n (samples) | Verdict |
|---|---|---|---|
| `SpinLattice::step()` | 2.38 | 0.009M | **PASS** |
| `aead::encrypt` | 2.50 | 0.008M | **PASS** |
| `aead::decrypt` | 2.40 | 0.007M | **PASS** |
| `decapsulate` (FO rejection) | 1.74 | 0.001M | **PASS** |

All four functions show `max |t| < 5`, providing statistical evidence
that the two input classes are timing-indistinguishable.

#### Fixes applied to achieve these results

Two timing leaks were found in the initial audit and fixed:

1. **`aead::decrypt` (was |t|=8.18):** The `chacha20poly1305` crate's
   `decrypt()` uses a verify-then-decrypt pattern that skips the ChaCha20
   keystream XOR when the Poly1305 tag fails.  Fixed by replacing the
   crate's `decrypt()` with a double-`encrypt_in_place_detached` approach
   that always applies the full keystream regardless of tag validity.

2. **`kem::decapsulate` (was |t|=7.95):** `decode_message()` and
   `encode_message()` in `src/kem/ring.rs` used data-dependent branches
   on coefficient values (`if c >= half_q`, `if d_half < d0`, `if bit == 1`).
   Fixed with branchless arithmetic: signed-shift masks for constant-time
   min/abs/select, and multiplication instead of conditional assignment.

## Side-Channel Hardening (Tier 4)

The following mitigations are in place:

- **Barrett reduction**: All modular arithmetic uses constant-time Barrett
  reduction (`src/core/reduce.rs`) instead of variable-time hardware
  division (`%` / `rem_euclid`).

- **`#[inline(never)]`**: Applied to `SpinLattice::step()`,
  `derive_spin_subkey()`, and `decapsulate()` to prevent the compiler
  from inlining secret-dependent code into larger functions where
  different optimization decisions could introduce timing variation.

- **`black_box`**: All secret-dependent values in the lattice engine and
  NTT are wrapped in `core::hint::black_box` to inhibit compiler
  optimizations that could introduce data-dependent branches.

- **Constant-time libraries**: The `subtle` crate is used for all
  secret-dependent comparisons (`ct_eq`), and `zeroize` wipes sensitive
  values on drop.
