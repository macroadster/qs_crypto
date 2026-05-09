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

_Not yet collected — run the harness and record results here._

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
