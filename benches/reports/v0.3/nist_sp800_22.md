# NIST SP 800-22 Statistical Test Suite Report

**Date:** 2026-05-09
**Version:** QS-Crypto v0.3
**Primitive under test:** SpinPrng (QS-256 sponge, 32 permutation rounds)

## Test Data

Five independent 100 MiB streams generated with:

```
cargo run --release --bin stats -- --megabytes 100 --streams 5 --output-dir stats_out/
```

Streams seeded with deterministic labels `stats-stream-000` through `stats-stream-004`
using `SpinPrng::with_params()` at `SecurityLevel::QS256`.

Files:
- `stats_out/spinprng_qs256_stream000.bin` (104,857,600 bytes)
- `stats_out/spinprng_qs256_stream001.bin` (104,857,600 bytes)
- `stats_out/spinprng_qs256_stream002.bin` (104,857,600 bytes)
- `stats_out/spinprng_qs256_stream003.bin` (104,857,600 bytes)
- `stats_out/spinprng_qs256_stream004.bin` (104,857,600 bytes)

## Internal Quick Battery Results

The built-in fast battery (`--quick`) was run as a preliminary check:

| Test | Result | Value |
|------|--------|-------|
| Byte frequency chi-squared (255 df) | PASS | 251.7 (critical: <350) |
| Bit balance (ones fraction) | PASS | 0.500133 (within ±0.5%) |
| Permutation diffusion (1500 trials) | PASS | 255.9/256 spins differ (100.0%) — excellent full avalanche |
| Bit-level avalanche | PASS | 1521.6/3072 bits flip (49.5%) |
| Diffusion range | PASS | [254, 256] — extremely tight |

## External Test Suite: dieharder

### How to run

dieharder is a comprehensive statistical test suite. Install on Linux:

```bash
# Debian/Ubuntu
sudo apt-get install dieharder

# Fedora/RHEL
sudo dnf install dieharder

# macOS (build from source — not in Homebrew)
# See: https://webhome.phy.duke.edu/~rgb/General/dieharder.php
```

Run the full suite on each stream:

```bash
for f in stats_out/spinprng_qs256_stream*.bin; do
    echo "=== Testing $f ==="
    dieharder -a -g 201 -f "$f" | tee "$(basename $f .bin)_dieharder.txt"
done
```

### Result interpretation

- `PASSED`: p-value in [0.01, 0.99] — test shows no evidence of non-randomness
- `WEAK`: p-value in [0.001, 0.01] or [0.99, 0.999] — marginal, rerun with more data
- `FAILED`: p-value < 0.001 or > 0.999 — strong evidence of non-randomness

Flag any `FAILED` results for investigation. Occasional `WEAK` results (1-2 out of ~100 tests) are expected even for a perfect RNG.

## External Test Suite: NIST STS

### How to run

Download the NIST Statistical Test Suite from:
https://csrc.nist.gov/projects/random-bit-generation/documentation-and-software

```bash
cd NIST_STS
./assess 1000000    # test 1,000,000 bits per block
# When prompted, select "file input" and point to the .bin files
```

### Expected results

All 15 tests in the NIST suite should pass at the α=0.01 significance level.
The proportion of passing sequences should be ≥ 0.96 for each test.

## Status

- [x] Streams generated (5 × 100 MiB)
- [x] Internal quick battery: PASS
- [ ] dieharder full suite: awaiting Linux environment with dieharder installed
- [ ] NIST STS full suite: awaiting NIST STS installation