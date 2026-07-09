# TestU01 BigCrush Report

**Date:** 2026-05-09
**Version:** QS-Crypto v0.3
**Primitive under test:** SpinPrng (QS-256 sponge, 32 permutation rounds)

## Overview

TestU01's BigCrush battery is the most demanding publicly available statistical
test suite for random number generators. It runs 160 individual tests and
typically requires ~4 hours on modern hardware with ≥1 GiB of input data.

## Setup

### 1. Generate the input stream

```bash
cargo run --release --bin stats -- --megabytes 1024 --output stats_out/spinprng_bigcrush.bin
```

This produces a single 1 GiB binary file of SpinPrng output at QS-256 security level.

### 2. Build the C wrapper

Prerequisites: Install TestU01 from source:
- Source: http://simul.iro.umontreal.ca/testu01/tu01.html
- Or: https://github.com/umontreal-simul/TestU01-2009

```bash
cd scripts/testu01/
gcc -O2 -o bigcrush_wrapper bigcrush_wrapper.c \
    -I/usr/local/include -L/usr/local/lib \
    -ltestu01 -lprobdist -lmylib -lm
```

### 3. Run BigCrush

```bash
./bigcrush_wrapper ../../stats_out/spinprng_bigcrush.bin | tee bigcrush_results.txt
```

Expected runtime: approximately 4 hours.

## Result Interpretation

BigCrush runs 160 tests. For each test:
- **PASS**: p-value in (ε, 1-ε) where ε = 10⁻¹⁰ — no evidence of non-randomness
- **FAIL**: p-value outside this range — indicates a statistical anomaly

A well-designed PRNG should pass all 160 tests. Even 1-2 failures warrant
investigation (unlike dieharder where occasional WEAKs are expected).

### Tests included in BigCrush

BigCrush includes (among others):
- Serial Over, CollisionOver, BirthdaySpacings
- Gap, Permutation, Run, MaxOft
- WeightDistrib, SumCollector, MatrixRank
- Savir2, GCD, RandomWalk1
- LinearComp, LempelZiv, Fourier3, LongestHeadRun
- ClosePairs, SimpPoker, CouponCollector
- AutoCor, HammingWeight, HammingCorr
- And ~140 more (full list in TestU01 documentation)

## Status

- [x] C wrapper created (`scripts/testu01/bigcrush_wrapper.c`)
- [x] Stream generation command documented
- [ ] 1 GiB stream generation: not run on implementation host (large artifact; run when TestU01 is available)
- [ ] BigCrush execution: **blocked** — TestU01 libraries not installed (`libtestu01` absent under `/usr/local/lib`)

### Attempt log (2026-06-30)

| Check | Result |
|-------|--------|
| TestU01 headers/libs | not found |
| `bigcrush_wrapper` binary | not built (depends on TestU01) |
| 1 GiB stream | not generated (blocked on runner time / tool availability) |

No BigCrush pass/fail results are recorded. Infrastructure and commands remain ready for a machine with TestU01 installed.