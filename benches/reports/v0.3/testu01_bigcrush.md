# TestU01 BigCrush Report

**Date:** 2026-08-12 (clean pass) · prior stubs 2026-05-09 / 2026-06-30  
**Version:** QS-Crypto v0.2 product / v0.3 validation track  
**Primitive under test:** SpinPrng (QS-256 sponge, continuous SplitMix soft re-mix expander)

## Result (authoritative)

```
========= Summary results of BigCrush =========

 Version:          TestU01 1.2.3
 Generator:        SpinPrng_QS256_stdin
 Number of statistics:  160
 Total CPU time:   06:23:48.75

 All tests were passed
```

| Field | Value |
|-------|--------|
| Verdict | **All 160 statistics passed** |
| Method | Streaming stdin (`bigcrush_stream` in Docker `qs-crypto-testu01`) |
| Host stream | `stats --megabytes 0 --output -` (unlimited until pipe close) |
| Bytes fed | **1 428 418 461 696** (~1.33 TiB / 1 362 246 MiB) @ ~53.9 MiB/s |
| Wall | ~7.0 h (25254 s host stream duration; TestU01 CPU 6 h 24 m) |
| Disk used for stream | **~0** (pipe only); results text ~95 KB |
| p-values sampled | 254 reported; min **0.0054**, max **0.9975**; **no `eps`**, none outside (10⁻⁴, 1−10⁻⁴) |
| Raw log | [`results/bigcrush_results.txt`](results/bigcrush_results.txt) |
| Run note | [`results/VALIDATION_RUN_2026-08-12.md`](results/VALIDATION_RUN_2026-08-12.md) |

**Interpretation:** SpinPrng (QS-256) passes TestU01 BigCrush under the current squeeze/expander. This is strong external statistical evidence. It is **not** a cryptographic security proof of the sponge permutation; hybrid/SHAKE paths remain preferred for asymmetric hardness claims.

## How to reproduce (min-disk)

```bash
# Build image once
docker build -t qs-crypto-testu01 scripts/testu01/

# Stream until BigCrush exits (default BIGCRUSH_MEGABYTES=0)
./scripts/testu01/run_bigcrush.sh
# Results → benches/reports/v0.3/results/bigcrush_results.txt
```

Finite file input is **not** recommended: MultinomialOver alone needs ≫1 GiB, and a fixed 200 GiB cap ended mid-battery (see partial log `results/bigcrush_results_partial_200g_eof.txt`).

## Overview

TestU01 BigCrush runs 160 statistics. TestU01 treats a p-value outside roughly
(10⁻¹⁰, 1−10⁻¹⁰) as a failure (`eps`). A well-designed PRNG is expected to pass
all tests; even 1–2 failures warrant investigation.

### Families exercised (this run)

Among others: Serial/Collision MultinomialOver, BirthdaySpacings, ClosePairs,
SimpPoker, CouponCollector, Gap, Run, MaxOft, WeightDistrib, MatrixRank, GCD,
Savir2, RandomWalk1, LinearComp, LempelZiv, Fourier3, Hamming\*, AutoCor,
AppearanceSpacings, SampleMean/Prod/Corr, SumCollector, PeriodsInStrings,
LongestHeadRun.

## Historical status

| Date | Outcome |
|------|---------|
| 2026-05-09 | Infrastructure stub; file-based path documented |
| 2026-06-30 | Blocked on host TestU01 install; Docker path designed |
| 2026-07-23 | Streaming attempted; finite-cap / incomplete records |
| 2026-08-12 | **Clean pass** via Docker streaming + unlimited host pipe |

### Attempt log (2026-08-12)

| Step | Result |
|------|--------|
| Docker `qs-crypto-testu01` | Built and used |
| Finite 200 GiB stream | EOF mid-`sknuth_SimpPoker` (~45 p-values; no failures yet) |
| Unlimited stream fix | `stats --megabytes 0` + BrokenPipe exit |
| Full BigCrush | **All tests were passed** |
