# NIST SP 800-22 Statistical Test Suite Report

**Date:** 2026-06-30 (Docker re-run)  
**Version:** QS-Crypto v0.3  
**Primitive under test:** SpinPrng (QS-256 sponge, 32 permutation rounds)

## Test Data

Five independent 100 MiB streams generated with:

```
cargo run --release --bin stats -- --megabytes 100 --streams 5 --output-dir stats_out/
```

Streams seeded with deterministic labels `stats-stream-000` through `stats-stream-004`
using `SpinPrng::with_params()` at `SecurityLevel::QS256`.

Files (present on disk after generation):

- `stats_out/spinprng_qs256_stream000.bin` (104,857,600 bytes)
- `stats_out/spinprng_qs256_stream001.bin` (104,857,600 bytes)
- `stats_out/spinprng_qs256_stream002.bin` (104,857,600 bytes)
- `stats_out/spinprng_qs256_stream003.bin` (104,857,600 bytes)
- `stats_out/spinprng_qs256_stream004.bin` (104,857,600 bytes)

Quick bias checks during generation: all five streams **PASS** (byte χ² and bit balance).

## Internal Quick Battery Results

The built-in fast battery (`--quick`) was run as a preliminary check historically:

| Test | Result | Value |
|------|--------|-------|
| Byte frequency chi-squared (255 df) | PASS | 251.7 (critical: <350) |
| Bit balance (ones fraction) | PASS | 0.500133 (within ±0.5%) |
| Permutation diffusion (1500 trials) | PASS | 255.9/256 spins differ (100.0%) — excellent full avalanche |
| Bit-level avalanche | PASS | 1521.6/3072 bits flip (49.5%) |
| Diffusion range | PASS | [254, 256] — extremely tight |

## Environment

Runs used Docker image `qs-crypto-rng-tests` (Ubuntu 22.04 + `dieharder` 3.31.1 + NIST STS 2.1.2).

Build / re-run:

```bash
docker build -t qs-crypto-rng-tests scripts/rng_docker/
./scripts/rng_docker/run_suites.sh
# or manual commands below
```

## External Test Suite: dieharder (full battery, all 5 streams)

### How to run

```bash
docker run --rm \
  -v "$PWD/stats_out:/data:ro" \
  -v "$PWD/benches/reports/v0.3/results:/out" \
  qs-crypto-rng-tests \
  bash -c 'for f in /data/spinprng_qs256_stream*.bin; do
    base=$(basename "$f" .bin)
    dieharder -a -g 201 -f "$f" | tee "/out/${base}_dieharder.txt"
  done'
```

Raw logs: `benches/reports/v0.3/results/spinprng_qs256_stream00{0..4}_dieharder.txt`

### Summary counts (assessment lines)

| Stream | PASSED | WEAK | FAILED |
|--------|--------|------|--------|
| 000 | 94 | 11 | 9 |
| 001 | 92 | 12 | 10 |
| 002 | 94 | 11 | 9 |
| 003 | 93 | 11 | 10 |
| 004 | 96 | 7 | 11 |

### FAILED tests (flagged for investigation)

Failures that **repeat across multiple independent streams** (not explained by a single-seed fluke):

| Test | Streams with FAILED | Notes |
|------|---------------------|--------|
| `marsaglia_tsang_gcd` | 000–004 (one or both subtests) | Consistent; needs investigation |
| `rgb_lagged_sum` (several ntuples, esp. 4, 9, 15, 19, 23, 24, 29, 31) | 000–004 | Many ntuples fail; **also** dieharder rewound each 100 MiB file **thousands of times** during these tests (finite-file wraparound artifact is a known caveat for `file_input_raw` when tests demand more data than the file holds) |
| `dab_bytedistrib` | 000–004 | Consistent fail with p≈0 |
| `dab_monobit2` | 000–004 | Consistent fail with p=1.0 (opposite extreme) |
| `diehard_opso` | 001 only | Single-stream |

**Caveat:** For a 100 MiB file, dieharder prints `# The file file_input_raw was rewound N times` with N often >2000 on lagged-sum / DAB tests. Wraparound re-uses the same bytes and can induce spurious failures that are **not** equivalent to testing a true infinite PRNG stream. Failures that appear **only** after heavy rewind should be re-checked on a much larger stream (e.g. multi-GiB) before treating them as definitive cryptanalytic defects. Failures on early tests with little rewind (e.g. `marsaglia_tsang_gcd`, `diehard_opso` on stream 001) are stronger signals.

### WEAK assessments

Occasional WEAK (p-value near 0.001 or 0.999) appeared on classical diehard tests (`opso`, `squeeze`, `craps`, etc.) and on some `rgb_lagged_sum` / `sts_serial` ntuples. Per dieharder guidance, 1–2 WEAKs in a full battery can occur for a good RNG; here WEAK counts are elevated (~7–12 per stream), which also warrants follow-up—especially together with the consistent FAILs above.

## External Test Suite: NIST STS 2.1.2

### Parameters

- Block / sequence length: **1,000,000 bits**
- Number of sequences: **100** per stream (uses 100 Mbit ≈ 12.5 MiB of each file; binary mode)
- Significance level: **α = 0.01**
- Apply all 15 tests (default STS parameters)

### How to run

```bash
docker run --rm \
  -v "$PWD/stats_out:/data:ro" \
  -v "$PWD/benches/reports/v0.3/results:/out" \
  qs-crypto-rng-tests \
  bash -c 'STS=/opt/sts-2.1.2/sts-2.1.2; cd $STS
  for f in /data/spinprng_qs256_stream*.bin; do
    base=$(basename "$f" .bin)
    find experiments/AlgorithmTesting -name "*.txt" -delete 2>/dev/null || true
    { echo 0; echo "$f"; echo 1; echo 0; echo 100; echo 1; } | ./assess 1000000
    cp experiments/AlgorithmTesting/finalAnalysisReport.txt "/out/${base}_nist_finalAnalysisReport.txt"
  done'
```

Raw reports: `benches/reports/v0.3/results/spinprng_qs256_stream00{0..4}_nist_finalAnalysisReport.txt`

### Interpretation

STS marks a test with `*` when the **proportion** of passing sequences is below the allowed interval for α=0.01 and 100 sequences (roughly **≥ 96/100** for most tests; Random Excursions variants use a reduced denominator when applicable).

### Results

| Stream | Proportion failures (`*`) | Detail |
|--------|---------------------------|--------|
| 000 | **none** | All listed tests met proportion / uniformity thresholds |
| 001 | **1** | `RandomExcursionsVariant` 58/62 * |
| 002 | **1** | `NonOverlappingTemplate` 94/100 * (one template) |
| 003 | **1** | `NonOverlappingTemplate` 95/100 * (one template) |
| 004 | **none** | All listed tests met thresholds |

Overall: NIST STS is **largely passing** at α=0.01. Isolated proportion misses on one NonOverlappingTemplate parameter or one RandomExcursionsVariant row on some streams are marginal and should be re-checked with more sequences or another seed; they are **not** a blanket failure of all 15 tests.

## Status

- [x] Stream generation commands documented
- [x] Stream artifacts generated (`stats_out/*.bin`, 5 × 100 MiB)
- [x] Internal quick battery: PASS
- [x] dieharder full suite on all 5 streams (Docker)
- [x] NIST STS (α=0.01, 1M bits × 100 sequences) on all 5 streams (Docker)
- [x] FAILED/WEAK results recorded and flagged for investigation

### Investigation flags (open)

1. **dieharder `marsaglia_tsang_gcd` FAILED** on all streams — prioritize re-run with ≥1 GiB continuous stream without wraparound.
2. **dieharder `dab_bytedistrib` / `dab_monobit2` FAILED** on all streams — same re-run requirement; interpret with rewind caveat.
3. **dieharder `rgb_lagged_sum` multi-ntuple FAILED** — heavily confounded by file rewind; re-test on larger file.
4. **NIST** occasional `NonOverlappingTemplate` / `RandomExcursionsVariant` proportion `*` on streams 001–003 — minor; re-run with more bitstreams if needed.
5. **TestU01 BigCrush** still not run (see `testu01_bigcrush.md`); needs TestU01 + 1 GiB stream (~4 h).

### Attempt / run log (2026-06-30)

| Step | Result |
|------|--------|
| Generate 5 × 100 MiB streams | OK (~0.1 MiB/s host generation; all quick bias PASS) |
| Docker `qs-crypto-rng-tests` | Built from `scripts/rng_docker/Dockerfile` (dieharder + STS 2.1.2) |
| dieharder `-a -g 201` × 5 | Completed; logs under `results/*_dieharder.txt` |
| NIST STS assess 1e6 × 100 × 5 | Completed; `finalAnalysisReport.txt` copies under `results/` |
