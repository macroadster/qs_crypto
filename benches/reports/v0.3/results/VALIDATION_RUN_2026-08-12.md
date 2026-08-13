# Validation run — 2026-08-12 (min-disk)

## Setup
- Reclaimed ~9 GiB: deleted `research/prng_quality/out/*.bin` and `stats_out/*` (text logs kept).
- Docker image: `qs-crypto-testu01` (built from `scripts/testu01/`).
- Method: **streaming** BigCrush — no multi-GiB PRNG files on disk.

## Internal battery (complete)
```
cargo run --release --manifest-path research/prng_quality/Cargo.toml --bin prng_quality -- --mib 32
```
- SUT-A / SUT-B / SUT-C: **ALL PASS** (32 MiB)
- Temp `.bin` streams deleted after run
- Log: `research/prng_quality/out/internal_battery.md`

## BigCrush attempt 1 — EOF (incomplete)
- Cap: `BIGCRUSH_MEGABYTES=200000` (200 GiB finite)
- Host wrote 200 GiB @ ~40.5 MiB/s in ~82 min, then closed pipe
- BigCrush hit `EOF/short read` mid-`sknuth_SimpPoker` after ~45 p-values
- Partial log: `bigcrush_results_partial_200g_eof.txt`
- p-values so far: min 0.0059, max 0.9975; no eps

## Fix applied
- `stats --megabytes 0 --output -` = unlimited stream until consumer closes pipe
- Banner moved off stdout when streaming
- `run_bigcrush.sh` default is unlimited (`BIGCRUSH_MEGABYTES=0`)

## BigCrush attempt 2 — **PASSED**

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
| Streamed bytes | 1 428 418 461 696 (~1.33 TiB) |
| Host rate | ~53.9 MiB/s for 25254 s wall |
| Disk for stream | ~0 (pipe); results ~95 KB |
| p-values | min 0.0054, max 0.9975; no eps / no p&lt;1e-4 |
| Raw | `bigcrush_results.txt` |
| Summary | `../testu01_bigcrush.md` |

## Prior external evidence (not re-run this session)
- dieharder 1 GiB post-expander-fix: 109 PASS / 5 WEAK / 0 FAIL
- NIST SP 800-22: largely pass

## Status
- [x] Disk reclaim
- [x] Internal battery
- [x] Diagnose 200 GiB EOF
- [x] Unlimited stream fix
- [x] BigCrush complete — **All tests were passed**
