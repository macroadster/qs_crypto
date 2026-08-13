# dieharder 1 GiB — SpinPrng QS-256

## 2026-08-13 re-run (post-BigCrush)

| Field | Value |
|-------|--------|
| Stream | `stats --megabytes 1024` → `sut_a_spinprng.bin` (seed `stats-stream-000`) |
| Tool | Docker `qs-crypto-rng-tests`, dieharder **3.31.1**, `-a -g 201` |
| Size | 1 GiB |
| Wall | ~27 min |
| Max file rewinds | **229** |
| **PASSED** | **109** |
| **WEAK** | **5** |
| **FAILED** | **0** |

### WEAK (not FAIL)

| Test | p-value |
|------|---------|
| `diehard_operm5` | 0.995 |
| `sts_monobit` | 0.999 |
| `rgb_lagged_sum` n=31 | 0.00021 |
| `rgb_lagged_sum` n=32 | 0.996 |
| `dab_filltree` (one of two) | 0.00097 |

### Key tests previously sensitive

| Test | Result |
|------|--------|
| `diehard_opso` | **PASSED** p≈0.78 |
| `diehard_oqso` | **PASSED** p≈0.44 |
| `marsaglia_tsang_gcd` (both) | **PASSED** |
| `dab_bytedistrib` | **PASSED** |
| `dab_monobit2` | **PASSED** |

Raw log: `sut_a_spinprng_dieharder_1g_2026-08-13.txt` (also copied to `sut_a_spinprng_dieharder_1g.txt`).

Stream binary deleted after run (disk hygiene).

## Prior (2026-07-23, post expander fix)

Same headline: **109 PASSED / 5 WEAK / 0 FAILED**, OPSO/OQSO PASS. WEAK set differed slightly (seed/stream dependent), as expected for borderline p-values.
