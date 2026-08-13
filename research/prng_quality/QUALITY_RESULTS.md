# PRNG quality evaluation — results note

**Status:** Research evaluation (not a production clearance)  
**Date:** 2026-07-23  
**Question:** Does current work support a finding that a **good-quality PRNG** can be generated?

## Short answer

**Statistically strong yes for stream randomness; still no for “production CSPRNG / novel-permutation clearance.”**

| Claim | Supported? |
|-------|------------|
| SpinPrng can emit high-throughput byte streams from fixed / isolation / OS seeds | **Yes** (engineering) |
| Isolation-qualified seeds drive product SpinPrng without putting timing into the seed | **Yes** (S3 hygiene) |
| Internal extended battery (χ², monobit, lag corr, entropy) passes on 32–1024 MiB | **Yes** (gross-bias only) |
| dieharder full battery on 1 GiB **after expander fix** | **Yes — 0 FAILED** (5 WEAK; OPSO/OQSO PASS) |
| NIST / BigCrush external batteries | **Yes** (NIST largely pass; BigCrush **all 160 passed** 2026-08-12) |
| Cryptanalysis / formal security of sponge | **No** (not addressed by RNG batteries) |

---

## 1. Objects under test (SUT)

| ID | Definition | Purpose |
|----|------------|---------|
| **SUT-A** | `SpinPrng::with_params(label, QS256)` | Baseline product PRNG from fixed seed |
| **SUT-B** | `isolation_session` Clean → 32-byte qualified seed → same `SpinPrng` | Isolation research path |
| **SUT-C** | `SpinPrng` from 32-byte OS entropy | Fresh-seed control |

Isolation does **not** claim better statistical quality than A/C. It only changes **how the seed is obtained** (and whether isolation is asserted).

Harness: `research/prng_quality/`

```bash
cargo run --release --manifest-path research/prng_quality/Cargo.toml -- --mib 32
```

---

## 2. Internal battery (this machine, 2026-07-23)

**32 MiB** (first pass) and **1024 MiB** (dieharder prep), release (~400–700 MiB/s).

### 1024 MiB internal (pre-dieharder)

| SUT | byte χ² | bit ones | serial r | lag8 r | Shannon H | Verdict |
|-----|---------|----------|----------|--------|-----------|---------|
| SUT-A | 265.3 | 0.500005 | ~0 | ~0 | 8.000 | PASS |
| SUT-B | 307.7 | 0.499985 | ~0 | ~0 | 8.000 | PASS |
| SUT-C | 293.6 | 0.499999 | ~0 | ~0 | 8.000 | PASS |

Also verified: SUT-B deterministic under replay; SUT-A ≠ SUT-B streams; isolation `RequireIsolation` accepted.

Raw: `out/internal_battery.md` · streams: `out/sut_{a,b,c}_*.bin` (gitignored)

---

## 3. dieharder on 1 GiB (2026-07-23, Docker)

**Environment:** `qs-crypto-rng-tests`, `dieharder 3.31.1`, `-a -g 201` (file_input_raw).  
**Streams:** 1 GiB each (`sut_a_spinprng.bin`, `sut_b_isolation.bin`), generated ~688 MiB/s.  
**Runtime:** ~15 min per stream. Max file rewind during battery: **229** (vs thousands on old 100 MiB files).

| Stream | PASSED | WEAK | FAILED | Log |
|--------|--------|------|--------|-----|
| SUT-A (fixed seed) | **109** | **2** | **3** | `out/sut_a_spinprng_dieharder_1g.txt` |
| SUT-B (isolation seed) | **107** | **4** | **3** | `out/sut_b_isolation_dieharder_1g.txt` |

### FAILED tests (1 GiB)

| Test | SUT-A | SUT-B | Rewinds at fail | Notes |
|------|-------|-------|-----------------|-------|
| `diehard_opso` | FAILED p≈0 | FAILED p≈0 | **2** | Strong signal — not a wraparound artifact |
| `diehard_oqso` | FAILED p≈0 | FAILED p≈0 | **2** | Same; overlapping-tuples family with OPSO |
| `rgb_lagged_sum` n=31 | FAILED p≈0 | WEAK p≈4.5e-4 | 215 | High rewind; weaker evidence than OPSO/OQSO |
| `marsaglia_tsang_gcd` (2nd) | PASSED both | FAILED p≈0 + WEAK | 12 | Seed-dependent; A clean, B fails one subtest |

### WEAK (not FAIL)

- SUT-A: `sts_serial` n=9; `rgb_lagged_sum` n=15  
- SUT-B: `marsaglia_tsang_gcd` first; `sts_serial` n=14; `rgb_lagged_sum` n=24, n=31  

### Compared to 100 MiB dieharder (2026-06-30)

| Prior FAIL (100 MiB, heavy rewind) | 1 GiB result |
|-------------------------------------|--------------|
| `marsaglia_tsang_gcd` all streams | **Often PASS** (SUT-A); residual FAIL on SUT-B only |
| `dab_bytedistrib` | **PASSED** both |
| `dab_monobit2` | **PASSED** both |
| many `rgb_lagged_sum` | **Mostly PASSED**; isolated n=31 issues |
| (not highlighted) OPSO/OQSO | **Consistent FAILED** both SUTs @ 2 rewinds |

**Conclusion from dieharder:** Larger files cleared several prior FAILs as likely **file-wrap artifacts**. Remaining **OPSO/OQSO failures on both product and isolation seeds with only 2 rewinds** are the primary quality defect signal. Isolation seeding does **not** fix them (same sponge).

---

## 4. Other external suites (prior + status)

### NIST SP 800-22 (2026-06-30, Docker STS 2.1.2)

- 5 × 100 MiB streams, α=0.01, 1M bits × 100 sequences.
- **Largely passing**; isolated proportion `*` on some streams/templates.
- Source: `benches/reports/v0.3/nist_sp800_22.md`.

### TestU01 BigCrush (2026-08-12, Docker streaming)

- Infrastructure: `scripts/testu01/run_bigcrush.sh` (`stats --megabytes 0` → `bigcrush_stream`).
- **All 160 statistics passed** (TestU01 1.2.3, generator `SpinPrng_QS256_stdin`).
- Total CPU 06:23:48.75; ~1.33 TiB streamed through pipe (no multi-GiB file on disk).
- Raw: `benches/reports/v0.3/results/bigcrush_results.txt` · summary: `benches/reports/v0.3/testu01_bigcrush.md`.

---

## 5. Isolation research vs quality research

| Isolation research (`spin_backend`) | Quality research (this note) |
|-------------------------------------|------------------------------|
| Seed hygiene, gate, backends | Stream statistics |
| “Can we seed SpinPrng safely under observer policy?” | “Is the stream random enough?” |
| Does **not** prove quality | Does **not** prove isolation |

Crossing the streams: SUT-B shows isolation seeds are **usable** by product SpinPrng and pass the same internal smoke tests as A/C. That is **compatibility**, not a quality upgrade.

---

## 6. Finding (formal)

> **Finding F-Q1 (updated 2026-08-12, post-BigCrush):** The prior OPSO/OQSO failures were a **real expander defect** (hard re-key / CTR-style construction), not isolation and not only 100 MiB rewinds. After continuous SplitMix + soft sponge re-mix, SpinPrng (QS-256) achieves: internal battery PASS; dieharder 1 GiB **109 PASSED / 5 WEAK / 0 FAILED** (OPSO/OQSO PASS); NIST historically largely pass; **TestU01 BigCrush: all 160 statistics passed** (Docker streaming, 2026-08-12). Isolation seeding neither caused nor cured OPSO; it remains a separate observer-meter track.

**Implication:** External statistical evidence for SpinPrng is now **strong** across dieharder, NIST, and BigCrush. This still does **not** prove cryptographic security of the novel sponge permutation (no reduction / third-party cryptanalysis). Prefer hybrid/SHAKE paths for asymmetric hardness claims; treat SpinPrng as statistically validated research-grade, not a drop-in CSPRNG clearance.

---

## 7. Next steps

1. Optional: re-run dieharder on a fresh 1 GiB stream if residual WEAKs need re-check.  
2. Keep BigCrush streaming path as the canonical external gate (`run_bigcrush.sh`).  
3. Proceed on **cryptanalysis / ProVerif / third-party review** — statistical suites no longer block Priority 1.

```bash
# Internal
cargo run --release --manifest-path research/prng_quality/Cargo.toml -- --mib 64

# dieharder 1 GiB (Docker)
docker run --rm -v "$PWD/research/prng_quality/out:/data:ro" -v "$PWD/research/prng_quality/out:/out" \
  qs-crypto-rng-tests dieharder -a -g 201 -f /data/sut_a_spinprng.bin | tee research/prng_quality/out/sut_a_spinprng_dieharder_1g.txt

# BigCrush stream
bash scripts/testu01/run_bigcrush.sh
```

---

## 8. OPSO/OQSO root cause and fix (2026-07-23)

### Diagnosis

| Generator (1 GiB) | OPSO | OQSO |
|-------------------|------|------|
| SpinPrng **before** fix (CTR `key⊕ctr` / hard re-key SplitMix) | FAILED p≈0 | FAILED p≈0 |
| Pure SplitMix64 control | PASSED | PASSED |
| Once-seed SplitMix from sponge keys (no re-key) | PASSED | PASSED |
| SpinPrng **after** continuous-state soft re-mix | **PASSED** | **PASSED** |

**Root cause:** Not “dieharder is broken” (control passes). Not isolation.  
Hard **re-seeding / resetting** the 64-bit expander every 32 KiB (and the older CTR `key ⊕ ctr·γ` form) injects overlapping-tuple structure that OPSO/OQSO detect at p≈0.

**Fix (product `squeeze_streaming_into`):**
1. Use SplitMix64 Weyl advancement (not CTR XOR).
2. Keep one continuous `state` across the whole squeeze.
3. On lattice re-mix, **fold** new rate keys into `state` (XOR/mul/add) instead of replacing it.
4. Re-mix interval increased to 64 KiB words (512 KiB) for throughput.

dieharder still labels OPSO/OQSO “Suspect” reliability, but the control/fix A-B table makes the defect and fix real.

### Post-fix verification (1 GiB SpinPrng, Docker dieharder 3.31.1)

| Check | Result |
|-------|--------|
| OPSO alone | **PASSED** p≈0.66 |
| OQSO alone | **PASSED** p≈0.75 |
| Full `-a` battery | **PASS 109 · WEAK 5 · FAIL 0** |

WEAK only (acceptable noise; not FAIL): `diehard_operm5`, `sts_monobit`, `rgb_lagged_sum` n=31/32, `dab_filltree` one subtest.  
Log: `out/sut_a_after_remix_dieharder_1g.txt`.

---

## 9. BigCrush wall-time estimate (updated throughput)

| Factor | Value |
|--------|--------|
| Host SpinPrng (release, post-opt) | **~400–700 MiB/s** |
| Old bottleneck (pre-opt) | ~0.8 MiB/s → **days** of generation alone |
| TestU01 BigCrush compute (literature / practice) | **~3–5 hours** CPU for a fast RNG on a modern laptop |
| Raw u32 demand (order-of-magnitude) | up to ~2³⁵–2³⁸ samples (~128 GiB–1 TiB if fully materialized); streaming avoids disk |
| Generation time @ 500 MiB/s for 256 GiB | **~9 minutes** |
| Generation time @ 500 MiB/s for 1 TiB | **~35 minutes** |

**Estimate for this machine:** **about 3.5–6 hours wall clock**, dominated by **TestU01 inside Docker**, not by SpinPrng.  
If the container is CPU-throttled or single-core slow, budget **up to ~8 hours**.  
Pipe: `scripts/testu01/run_bigcrush.sh` (stream stdin). Cap `BIGCRUSH_MEGABYTES` high enough to avoid EOF (e.g. 200000–500000).

---

## Changelog

| Date | Note |
|------|------|
| 2026-07-23 | Initial quality note: SUT A/B/C, internal 32 MiB PASS; F-Q1 draft. |
| 2026-07-23 | 1 GiB dieharder SUT-A/B via Docker: 109/107 PASS; OPSO+OQSO FAIL both; many old FAILs cleared; F-Q1 updated. |
| 2026-07-23 | Root cause: hard re-key/CTR expander; soft continuous SplitMix fix; OPSO/OQSO PASS; BigCrush est. 3.5–6 h. |
