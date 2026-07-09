# QS-Crypto — TODO

## Priority 1 — Run external statistical test suites

Run dieharder, NIST STS, and TestU01 BigCrush on the SpinPrng output streams.
Docker image + runner (dieharder / NIST): `scripts/rng_docker/` (`qs-crypto-rng-tests`).
TestU01 image + runners: `scripts/testu01/` (`qs-crypto-testu01`) —
`bigcrush_stream.c` (stdin pipe; preferred), `bigcrush_wrapper.c` (file input),
`run_bigcrush.sh`.

- [x] Run dieharder full suite on all 5 streams (Docker `dieharder -a -g 201`)
- [x] Run NIST STS (α=0.01, 1M bits × 100 sequences per stream, Docker STS 2.1.2)
- [ ] Finish TestU01 BigCrush on continuous SpinPrng stream (in progress — see status)
- [ ] Record BigCrush results under `benches/reports/v0.3/` (results file + summary markdown)
- [x] Record results in `benches/reports/v0.3/nist_sp800_22.md` (dieharder + NIST)
- [x] Flag FAILED/WEAK results for investigation (see report; open items below)

**Status (2026-06-30):** **dieharder + NIST completed via Docker.** Raw logs under
`benches/reports/v0.3/results/`. NIST largely passes (isolated proportion `*` on some
streams). dieharder reports **consistent FAILED** on `marsaglia_tsang_gcd`,
`dab_bytedistrib`, `dab_monobit2`, and multiple `rgb_lagged_sum` ntuples — partly
confounded by thousands of file rewinds on 100 MiB inputs; **re-test on multi-GiB
streams before treating as definitive**.

**BigCrush (updated 2026-06-30):** Finite **1 GiB files are insufficient** (first
MultinomialOver alone needs >1 GiB). Approach changed to **on-the-fly streaming**:

```bash
./scripts/testu01/run_bigcrush.sh
# stats --megabytes 200000 --output - | docker run --rm -i --entrypoint bigcrush_stream qs-crypto-testu01
```

- Host **`stats` / SpinPrng** is the bottleneck at **~0.8 MiB/s** release (was
  ~0.1 MiB/s before lattice hot-path optimisations; one core, almost all time in
  `SpinLattice::step` via mini-block permutes every 48 bytes). Docker stdin is
  **not** the stall.
- Wall time at that rate is on the order of **~many hours to ~1 day** (tens of
  GiB of stream; script caps at 200 000 MiB to avoid early EOF). Expect little
  output in `benches/reports/v0.3/results/bigcrush_results.txt` until early
  battery tests complete.
- A run was started via `run_bigcrush.sh` (container `bigcrush_stream`); treat as
  **in progress** until `=== BigCrush complete ===` or an EOF/short-read exit.

**Speed-up options (optional follow-ups, restart required):** optimize
`SpinLattice::step`; document alternate squeeze (`squeeze_raw` / larger mini-block)
if testing a defined variant; Docker/pipe tweaks will not move the needle.

## Priority 2 — Investigate differential analysis plateau

The differential report (`benches/reports/v0.3/differential.md`) showed per-spin
max DP plateauing at ~0.92 (`log2 ≈ -0.1`) even at 32 rounds, instead of
decaying exponentially toward `2^{-128}`. Either the metric is measuring
per-spin identity rate rather than per-position differential probability, or
the permutation has high-probability truncated differentials.

- [x] Review the differential measurement code in `src/bin/stats.rs`
- [x] Determine if the metric is correct or measuring the wrong quantity
- [x] If metric is wrong, fix and re-run; if real, assess impact on security claims
- [x] Update `benches/reports/v0.3/differential.md` with findings

**Finding:** The old "Max DP (per spin)" column was **mode probability of the output
differential weight histogram** (`max_w Pr[wt(Δ_out)=w]`), not classical or per-position
DP. Under full avalanche that concentrates near weight ≈ N, so it naturally plateaus
near ~0.9. Corrected metrics add **Max id rate** (`max_i Pr[out_i unchanged]`) and
**Mean id rate** (`mean_i Pr[out_i unchanged]`). At full rounds, mean id ≈ 1/q ≈ 0.0003
(direct estimator of per-position identity); max id remains ~0.0015–0.002 because it is
elevated by max-over-N (multiple-testing), not because mixing failed. **Security claims
unaffected** — no evidence of high-probability truncated differentials. Re-ran with
`--differential --trials 2000 --max-weight 3`.

## Priority 3 — Verify NTT-128 is active for QS128

QS128 uses `ring_dim: 128`. The NTT-128 code exists in `src/kem/ntt.rs` and
`poly_mul` is gated on `uses_ntt_mul(n)` (true for 128 and 256) and calls NTT-128
for QS128. Verify this path is actually hit and QS128 is not falling through to
schoolbook O(N²).

- [x] Add a test or assertion confirming NTT-128 is used for QS128 KEM operations
- [x] Benchmark QS128 poly_mul to confirm O(N log N) performance

**Done:** `uses_ntt_mul(n)` helper; unit tests in `kem::ring` and `kem::ntt` (NTT-128
matches schoolbook; QS128 `ring_dim == 128` uses NTT path); Criterion benches
`poly_mul_n128/{ntt,schoolbook}_poly_mul` and `keygen_qs128` in `benches/qs_crypto.rs`.

**Path proof:** `poly_mul` gates NTT on `uses_ntt_mul` (single source of truth);
schoolbook-agreement tests prove correctness, not path alone — path is enforced by that
gate plus Criterion `poly_mul_n128` timing.

## Priority 4 — Set up GitHub Actions CI

No CI pipeline exists yet. Prevents regressions as the library evolves.

- [x] Create `.github/workflows/ci.yml`
- [x] Jobs: `cargo test`, `cargo clippy --all-targets -- -D warnings -A clippy::needless_range_loop -A clippy::type_complexity -A clippy::print_literal`, `cargo fmt --check`
- [x] KAT vector verification (`tests/kat.rs` + `gen_kat` drift check)
- [x] Optional: `cargo miri test` (nightly, **advisory** UB detection; `continue-on-error` so it does not fail the workflow)
- [x] Optional: `cargo bench --no-run` compile check (no host-dependent regression thresholds)

## Priority 5 — Run ProVerif model

A formal model exists at `docs/proverif/qs_crypto.pv` covering the PAKE +
Double Ratchet composition. No record of it being verified.

- [ ] Install ProVerif
- [ ] Run `proverif docs/proverif/qs_crypto.pv`
- [ ] Document verification results (mutual auth, session key secrecy, forward secrecy, break-in recovery)
- [x] Add results stubs / how-to to `docs/proverif/README.md`

**Status (2026-06-30):** **Blocked on install.** `brew install proverif` failed (no formula);
opam/OCaml not on host. README updated with install-from-source instructions, query table
with *not yet run* statuses, and attempt log.

## Priority 6 — Publish for third-party cryptanalysis review

Depends on priorities 1–2 being complete. The review request doc exists at
`docs/SPINLATTICE_REVIEW_REQUEST.md`.

- [x] Finalize statistical evidence for priority 2 (metric corrected; avalanche confirmed)
- [ ] Finalize statistical evidence for priority 1 (dieharder/NIST run; open FAIL investigation + BigCrush in progress / streaming)
- [ ] Submit to IACR ePrint (SG-LWE hardness assumption) — **human-only**
- [ ] Post to crypto/real-world-crypto mailing lists — **human-only**
- [ ] Direct outreach to lattice cryptographers — **human-only**
