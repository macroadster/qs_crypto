# prng_quality — SpinPrng quality evaluation (research)

Answers: *can we claim a good-quality PRNG?* with an explicit SUT definition,
an always-on internal battery, and pointers to external suites.

**Canonical finding:** [`QUALITY_RESULTS.md`](QUALITY_RESULTS.md) (**F-Q1**: not yet).

## Run

```bash
# from repo root
cargo run --release --manifest-path research/prng_quality/Cargo.toml -- --mib 32

# larger streams for offline dieharder
cargo run --release --manifest-path research/prng_quality/Cargo.toml -- --mib 256 --out-dir research/prng_quality/out

# optional external (no-op if Docker missing)
bash research/prng_quality/scripts/run_external_if_available.sh
```

## SUT

| ID | Seed path |
|----|-----------|
| SUT-A | Fixed label → `SpinPrng` |
| SUT-B | `spin_backend` isolation Clean seed → `SpinPrng` |
| SUT-C | OS 32 bytes → `SpinPrng` |

## Outputs

- `out/internal_battery.md` — last internal run table  
- `out/sut_*.bin` — streams for external tools (gitignored)

## Relation to spin_backend

Isolation research proves **seed hygiene and gating**, not stream quality.
This crate tests whether isolation seeds still produce streams that pass the
same smoke tests as ordinary product seeds.
