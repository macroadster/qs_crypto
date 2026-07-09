# RNG statistical suites (Docker)

Image `qs-crypto-rng-tests` provides:

- **dieharder** 3.31.1 (Ubuntu package)
- **NIST SP 800-22 STS** 2.1.2 (`assess`)

## Build

```bash
docker build -t qs-crypto-rng-tests scripts/rng_docker/
```

## Generate streams (host)

```bash
cargo run --release --bin stats -- --megabytes 100 --streams 5 --output-dir stats_out/
```

## Run suites

```bash
./scripts/rng_docker/run_suites.sh
```

Results land in `benches/reports/v0.3/results/`. Summary write-up:
`benches/reports/v0.3/nist_sp800_22.md`.

## Notes

- NIST menu automation: generator `0` (file), apply all tests `1`, binary mode `1`,
  100 bitstreams of 1,000,000 bits.
- dieharder on finite files may rewind the input many times; failures under heavy
  rewind need confirmation on larger streams.
