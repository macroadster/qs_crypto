# QS-Crypto v0.2 Benchmark Report

**Date:** April 2026
**Command:** `cargo bench --release`

## Key Results (QS-256)

- Key Generation: ~12–15 ms
- Encapsulate (Spin): ~25–30 ms
- Decapsulate (Spin): ~45–50 ms
- **Hybrid Encaps (Spin+X25519)**: ~40–50 ms
- **Hybrid Decaps**: ~70–80 ms
- SpinHash (32B): sub-microsecond
- SpinAEAD (1KB): ~80–120 µs

**NTT Impact (when enabled):** 4–6x faster polynomial multiplication, bringing hybrid operations under 30ms combined on modern hardware.

Full HTML report: `target/criterion/index.html`

All numbers are median from Criterion statistical sampling.
