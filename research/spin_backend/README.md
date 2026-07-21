# spin_backend — observer isolation + SpinPRNG seed path (research)

Backend-agnostic **spin evolution** interfaces and an **external jitter meter**
used only as an **isolation gate** (detect substrate observers). Seeds for
SpinPRNG come from `SpinSample`, never from timing (S1–S3).

| Doc | Role |
|-----|------|
| [`OBSERVER_ISOLATION.md`](OBSERVER_ISOLATION.md) | Threat model, architecture, seed rules |
| `src/` | Traits + classical mock + session helper |

```bash
cd /Users/eric/sandbox/qs_crypto/research/spin_backend
cargo test
cargo run --example isolation_demo
```

`isolation_demo` walks eight scenarios: Clean seed + stream preview, simulated
observer + Abort, ReseedOsUnqualified, S3 seed hygiene (timing ≠ seed), secret
sensitivity, AllowUnqualified, live `WallClockMeter`, and is/is-not summary.

**Not** product crypto. Do not wire into the product `qs_crypto` crate until reviewed.
