# spin_backend — observer isolation + SpinPRNG seed path (research)

Backend-agnostic **spin evolution** interfaces and an **external jitter meter**
used only as an **isolation gate** (detect substrate observers). Seeds for
SpinPRNG come from `SpinSample`, never from timing (S1–S3).

| Doc | Role |
|-----|------|
| [`OBSERVER_ISOLATION.md`](OBSERVER_ISOLATION.md) | Threat model, architecture, seed rules |
| `src/` | Traits + backends + baseline helpers + session helper |
| `trin/spin_sample.trin` | Deterministic Trin kernel (no in-process timing) |

## Backends

| Backend | Feature | Role |
|---------|---------|------|
| `ClassicalMockBackend` | default | Interface stub |
| `BusyMockBackend` | default | Deterministic sample + CPU burn for gate experiments |
| `TrinBackend` | default | External `trin run`; wall time metered outside |
| `SpinLatticeBackend` | `spin-lattice` | Real `qs_crypto::SpinLattice` adapter |
| `QuantumSimBackend` | default | `DeviceSpinBackend` over simulated QPU shots |
| `QuantumDevice` / `VendorStubDevice` | default | Vendor-neutral device trait + stub |
| `product_seed` | `spin-lattice` | `QualifiedSeed` → product `SpinPrng` (research bridge) |

## Commands

```bash
cd research/spin_backend

cargo test
cargo test --features spin-lattice

cargo run --example isolation_demo
cargo run --example load_contention --release
cargo run --example load_contention --release -- --trin
cargo run --example load_contention --release --features spin-lattice -- --lattice
cargo run --example load_contention --release --features spin-lattice -- --all
cargo run --example load_contention --release -- --quantum
cargo run --example qualified_prng_demo --release --features spin-lattice
```

### Trin on PATH (recommended)

Install once so research code never needs a machine-specific absolute path:

```bash
# from your trin build tree (stable copy preferred over symlink)
mkdir -p ~/.local/bin
cp -f ./trin ~/.local/bin/trin && chmod +x ~/.local/bin/trin
# ensure ~/.local/bin is on PATH (macOS zsh often already has it)
hash -r && which trin && trin version
# re-copy after rebuilding trin
```

Override without PATH: `TRIN=/path/to/trin cargo test`.

`isolation_demo` — synthetic Clean / Abort / Reseed / S3 hygiene scenarios.

`load_contention` — calibrate idle baseline, then re-run under CPU burn threads;
reports Clean vs SuspectObserver rates and checks seed bytes stay fixed (S3).

**Not** product crypto. Do not wire into the product `qs_crypto` crate until reviewed.
