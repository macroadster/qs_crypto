# Observer isolation for SpinPRNG backends

**Status:** Research draft (interface freeze candidate)  
**Home:** `qs_crypto/research/spin_backend/`  
**Product:** useful `SpinPRNG` seeds from spin / quantum / Trin evolution  
**Non-goals:** network MITM-as-TLS; jitter-in-KDF hardness; conflating process
observers with network MITM

---

## 1. Thesis

QS-Crypto’s Layer‑1 usefulness does not require a QPU today: classical
`SpinLattice` + sponge already drives `SpinPRNG`. The research goal is a
**backend-agnostic evolution interface** such that:

1. The same **crypto path** works for classical lattice, Trin soft simulation, or
   a future quantum backend.
2. **Jitter / wall-clock** of a scheduled evolution is a meter for whether
   **another observer coupled to the execution substrate** — not entropy and not
   hardness (F1).
3. SpinPRNG is only released under an explicit **isolation verdict**, or is
   clearly labeled as isolation-unqualified.

```text
Spin dynamics  →  SpinSample  →  SpinPRNG seed     (crypto channel)
External meter →  TimingReport → IsolationGate     (observer channel)
```

These channels **must not mix** in the seed derivation for hardness claims.

---

## 2. Threat model (this exercise)

### In scope

| Adversary | Goal | Defense surface |
|-----------|------|-----------------|
| **Process observer** | Trace, debug, schedule-contend, or otherwise couple to the *local* evolution run | `ObserverMeter` + `IsolationGate` |
| **Physical coupler** (QPU path, research) | Extra measurement / crosstalk that shifts job timing or fidelity proxies | Same gate + optional HW stats in `TimingReport` |
| **Passive wire eavesdropper** | Recover PRNG output / messages | SpinPRNG / sponge / KEM assumptions — *not* the meter |

### Out of scope / non-claims

- Network MITM detection via RTT (different problem; cert pin / PAKE / fingerprint).
- “Jitter ⇒ IND-CPA” or “observer-free ⇒ unforgeable keys.”
- Trin wall-clock ≡ quantum state disturbance (classical meter can move with sample fixed).
### Isolation assumption (explicit, research-grade)

> If `IsolationGate` returns `Clean` for profile \(P\), the evolution run is
> consistent with the unperturbed baseline for \(P\). This is a **heuristic
> tamper / coupling sensor**, not a cryptographic reduction. A sophisticated
> observer may try to match the baseline.

---

## 3. Architecture

```
┌────────────────────────────────────────────────────────────┐
│  Layer 1 (product): SpinPRNG / SpinKDF / SpinAEAD          │
│  seed = H("qs-spinprng-v1" ‖ backend_id ‖ program_hash     │
│            ‖ SpinSample)                                   │
│  NEVER: H(... ‖ TimingReport) for hardness                 │
└───────────────────────────▲────────────────────────────────┘
                            │ SpinSample (only if policy allows)
┌───────────────────────────┴────────────────────────────────┐
│  IsolationGate                                             │
│  gate(report, profile) → Clean | SuspectObserver | …       │
│  policy: Abort | ReseedOsUnqualified | AllowUnqualified    │
└──────────────▲────────────────────────▲────────────────────┘
               │ SpinSample             │ TimingReport
┌──────────────┴──────────┐  ┌──────────┴────────────────────┐
│  SpinBackend            │  │  ObserverMeter (EXTERNAL)     │
│  prepare / evolve /     │  │  start/stop around evolve+    │
│  measure                │  │  measure only — not inside    │
│                         │  │  the math path (F1)           │
└──────────────▲──────────┘  └───────────────────────────────┘
       ┌───────┼────────────────────┐
       │       │                    │
 Classical  TrinBackend      QuantumBackend
 SpinLattice (future)         (future)
```

Sketch crate: `research/spin_backend` (`spin_backend` package) — traits +
classical mock + isolation session helper. **Not** wired into product `qs_crypto`
until review.

---

## 4. Types

### 4.1 `EvolutionSpec`

Identifies **what** is scheduled (so baselines and program hashes are meaningful).

| Field | Meaning |
|-------|---------|
| `backend_id` | `"classical-spinlattice-v1"`, `"trin-v1"`, `"qpu-…"` |
| `program_hash` | Hash of lattice params / Trin source / QASM |
| `params` | QS-128/192/256 or research params |
| `schedule` | rounds / shots / anneal schedule id |
| `mode` | `DeterministicClassical` \| `PhysicalShots` |

### 4.2 `SpinSample`

Opaque bytes (or structured spins later) that **may** feed SpinPRNG.

- Classical: encode lattice spins or sponge-ready bytes after `K` steps.  
- Trin: hardened soft state / structured digest of unit/trit outcomes.  
- QPU: extractor output from shot histogram (research).

**Invariant (classical deterministic mode):**  
`ObserverMeter` on/off must **not** change `SpinSample`.

### 4.3 `TimingReport`

| Field | Meaning |
|-------|---------|
| `wall_ns` | External wall duration of evolve+measure |
| `label` | Session / phase tag |
| `load_hint` | Optional host load proxy |
| `queue_ms` | Optional simulated/vendor queue wait (ms) |
| `shot_count` | Optional shot count for QPU jobs |
| `fidelity_proxy` | Optional \[0,1\] research quality proxy |

Public-safe to log for experiments. **Not** secret key material. Use
`TimingReport::with_job_stats` to attach [`JobStats`] from `QuantumSimBackend`.

### 4.4 `IsolationProfile`

| Field | Meaning |
|-------|---------|
| `spec_fingerprint` | `backend_id ‖ program_hash ‖ schedule` |
| `baseline_p50_ns`, `baseline_p95_ns`, `baseline_iqr_ns` | Clean-lab baselines |
| `margin_ns`, `iqr_factor` | Tolerances |
| `min_samples` | For baseline construction |

### 4.5 `IsolationVerdict`

| Verdict | Meaning |
|---------|---------|
| `Clean` | Within envelope; isolation-qualified sample OK |
| `SuspectObserver` | Timing inconsistent with baseline; possible coupling |
| `Inconclusive` | Cold start / no baseline / too few samples |
| `BackendError` | Evolution failed |

### 4.6 `ReleasePolicy`

| Policy | Behavior |
|--------|----------|
| `Abort` | Return error; no PRNG |
| `ReseedOsUnqualified` | SpinPRNG from OS entropy; mark `isolation=false` |
| `AllowUnqualified` | Use `SpinSample` anyway; mark `isolation=false` (debug only) |

Default research policy for “isolation-claimed” APIs: **`Abort`** or
**`ReseedOsUnqualified`**, never silent `AllowUnqualified` in product paths.

---

## 5. Seed derivation (crypto channel)

```text
LP(x) = u64le(len(x)) ‖ x

SpinPRNG_seed =
  H( "qs-spinprng-v1" ‖ LP(backend_id) ‖ LP(program_hash)
     ‖ LP(schedule_id) ‖ LP(SpinSample) )
```

- `H` = product sponge absorb path or SHAKE256 during research hybrid.  
- Domain separation versioned; **all variable fields length-prefixed** (no concat ambiguity).  
- **Forbidden in hardness path:** `wall_ns`, jitter CV, or any meter fields.

Unqualified reseed (`ReseedOsUnqualified`): `H(domain ‖ LP(tag) ‖ LP(getrandom(32)))` —
not `SystemTime`.

Optional public nonce (counter, OS random) may be absorbed for multi-stream
independence; that nonce is not the isolation meter.

`WallClockMeter::stop` without a live `start` (including double-stop) returns
`MeterNotRunning` — it must not invent `wall_ns = 0`.

---

## 6. Observer channel (meter)

### Correct use

1. Build `IsolationProfile` offline under controlled conditions (many runs).  
2. Each session: `meter.start` → `evolve` → `measure` → `meter.stop`.  
3. `gate(report, profile)` → release policy.  
4. Log reports for science; do not mix into seed for hardness.

### Incorrect use (rejected)

- `seed = H(sample ‖ wall_ns)` “so MITM can’t predict.”  
- In-process instruction counters inside Trin math as the only meter (alters path; finer leak).  
- Claiming Clean ⇔ no network attacker.

### Dual-backend truth table

| Backend | Sample bit-stable under load? | Meter moves under load? | Interpretation |
|---------|-------------------------------|-------------------------|----------------|
| Classical / Trin deterministic | Yes (required) | Yes | Observer on **substrate**, not on spin math |
| QPU | Often no (noise + possible disturbance) | Yes | Meter + fidelity; sample statistics separate |

---

## 7. Trait contracts (normative sketch)

See `src/lib.rs` in this crate.

```text
trait SpinBackend {
  fn backend_id(&self) -> &str;
  fn prepare(&mut self, spec: &EvolutionSpec, secret: &[u8]) -> Result<()>;
  fn evolve(&mut self) -> Result<()>;
  fn measure(&mut self) -> Result<SpinSample>;
}

trait ObserverMeter {
  fn start(&mut self, label: &str);
  fn stop(&mut self, label: &str) -> TimingReport;
}

trait IsolationGate {
  fn gate(&self, report: &TimingReport, profile: &IsolationProfile) -> IsolationVerdict;
}
```

Session helper:

```text
fn isolation_session(
  backend, meter, gate, profile, policy, secret
) -> Result<QualifiedSeed>
```

`QualifiedSeed { bytes, isolation: bool, report, verdict }`.

---

## 8. Backend roadmap

| Backend | Status | Notes |
|---------|--------|-------|
| `ClassicalMockBackend` | **In this crate** | Deterministic hash-based “lattice” stub for interface tests |
| `BusyMockBackend` | **In this crate** | Deterministic sample + tunable CPU burn (`rounds=N`) for gate experiments |
| `SpinLatticeBackend` | **In this crate** (`feature = "spin-lattice"`) | Wraps `qs_crypto::SpinLattice`; sample = SHAKE of post-step spins |
| `TrinBackend` | **In this crate** | `trin run` via `$PATH` or `TRIN=`; meter wraps process wall time |
| `QuantumSimBackend` | **In this crate** | `DeviceSpinBackend<SimulatedQuantumDevice>` — stable research id `qpu-sim-v1` |
| `QuantumDevice` trait | **In this crate** | Vendor-neutral `run_job` surface; sim + `VendorStubDevice` |
| `VendorStubDevice` | **In this crate** | Documents cloud/on-prem hook; always errors until configured |
| Real vendor device | Future | Implement `QuantumDevice` for IBM/IonQ/Braket/etc. |
| `product_seed` bridge | **Feature `spin-lattice`** | `QualifiedSeed` → product `SpinPrng` (research only; product crate untouched) |

Trin wiring: **external** process wall timing (meter outside the math path),
host SHAKE(`secret ‖ program_hash ‖ stdout`) → sample — not jitter in SHAKE.

### 8.1 Baseline calibration

```text
collect_wall_samples(backend, spec, secret, n)
  → profile_from_samples / calibrate_profile(margin_ns, iqr_factor)
  → IsolationProfile
```

Use idle-lab runs only for baselines. Empirical demo:

```bash
cargo run --example load_contention --release
cargo run --example load_contention --release -- --trin
cargo run --example load_contention --release --features spin-lattice -- --lattice
cargo run --example load_contention --release --features spin-lattice -- --all
cargo run --example load_contention --release -- --quantum
```

### 8.2 Quantum device trait + sim

```text
QuantumDevice::run_job(req) → QuantumJobResult { histogram, JobStats }
DeviceSpinBackend<D>        → SpinBackend prepare/evolve/measure
measure                     → SHAKE(secret ‖ program ‖ histogram)  // never stats
```

- [`SimulatedQuantumDevice`] — local CPU histogram (default deterministic).
- [`VendorStubDevice`] — integration placeholder (`Backend` error until wired).
- [`QuantumSimBackend`] — type alias with `backend_id = "qpu-sim-v1"`.
- No real QPU; no claim that `fidelity_proxy` is cryptographic.

### 8.3 Product seed bridge (research only)

```text
isolation_session → QualifiedSeed → spinprng_from_qualified(policy) → SpinPrng
```

| Policy | Behavior |
|--------|----------|
| `RequireIsolation` | Clean path only |
| `AllowUnqualified` | Sample path with `isolation=false` |
| `AllowOsUnqualified` | OS reseed path allowed |

Product `qs_crypto` is **not** modified. Demo:

```bash
cargo run --example qualified_prng_demo --release --features spin-lattice
```

Baseline margin is **adaptive** (`AdaptiveMargin`: effective floor ∨ p95-fraction ∨
spread×max(iqr, p95−p50)) via `calibrate_profile_adaptive` (3-run warmup discard).
Absolute floor is capped at `min(floor, max(100µs, 2·p95))` so short evolutions
are not dominated by a multi-ms floor.

### Lab notes (2026-07-23, release, 2×ncpu burn threads)

| Backend | Schedule | Idle Clean | Load Suspect | Seed idle==load |
|---------|----------|------------|--------------|-----------------|
| BusyMock | 80k burn | 100% | 100% | yes |
| SpinLattice QS128 | 12288 steps | 100% | ~47% | yes |
| Trin external | spin_sample.trin | 100% | ~93% | yes |
| QuantumSim | 48k shots, queue=0 | 100% | ~93% | yes |

Lattice under load is noisier than Busy/Trin (partial Suspect rate) but still
shows separation; S3 seed hygiene holds on deterministic backends.

---

## 9. Test plan (interface)

| Test | Expect |
|------|--------|
| T1 Classical determinism | Same secret+spec ⇒ same `SpinSample` |
| T2 Meter non-interference | Meter on/off ⇒ identical sample (classical) |
| T3 Gate baseline | Synthetic reports inside envelope ⇒ `Clean` |
| T4 Gate stress | Inflated `wall_ns` ⇒ `SuspectObserver` |
| T5 Seed hygiene | Seed bytes independent of `TimingReport` fields |
| T6 Policy Abort | Suspect + Abort ⇒ no seed bytes returned |
| T7 PRNG usefulness | Clean seeds drive sponge/PRNG-shaped absorb (product integration later) |
| T8 Busy sample stable | Same schedule ⇒ same sample independent of constructor burn default |
| T9 Baseline envelope | `profile_from_samples` → Clean inside / Suspect above p95+margin |
| T10 Calibrate live | Idle `calibrate_profile` + `live_session` → Clean |
| T11 Lattice (feature) | Determinism, secret sensitivity, seed hygiene |
| T12 Trin (if binary) | Determinism + secret sensitivity via external process |

```bash
cargo test
cargo test --features spin-lattice
cargo run --example isolation_demo
cargo run --example load_contention --release
```

---

## 10. Mapping to product qs_crypto

| Product piece | Relation |
|---------------|----------|
| `SpinPrng::new(seed)` | Unchanged; research `spinprng_from_qualified` wraps this |
| Product public API | **Not wired** — bridge stays under `research/spin_backend` until review |
| `SpinLattice` / `SpinSponge` | Future `SpinBackend` impl |
| KEM (RLWE+SHAKE hardened path) | Orthogonal; do not block on isolation research |
| Visual fingerprint / PAKE MITM | **Different** channel (identity / OOB) |

Product docs should keep: *simulation is classical unless a QuantumBackend is
explicitly selected.*

---

## 11. Footnotes (spin_backend)

| Id | Rule |
|----|------|
| **S1** | Jitter/timing is a meter for substrate observers, not key material (aligns F1). |
| **S2** | Isolation verdict is heuristic; label isolation-qualified output explicitly. |
| **S3** | Seed derivation never includes `TimingReport` for hardness. |
| **S4** | Only `SpinSample` (backend measure) feeds the hardness seed path. |
| **S5** | Network MITM ≠ process observer; do not conflate APIs. |

---

## Changelog

| Date | Note |
|------|------|
| 2026-07-21 | Initial interface freeze draft + `spin_backend` sketch crate. |
| 2026-07-23 | SpinLatticeBackend (feature), TrinBackend, BusyMock, baseline helpers, load_contention empirical gate success. |
| 2026-07-23 | AdaptiveMargin + warmup; multi-backend load_contention (`--busy/--lattice/--trin/--all`); lattice+trin lab table. |
| 2026-07-23 | QuantumSimBackend + JobStats on TimingReport; `--quantum` load harness; dual-channel QPU sketch. |
| 2026-07-23 | `QuantumDevice` + `DeviceSpinBackend` + `VendorStubDevice`; `product_seed` → SpinPrng bridge. |
