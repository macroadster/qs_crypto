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
| Optional | `queue_ms`, `shot_count`, power samples, host load snapshot |

Public-safe to log for experiments. **Not** secret key material.

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
| `SpinLatticeBackend` | Future adapter in product or research | Wrap `qs_crypto::core::lattice` |
| `TrinBackend` | Future | `trin run` external process; meter wraps process wall time |
| `QuantumBackend` | Future | Job submit + shot gather; report includes queue/shot stats |

Trin wiring: **external** process wall timing (meter outside the math path),
deterministic kernel stdout → sample encoding — not jitter in SHAKE.

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

Run: `cargo test` in `research/spin_backend/`.

---

## 10. Mapping to product qs_crypto

| Product piece | Relation |
|---------------|----------|
| `SpinPrng::new(seed)` | Unchanged; consumes qualified seed bytes |
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
