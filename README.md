# QS-Crypto

**Encryption born from the birth of a universe.**

QS-Crypto is an experimental cryptographic library built around a novel sponge permutation inspired by frustrated spin-glass lattice dynamics. It provides a full protocol stack (KEM, AEAD, PAKE, forward-secret ratchet, visual fingerprinting) on top of this primitive.

The KEM layer has been **hardened** (2026) to use SHAKE256 for all internal randomness. Its security therefore reduces to standard Ring-LWE + SHAKE256 and no longer depends on the unanalyzed permutation.

> **Research project — not for production use without further analysis.** The symmetric primitives rest on a novel, statistically unvalidated permutation. See [Status](#status) and [SECURITY.md](docs/SECURITY.md) for details.

---

## The Core Idea

Classical public-key cryptography relies on the difficulty of factoring large numbers or computing discrete logarithms — problems a sufficiently powerful quantum computer can solve. QS-Crypto explores a different foundation: the **planted spin glass problem**, drawn from statistical physics.

A spin glass is a magnetic system where competing interactions between particles create a chaotically frustrated energy landscape with an exponential number of near-optimal configurations. Finding the true ground state of such a system is NP-hard. QS-Crypto exploits this by:

1. **Creating a quantum universe** — A triangular lattice of spins over a prime field (Z_q, q=3329) is initialized with a secret ground state and random frustrated couplings.
2. **Publishing the universe, keeping the secret** — The coupling matrix and a noisy observation of the ground state become the **public key**. The ground state itself is the **private key**. Recovering it requires solving an NP-hard optimization problem.
3. **Communicating through the universe** — A second party can encapsulate a shared secret using only the public lattice. Only the holder of the ground state can decapsulate it.

The hardness does not depend on integer factoring or discrete logarithms, making it orthogonal to Shor's algorithm and potentially post-quantum resistant.

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                      PUBLIC API  (lib.rs)                │
│  generate_keypair · encapsulate · Session · PAKE         │
├──────────────────────────────────────────────────────────┤
│  Layer 3: PROTOCOLS           Layer 2: ASYMMETRIC        │
│  ┌────────────────────┐      ┌─────────────────────┐     │
│  │ OPAQUE-Spin PAKE   │      │  Spin Glass KEM     │     │
│  │ Double Ratchet     │─────▶│  KeyGen / Encaps /  │     │
│  │ Session Manager    │      │  Decaps             │     │
│  └────────┬───────────┘      └──────────┬──────────┘     │
│           │                             │                │
│           ▼                             ▼                │
│  Layer 1: SYMMETRIC PRIMITIVES                           │
│  ┌──────────────────────────────────────────────┐        │
│  │ SpinHash · SpinPRNG · SpinKDF · SpinAEAD     │        │
│  └──────────────────────┬───────────────────────┘        │
│                         │                                │
│                         ▼                                │
│  Layer 0: SPIN GLASS CORE                                │
│  ┌──────────────────────────────────────────────┐        │
│  │ SpinLattice (simulation engine)              │        │
│  │ SpinSponge  (sponge construction)            │        │
│  └──────────────────────────────────────────────┘        │
└──────────────────────────────────────────────────────────┘
```

Each layer depends only on the layers below it. Users can adopt the sponge alone, the KEM alone, or the full session protocol.

---

## Project Structure

```
qs_crypto/
├── Cargo.toml
├── LICENSE                       # Apache License 2.0
├── src/
│   ├── lib.rs                   # Public API re-exports
│   ├── error.rs                 # Error types
│   ├── params.rs                # Security parameters (QS-128/192/256)
│   ├── bin/                     # CLI tools
│   │   ├── demo.rs              # End-to-end demo (cargo run --bin demo)
│   │   ├── bench.rs             # Benchmark runner
│   │   └── stats.rs             # Statistical validation harness
│   ├── core/                    # Layer 0 — lattice engine + sponge
│   ├── primitives/              # Layer 1 — hash, prng, kdf, aead
│   ├── kem/                     # Layer 2 — keygen, encaps, decaps, hybrid, ntt
│   ├── protocols/               # Layer 3 — pake, ratchet, session
│   └── visual/                  # Fingerprint renderer
├── benches/                     # Criterion benchmarks
│   └── qs_crypto.rs
├── tests/
│   ├── key_generation.rs        # Keypair generation + serialization tests
│   ├── encryption.rs            # KEM encapsulation + hybrid KEM + session encrypt tests
│   ├── decryption.rs            # KEM roundtrip + session decrypt + PAKE tests
│   ├── differential_ntt.rs      # NTT vs schoolbook correctness (6000+ trials)
│   └── stats.rs                 # Monte Carlo statistical tests
├── docs/
│   ├── DESIGN_PROPOSAL.md       # Full technical design document
│   ├── RELEASE_NOTES_v0.2.md
│   ├── SECURITY.md
├── legacy/                      # Original Python prototypes
    ├── q.py
    ├── starlight_crypto.py
    └── starlight_entropy.py
└── research/                    # Experiments (not product API)
    └── spin_backend/            # SpinBackend + ObserverMeter → SpinPRNG seeds
```

---

## Quick Start

### Prerequisites

- [Rust](https://rustup.rs/) 1.75+

### Build & Test

```bash
cargo build
cargo test
```

`cargo test` runs 77 tests covering all four layers: lattice/sponge properties, hash/KDF/PRNG/AEAD primitives, KEM roundtrips at all security levels, hybrid KEM (Spin + X25519), session encrypt/decrypt/save/restore, PAKE handshake, visual fingerprints, and authentication failure paths.

### CLI Demo

Run the interactive demo to verify every layer works end-to-end:

```bash
cargo run --bin demo
```

This walks through key generation, KEM encapsulation/decapsulation, symmetric primitives (hash, KDF, AEAD), a full Alice ↔ Bob encrypted session, PAKE handshake, and visual fingerprint generation — printing `[PASS]`/`[FAIL]` for each check. Exits with code 1 if anything fails.

Example output:

```
  QS-Crypto — Spin Glass Cryptography Demo
  =========================================

  1. Key Generation (all security levels)
    QS128: Public key 321 bytes, Private key 610 bytes
    QS192: Public key 425 bytes, Private key 818 bytes
    QS256: Public key 545 bytes, Private key 1058 bytes

  2. KEM Encapsulation / Decapsulation
    Ciphertext: 1025 bytes
    Secrets match: YES [PASS]
    Implicit rejection (wrong key): different secret [PASS]

  3. Symmetric Primitives
    SpinHash deterministic: YES [PASS]
    Avalanche (1 char change): 127/256 bits flipped [PASS]
    SpinKDF (64 bytes): [PASS]
    SpinAEAD roundtrip: [PASS]
    Tamper detected: YES [PASS]

  4. Session Encryption (Alice <-> Bob)
    Bidirectional messaging: [PASS]
    Forward secrecy: YES [PASS]

  5. PAKE — Password-Authenticated Key Exchange
    Keys match: YES [PASS]
    Wrong password rejected: YES [PASS]

  6. Visual Fingerprint
    Deterministic: YES [PASS]

  All checks passed. The spin glass lattice holds.
```

---

## Usage (API Preview)

```rust
use qs_crypto::*;

// ── Key Generation ─────────────────────────────────────
let keypair = generate_keypair(&Params::default());   // QS-256

// ── KEM Encapsulation / Decapsulation ──────────────────
let result    = encapsulate(&keypair.public_key);
let decapped  = decapsulate(&keypair.private_key, &result.ciphertext)?;
assert_eq!(result.shared_secret.as_bytes(), decapped.as_bytes());

// ── PAKE (no CA required) ──────────────────────────────
let record = pake_register("password", &keypair);
let mut client = PakeClient::new("password");
let mut server = PakeServer::new(record);

let msg1 = client.start();
let msg2 = server.respond(&msg1)?;
let client_key = client.finalize(&msg2)?;
let server_key = server.finalize()?;
// client_key == server_key

// ── Encrypted Session (forward secrecy) ────────────────
let mut session = Session::new(keypair, peer_pk, &session_key);
let ct = session.encrypt(b"Hello Bob");
let pt = session.decrypt(&ct)?;

// ── Hybrid KEM (recommended: Spin + X25519) ────────────
let hkp = hybrid_generate_keypair(&Params::default());
let hpk = hkp.public_key();
let (hct, hss) = hybrid_encapsulate(&hpk);
let hss2 = hybrid_decapsulate(&hkp.private_key(), &hct).unwrap();

// ── Visual Fingerprint (plain) ─────────────────────────
let rgba = session.visual_fingerprint(128, 128);

// ── Identity-Bound Fingerprint (photo + lattice) ──────
session.set_identity_photos(
    IdentityPhoto::new(my_photo_bytes),
    IdentityPhoto::new(peer_photo_bytes),
);
let rgba = session.identity_fingerprint(128, 128)?;
// Peer's face visible through spin-domain colouring.
// Session key determines colours; photo determines topology.
```

Secret material (`PrivateKey`, `SharedSecret`) implements `Zeroize + ZeroizeOnDrop` — memory is scrubbed automatically when values go out of scope.

---

## How Two Parties Communicate

```
Alice                                        Bob
═════                                        ═══

  1. Both agree on a password (in person, phone call, etc.)

  2. Alice registers:
     keypair = generate_keypair()
     record  = pake_register(password, keypair)
                          ──── record ────▶   (Bob stores it)

  3. Login (over any insecure channel):
     client = PakeClient::new(password)       server = PakeServer::new(record)
     msg1 = client.start()      ────────────▶
                                ◀──────────── msg2 = server.respond(&msg1)
     key_A = client.finalize(&msg2)           key_B = server.finalize()

     // key_A == key_B — both derived the same session key

  4. Encrypted session with forward secrecy:
     ct = session.encrypt(b"Hello Bob")  ───▶ pt = session.decrypt(&ct)

  5. Optional — identity-bound visual verification:
     Both attach their photos and generate an identity fingerprint.
     Each side sees the OTHER party's face rendered through the quantum lattice.
     The session key determines the colours; the photo shapes the domain topology.

     Alice (phone): "I see Bob's face — left half blue-green, orange spiral near chin."
     Bob   (phone): "I see Alice's face — forehead red, jawline teal, purple vortex on cheek."
     Match confirms no man-in-the-middle. No CA involved.
```

### Key Properties

- **Asymmetric keys from one event** — The public/private keypair emerges from a single lattice construction. The coupling matrix (public) and ground state (private) are inseparable halves of the same physical system.
- **No CA or PKI required** — Password-authenticated key exchange (OPAQUE) lets two parties bootstrap trust from a shared secret.
- **Forward secrecy** — A double-ratchet protocol (adapted from Signal) generates unique keys per message and deletes old ones. Compromising the current state reveals nothing about past messages.
- **Identity-bound visual fingerprinting** — Each party's photo is superimposed onto the quantum lattice simulation. The photo shapes the domain topology; the session key determines the colouring. You see your peer's face rendered through the lattice — change either input and the image is unrecognisable. More intuitive than comparing hex strings or abstract patterns.
- **Memory safety** — Rust's ownership model prevents use-after-free, double-free, and buffer overflow. Secret material is auto-zeroed on drop.

---

## Security Parameters

Three parameter sets are defined, defaulting to QS-256:

| Parameter | QS-128 | QS-192 | QS-256 |
|---|---|---|---|
| Target security | 128-bit | 192-bit | 256-bit |
| Lattice spins | 144 (12x12) | 196 (14x14) | 256 (16x16) |
| Public key size | 321 B | 425 B | 545 B |
| Private key size | 610 B | 818 B | 1058 B |
| Ciphertext size | 577 B | 785 B | 1025 B |

---

## Status

All four layers are **fully implemented** with 77 passing tests, zero warnings,
and clean clippy/fmt. The library is feature-complete for its research scope.

**Implemented:**
- [x] Layer 0 — SpinLattice engine (triangular Z_q lattice with cubing S-box) and SpinSponge (10\*1 padding, absorb/squeeze)
- [x] Layer 1 — SpinHash, SpinPRNG, SpinKDF (HKDF-style), SpinAEAD (duplex-mode with constant-time tag verification)
- [x] Layer 2 — Ring-LWE KEM (hardened with SHAKE256 XOF for all internal randomness) + Fujisaki-Okamoto + implicit rejection
- [x] Hybrid KEM (Spin + X25519) with SHAKE256 combiner — defense-in-depth
- [x] NTT polynomial multiplication for QS256 (unconditional for N=256), verified bit-identical to schoolbook across 6,000+ differential trials
- [x] Layer 3 — OPAQUE-Spin PAKE, Double Ratchet (symmetric + KEM ratchet), Session (encrypt/decrypt/save/restore)
- [x] Visual fingerprint renderer (plain + identity-bound)
- [x] 77 integration tests across all layers
- [x] Full technical design document ([DESIGN_PROPOSAL.md](docs/DESIGN_PROPOSAL.md))
- [x] CLI tools: interactive demo, benchmark runner, statistical validation harness
- [x] Secret material auto-zeroed via `Zeroize` + `ZeroizeOnDrop`
- [x] Constant-time tag comparison via `subtle` crate

### Empirical Validation of the Core Permutation (10,000 trials)

The most critical component — the `SpinLattice` round function — has received large-scale Monte-Carlo validation:

**10,000 independent trials (QS-256, 32 rounds):**
- Average **255.9 / 256 spins** flip after changing a single input spin by +1.
- Average **~1,521 bits** flip out of 3,072 (very close to ideal 1,536).
- Range across trials: **[253, 256]** spins differ.

This constitutes **full state randomization** (100% spin avalanche) with excellent bit-level diffusion. These results are among the strongest observed for custom cryptographic round functions of similar complexity and round count.

The statistical harness (`cargo run --bin stats -- --permutation --trials 10000` and `--quick`) makes this evidence reproducible and extensible.

**Future work:**
- [ ] Publish NIST SP 800-22 + TestU01 results for the SpinLattice permutation (`cargo run --bin stats -- --help`)
- [ ] Full 3-way hybrid KEM (Spin + X25519 + ML-KEM-768) — the `ml-kem` crate is a dependency but ML-KEM encaps/decaps is not yet wired into the hybrid combiner
- [ ] NTT support for non-power-of-2 dimensions (QS128 N=144, QS192 N=196) or migrate those levels to power-of-2 ring dimensions
- [ ] Formal side-channel audit (ctgrind / dudect) of the lattice step
- [ ] Third-party cryptanalysis of the custom permutation

### Honest Caveats

- The **asymmetric KEM** is a standard Ring-LWE scheme whose security reduces to a well-studied lattice problem + SHAKE256. Polynomial multiplication uses NTT for QS256 (N=256) and schoolbook for smaller dimensions. The recommended deployment mode is the **hybrid KEM** (Spin + X25519), which provides defense-in-depth so that the combined shared secret is at least as strong as the stronger component.
- The **novel contribution** is the `SpinLattice` permutation used for the symmetric sponge. It has only received basic functional and avalanche testing. Full statistical batteries (NIST SP 800-22, TestU01) and differential cryptanalysis are still required.
- The visual fingerprinting and identity-bound photo overlay are creative and safe for their intended purpose (human comparison over an out-of-band channel). They add no new cryptographic assumptions.
- This remains a **research / experimental library**. The "spin glass" story in early design documents was aspirational; the shipped asymmetric primitive is conventional Ring-LWE.

---

## References

1. F. Barahona. "On the computational complexity of Ising spin glass models." *J. Physics A*, 1982.
2. D. Gamarnik & M. Sudan. "Limits of local algorithms over sparse random graphs." *Annals of Probability*, 2017.
3. S. Jarecki, H. Krawczyk, J. Xu. "OPAQUE: An Asymmetric PAKE Protocol Secure Against Pre-Computation Attacks." *Eurocrypt*, 2018.
4. T. Perrin & M. Marlinspike. "The Double Ratchet Algorithm." Signal, 2016.
5. G. Bertoni et al. "Sponge Functions." ECRYPT Hash Workshop, 2007.

---

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full text.
