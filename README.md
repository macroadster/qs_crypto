# QS-Crypto

**Encryption born from the birth of a universe.**

QS-Crypto is an experimental cryptographic library that derives its security from simulating the creation and evolution of a quantum spin glass universe. Two parties establish a private channel using asymmetric keys that emerge together from a single event — the cooling of a simulated quantum lattice into its ground state — much like entangled particles created in the same moment share a connection no observer can replicate.

> **Research project — not for production use.** The asymmetric primitive rests on an unvetted hardness assumption (SG-LWE) and has not undergone formal cryptanalysis. See [Status](#status) below.

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
│                      PUBLIC API  (lib.rs)                  │
│  generate_keypair · encapsulate · Session · PAKE          │
├──────────────────────────────────────────────────────────┤
│  Layer 3: PROTOCOLS           Layer 2: ASYMMETRIC         │
│  ┌────────────────────┐      ┌─────────────────────┐     │
│  │ OPAQUE-Spin PAKE   │      │  Spin Glass KEM     │     │
│  │ Double Ratchet     │─────▶│  KeyGen / Encaps /  │     │
│  │ Session Manager    │      │  Decaps             │     │
│  └────────┬───────────┘      └──────────┬──────────┘     │
│           │                             │                 │
│           ▼                             ▼                 │
│  Layer 1: SYMMETRIC PRIMITIVES                            │
│  ┌──────────────────────────────────────────────┐        │
│  │ SpinHash · SpinPRNG · SpinKDF · SpinAEAD     │        │
│  └──────────────────────┬───────────────────────┘        │
│                         │                                 │
│                         ▼                                 │
│  Layer 0: SPIN GLASS CORE                                 │
│  ┌──────────────────────────────────────────────┐        │
│  │ SpinLattice (simulation engine)               │        │
│  │ SpinSponge  (sponge construction)             │        │
│  └──────────────────────────────────────────────┘        │
└──────────────────────────────────────────────────────────┘
```

Each layer depends only on the layers below it. Users can adopt the sponge alone, the KEM alone, or the full session protocol.

---

## Project Structure

```
qs_crypto/
├── Cargo.toml
├── src/
│   ├── lib.rs                   # Public API re-exports
│   ├── error.rs                 # Error types
│   ├── params.rs                # Security parameters (QS-128/192/256)
│   ├── core/                    # Layer 0 — lattice engine + sponge
│   ├── primitives/              # Layer 1 — hash, prng, kdf, aead
│   ├── kem/                     # Layer 2 — keygen, encaps, decaps
│   ├── protocols/               # Layer 3 — pake, ratchet, session
│   └── visual/                  # Fingerprint renderer
├── tests/
│   ├── key_generation.rs        # Keypair generation + serialization tests
│   ├── encryption.rs            # KEM encapsulation + session encrypt tests
│   └── decryption.rs            # KEM roundtrip + session decrypt + PAKE tests
└── legacy/                      # Original Python prototypes
    ├── q.py
    ├── starlight_crypto.py
    └── starlight_entropy.py
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

`cargo test` runs 70 tests covering all four layers: lattice/sponge properties, hash/KDF/PRNG/AEAD primitives, KEM roundtrips at all security levels, session encrypt/decrypt/save/restore, PAKE handshake, visual fingerprints, and authentication failure paths.

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
| Public key size | ~1.5 KB | ~2.0 KB | ~2.6 KB |
| Ciphertext size | ~432 B | ~588 B | ~768 B |

---

## Status

All four layers are **fully implemented** with 70 passing tests, zero warnings,
and clean clippy/fmt. The library is feature-complete for its research scope.

**Implemented:**
- [x] Layer 0 — SpinLattice engine (triangular Z_q lattice with cubing S-box) and SpinSponge (10\*1 padding, absorb/squeeze)
- [x] Layer 1 — SpinHash, SpinPRNG, SpinKDF (HKDF-style), SpinAEAD (duplex-mode with constant-time tag verification)
- [x] Layer 2 — Spin Glass KEM (KeyGen, Encaps, Decaps) with Fujisaki-Okamoto transform and implicit rejection
- [x] Layer 3 — OPAQUE-Spin PAKE, Double Ratchet (symmetric + KEM ratchet), Session (encrypt/decrypt/save/restore)
- [x] Visual fingerprint renderer (plain + identity-bound)
- [x] 70 integration tests across all layers
- [x] Full technical design document ([DESIGN_PROPOSAL.md](DESIGN_PROPOSAL.md))
- [x] Secret material auto-zeroed via `Zeroize` + `ZeroizeOnDrop`
- [x] Constant-time tag comparison via `subtle` crate

**Future work (not required for the research library):**
- [ ] Statistical validation (NIST SP 800-22, TestU01)
- [ ] Hybrid mode (Spin Glass KEM + X25519 fallback)
- [ ] NTT-based polynomial multiplication (currently schoolbook O(N^2))
- [ ] Side-channel hardening (constant-time throughout)
- [ ] Formal cryptanalysis of SG-LWE

### Honest Caveats

- The **SG-LWE hardness assumption is novel and unvetted**. The spin glass coupling structure may introduce exploitable regularities not present in standard LWE. No formal reduction exists.
- **Worst-case NP-hardness does not guarantee average-case hardness.** The planted construction may leak information.
- **Quantum annealers** (D-Wave) are specifically designed to find spin glass ground states. While current hardware is insufficient for these parameters, this requires ongoing monitoring.
- The symmetric layer (sponge) must pass standard statistical test suites before any of the upper layers can be trusted.

---

## References

1. F. Barahona. "On the computational complexity of Ising spin glass models." *J. Physics A*, 1982.
2. D. Gamarnik & M. Sudan. "Limits of local algorithms over sparse random graphs." *Annals of Probability*, 2017.
3. S. Jarecki, H. Krawczyk, J. Xu. "OPAQUE: An Asymmetric PAKE Protocol Secure Against Pre-Computation Attacks." *Eurocrypt*, 2018.
4. T. Perrin & M. Marlinspike. "The Double Ratchet Algorithm." Signal, 2016.
5. G. Bertoni et al. "Sponge Functions." ECRYPT Hash Workshop, 2007.

---

## License

TBD