# QS-Crypto: Spin Glass Cryptographic Library

**Design Proposal v0.2**
**Status:** Draft — Open for Review
**Language:** Rust
**Authors:** [TBD]
**Date:** July 2025

---

## Table of Contents

1. [Abstract](#1-abstract)
2. [Motivation & Problem Statement](#2-motivation--problem-statement)
3. [Design Goals & Non-Goals](#3-design-goals--non-goals)
4. [Threat Model](#4-threat-model)
5. [Architecture Overview](#5-architecture-overview)
6. [Layer 0 — Spin Glass Core](#6-layer-0--spin-glass-core)
7. [Layer 1 — Symmetric Primitives](#7-layer-1--symmetric-primitives)
8. [Layer 2 — Spin Glass KEM](#8-layer-2--spin-glass-kem)
9. [Layer 3 — Protocols](#9-layer-3--protocols)
10. [Visual Fingerprinting](#10-visual-fingerprinting)
11. [Public API Surface](#11-public-api-surface)
12. [Security Parameters](#12-security-parameters)
13. [Security Analysis & Hardness Assumptions](#13-security-analysis--hardness-assumptions)
14. [Implementation Plan](#14-implementation-plan)
15. [Open Questions](#15-open-questions)
16. [References](#16-references)

---

## 1. Abstract

QS-Crypto is a cryptographic library that uses the physics of frustrated spin glass
systems as the foundation for both symmetric and asymmetric cryptographic primitives.
The library provides a complete protocol stack: a sponge construction built over spin
lattice dynamics (symmetric), a Key Encapsulation Mechanism whose hardness derives
from the planted spin glass problem (asymmetric), a password-authenticated key exchange
(PAKE) protocol, and a double-ratchet session protocol with forward secrecy.

The core thesis is that the computational hardness of spin glass ground-state recovery
— an NP-hard problem whose difficulty does not rely on integer factoring or discrete
logarithms — can serve as the basis for a cryptographic system with a novel and
potentially post-quantum hardness assumption.

This document describes the full design for external review, with particular attention
to where the construction rests on established results versus where it introduces
unvetted assumptions.

---

## 2. Motivation & Problem Statement

### 2.1 Why Spin Glass Cryptography?

Modern public-key cryptography rests on two families of hardness assumptions:

| Assumption | Schemes | Quantum Threat |
|---|---|---|
| Integer factoring / RSA problem | RSA, DSA | Broken by Shor's algorithm |
| Discrete logarithm / Elliptic curves | ECDH, ECDSA, Ed25519 | Broken by Shor's algorithm |
| Lattice problems (LWE, RLWE) | Kyber, Dilithium (NIST PQC) | Believed resistant |

The NIST post-quantum standards (Kyber, Dilithium) address the quantum threat through
mathematical lattice problems. QS-Crypto explores an alternative foundation: the
**planted spin glass problem**, drawn from statistical physics. The motivation is not
to replace vetted schemes, but to investigate whether spin glass hardness — which is
NP-hard and orthogonal to the problems Shor's algorithm targets — can yield a viable
cryptographic primitive.

### 2.2 The Two-Party Problem

A secondary goal is enabling two parties to establish encrypted communication without
relying on a centralized Certificate Authority (CA) or Public Key Infrastructure (PKI).
The library achieves this through:

- **PAKE (Password-Authenticated Key Exchange):** Two parties who share a low-entropy
  password can establish a high-entropy session key without transmitting the password
  and without any third party.
- **Visual fingerprinting:** The spin glass ground state produces a complex, visually
  distinct 2D pattern. Two parties can compare rendered fingerprint images over an
  out-of-band channel (voice call, in person) to detect man-in-the-middle attacks.

### 2.3 What This Is Not

- This is **not** a production-ready cryptographic library. The asymmetric primitive
  (Spin Glass KEM) rests on an unvetted hardness assumption and must undergo formal
  cryptanalysis before any real-world deployment.
- This is **not** quantum computing. The simulation is classical. The "quantum" in the
  spin model name refers to the physics being modeled, not the computation platform.
- This is **not** a replacement for NIST PQC standards. It is a research library
  exploring an alternative hardness foundation.

---

## 3. Design Goals & Non-Goals

### Goals

1. **Layered architecture.** Each layer exposes clean primitives. Users can adopt the
   sponge alone, the KEM alone, or the full session protocol.
2. **Asymmetric key exchange from spin glass hardness.** The KEM's security reduction
   targets the planted spin glass problem, not standard LWE.
3. **No third-party authentication.** PAKE protocol enables two-party authentication
   from a shared password. Visual fingerprinting enables out-of-band verification.
4. **Forward secrecy.** Double-ratchet protocol ensures compromise of current keys
   does not reveal past messages.
5. **Authenticated encryption by default.** All encryption includes integrity
   protection (AEAD). No unauthenticated encryption mode is exposed.
6. **API-level library.** Clean Rust API that protocol designers can build on top of.
   Memory safety via ownership, secret material auto-zeroed via `Zeroize`.

### Non-Goals

- Performance parity with AES-GCM or ChaCha20-Poly1305. The spin lattice permutation
  is inherently slower than hardware-accelerated AES. Performance is a secondary
  concern during the research phase.
- Formal NIST submission. This is a research project, not a standards candidate.
- Side-channel hardening in v0.2. The Rust implementation enables constant-time
  operations via the `subtle` crate in a future hardening phase.

---

## 4. Threat Model

### In Scope

- **Passive eavesdropper (Dolev-Yao model).** An adversary who observes all
  communication on the wire. The KEM and AEAD must prevent plaintext recovery.
- **Active man-in-the-middle.** An adversary who can intercept, modify, and inject
  messages. The PAKE protocol and visual fingerprinting must detect or prevent this.
- **Key compromise (forward secrecy).** Compromise of current long-term keys must not
  reveal past session keys. The double ratchet addresses this.
- **Password guessing (online).** The PAKE protocol must resist online dictionary
  attacks. Each failed attempt must be detectable by the server.

### Out of Scope (for v0.1)

- **Offline dictionary attacks against the PAKE.** The OPAQUE-style protocol resists
  these by design, but formal analysis of the spin glass instantiation is deferred.
- **Side-channel attacks.** Timing, power analysis, and cache attacks are not addressed
  in the pure-Python implementation.
- **Quantum adversary with a fault-tolerant quantum computer.** While the hardness
  assumption is orthogonal to Shor's algorithm, resistance to Grover's algorithm and
  quantum annealing attacks on spin glass instances requires separate analysis.

---

## 5. Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    PUBLIC API (api.py)                      │
│  generate_keypair  kem_encaps  Session  PAKEClient/Server   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Layer 3: PROTOCOLS        Layer 2: ASYMMETRIC              │
│  ┌──────────────────┐     ┌─────────────────────┐           │
│  │ OPAQUE-Spin PAKE │     │  Spin Glass KEM     │           │
│  │ Double Ratchet   │────▶│  KeyGen / Encaps /  │           │
│  │ Session Manager  │     │  Decaps             │           │
│  └────────┬─────────┘     └──────────┬──────────┘           │
│           │                          │                      │
│           ▼                          ▼                      │
│  Layer 1: SYMMETRIC PRIMITIVES                              │
│  ┌──────────────────────────────────────────────┐           │
│  │ SpinHash  SpinPRNG  SpinKDF  SpinAEAD        │           │
│  └────────────────────┬─────────────────────────┘           │
│                       │                                     │
│                       ▼                                     │
│  Layer 0: SPIN GLASS CORE                                   │
│  ┌──────────────────────────────────────────────┐           │
│  │ SpinLattice (simulation engine)              │           │
│  │ SpinSponge  (sponge construction)            │           │
│  │ Params      (security parameters)            │           │
│  └──────────────────────────────────────────────┘           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Dependency rule:** Each layer depends only on the layers below it. No upward or
circular dependencies.

### Module Map (Rust)

```
qs_crypto/
├── Cargo.toml
├── src/
│   ├── lib.rs                   # Public API re-exports
│   ├── error.rs                 # Error type (thiserror)
│   ├── params.rs                # Security parameters, lattice configs
│   │
│   ├── core/                    # Layer 0
│   │   ├── mod.rs
│   │   ├── lattice.rs           # SpinLattice engine
│   │   └── sponge.rs            # SpinSponge construction
│   │
│   ├── primitives/              # Layer 1
│   │   ├── mod.rs
│   │   ├── hash.rs              # SpinHash
│   │   ├── prng.rs              # SpinPRNG (CSPRNG)
│   │   ├── kdf.rs               # SpinKDF
│   │   └── aead.rs              # SpinAEAD
│   │
│   ├── kem/                     # Layer 2
│   │   ├── mod.rs
│   │   ├── types.rs             # PublicKey, PrivateKey, KeyPair, Ciphertext, SharedSecret
│   │   ├── keygen.rs            # Key pair generation
│   │   ├── encaps.rs            # Encapsulation
│   │   └── decaps.rs            # Decapsulation
│   │
│   ├── protocols/               # Layer 3
│   │   ├── mod.rs
│   │   ├── pake.rs              # OPAQUE-Spin protocol
│   │   ├── ratchet.rs           # Double Ratchet
│   │   └── session.rs           # Session state machine
│   │
│   └── visual/                  # Visual verification
│       ├── mod.rs
│       └── fingerprint.rs       # Lattice fingerprint renderer
│
├── tests/                       # Integration tests
│   ├── key_generation.rs        # Keypair gen, serialization, param validation
│   ├── encryption.rs            # KEM encapsulation, session encrypt
│   └── decryption.rs            # KEM roundtrip, session decrypt, PAKE flow
│
└── legacy/                      # Original Python prototypes
    ├── q.py
    ├── starlight_crypto.py
    └── starlight_entropy.py
```

---

## 6. Layer 0 — Spin Glass Core

### 6.1 The Spin Lattice

**Model:** Generalized Potts model on a triangular lattice over Z_q.

```
Spin:       σ_i ∈ Z_q          where q = 3329 (prime)
Coupling:   J_ij ∈ Z_q          for each edge (i,j) in the lattice
Energy:     H(σ) = -Σ_{(i,j)} J_ij · σ_i · σ_j   (mod q)
Topology:   Triangular lattice, n × n, toroidal boundary conditions
```

**Why Z_q with q = 3329:**

- A prime field enables efficient Number Theoretic Transform (NTT) for fast
  polynomial/matrix multiplication in the KEM.
- q = 3329 is the same modulus used by NIST's Kyber (ML-KEM), providing compatibility
  with existing analysis of noise distributions and error bounds.
- Z_q spins give ~12 bits of state per lattice site, versus 1 bit for binary Ising.
  This yields more key material per lattice node.

**Why triangular lattice:**

- Triangular topology introduces **geometric frustration**: three mutually coupled
  spins on a triangle cannot all satisfy antiferromagnetic couplings simultaneously.
- Frustration creates an exponentially complex energy landscape with many competing
  local minima — the hallmark of spin glass behavior.
- Combined with random couplings, this produces the NP-hard ground-state search that
  underlies our hardness assumption.

**SpinLattice interface:**

```rust
pub struct SpinLattice { /* n, q, spins: Vec<u16>, couplings: Vec<u16> */ }

impl SpinLattice {
    /// Create a new n×n triangular lattice over Z_q from a parameter set.
    pub fn new(params: &Params) -> Self;

    /// Deterministically seed spin values and couplings from raw bytes.
    pub fn seed_from_bytes(&mut self, data: &[u8]);

    /// Current spin configuration as a slice of Z_q elements.
    pub fn spins(&self) -> &[u16];

    /// Overwrite the spin configuration.
    pub fn set_spins(&mut self, spins: &[u16]);

    /// Execute one synchronous update step across all spins.
    ///
    /// Update rule for each spin i:
    ///     h_eff(i) = Σ_j J_ij · σ_j             (mod q)
    ///     σ_i'     = (h_eff(i) · α + σ_i · β)   (mod q)
    ///
    /// Where α, β are round constants derived from the coupling structure.
    /// All updates are synchronous (computed from the previous state).
    pub fn step(&mut self);

    /// Execute multiple update steps.
    pub fn run(&mut self, rounds: usize);

    /// Compute the Hamiltonian H(σ) of the current configuration.
    pub fn energy(&self) -> i64;
}
```

### 6.2 The Sponge Construction

The sponge uses the spin lattice as its internal permutation, following the same
framework as Keccak/SHA-3.

**State partitioning:**

```
Total state:  N = n² spins, each ∈ Z_q
              Total bits ≈ N × log₂(q)

Rate (r):     First R spins — data is absorbed into and squeezed from this region.
Capacity (c): Remaining N - R spins — never directly exposed. Provides security
              margin.

Security claim: min(c × log₂(q) / 2, 256) bits against generic attacks.
```

**Operations:**

```
ABSORB(data):
    Pad data to a multiple of R × ⌈log₂(q)⌉ bits.
    For each R-element block:
        XOR block elements into the rate portion of the lattice state.
        Run PERMUTE.

PERMUTE:
    Execute K rounds of spin dynamics on the full lattice (rate + capacity).
    K ≥ 2n ensures full diffusion across the lattice.

SQUEEZE(num_bytes):
    output = []
    While len(output) < num_bytes:
        Read the rate portion of the lattice state.
        Encode as bytes and append to output.
        Run PERMUTE.
    Return output[:num_bytes]
```

**SpinSponge interface:**

```rust
pub struct SpinSponge { /* lattice: SpinLattice, rate, capacity, rounds */ }

impl SpinSponge {
    /// Create a new sponge sized for the given parameter set.
    pub fn new(params: &Params) -> Self;

    /// Absorb arbitrary data into the sponge state.
    pub fn absorb(&mut self, data: &[u8]);

    /// Run the internal permutation (K rounds of lattice dynamics).
    pub fn permute(&mut self);

    /// Squeeze `num_bytes` of output from the rate region.
    pub fn squeeze(&mut self, num_bytes: usize) -> Vec<u8>;

    /// Reset the sponge to its initial (all-zero) state.
    pub fn reset(&mut self);

    /// Borrow the underlying lattice (useful for fingerprinting).
    pub fn lattice(&self) -> &SpinLattice;
}
```

### 6.3 Diffusion and Confusion Properties

The spin dynamics must satisfy two classical cryptographic properties:

**Diffusion:** A change to any single input spin must affect all output spins after
K rounds. On a triangular n×n lattice, information propagates one lattice step per
round. After K = 2n rounds, every spin has been influenced by every other spin
(diameter of an n×n torus is n, and the triangular connectivity accelerates
propagation).

**Confusion:** The update rule must be nonlinear. The effective field computation
`h_eff(i) = Σ_j J_ij · σ_j (mod q)` is linear, but the mixing step
`σ_i' = (h_eff · α + σ_i · β) mod q` with non-trivially chosen round constants
introduces nonlinearity through the modular reduction and the interaction between
the current spin value and its neighborhood. Additional nonlinearity can be
introduced through a substitution step (S-box equivalent) applied to each spin
after the linear mixing, following the structure of AES rounds.

**Validation requirement:** Before the sponge is used for any cryptographic purpose,
the permutation must pass the NIST SP 800-22 statistical randomness test suite and
the TestU01 battery. Failure of these tests would indicate insufficient diffusion or
confusion and require redesign of the round function.

---

## 7. Layer 1 — Symmetric Primitives

All symmetric primitives are modes of the sponge. This mirrors the Keccak/SHA-3
approach where a single permutation yields a hash, XOF, PRNG, and AEAD.

### 7.1 SpinHash

```
SpinHash(message) → 32-byte digest

    1. Initialize sponge
    2. Absorb(0x01 || message)           # domain separator: 0x01 = hash
    3. Return Squeeze(32)
```

Domain separation byte `0x01` prevents cross-primitive collisions (e.g., a hash input
that collides with a KDF input).

### 7.2 SpinPRNG

```
SpinPRNG(seed) → unlimited byte stream

    1. Initialize sponge
    2. Absorb(0x02 || seed)              # domain separator: 0x02 = prng
    3. For each request of n bytes:
         Return Squeeze(n)
    
    Reseed(additional_entropy):
         Absorb(additional_entropy)
```

The PRNG supports incremental reseeding. The library should reseed from `os.urandom`
periodically (e.g., every 2^20 bytes squeezed) to maintain forward secrecy even if
the internal state is compromised.

### 7.3 SpinKDF

```
SpinKDF(key, salt, info, length) → derived key bytes

    Mirrors the HKDF extract-then-expand structure:
    
    EXTRACT:
        1. Initialize sponge
        2. Absorb(0x03 || salt || key)   # domain separator: 0x03 = kdf
        3. prk = Squeeze(32)             # pseudorandom key
    
    EXPAND:
        4. Initialize fresh sponge
        5. Absorb(prk || info || 0x01)   # counter byte for first block
        6. block_1 = Squeeze(32)
        7. For subsequent blocks:
             Absorb(block_{i-1} || info || counter_byte)
             block_i = Squeeze(32)
        8. Return first `length` bytes of concatenated blocks
```

### 7.4 SpinAEAD

Authenticated Encryption with Associated Data, using the sponge in duplex mode.

```
SpinAEAD.Encrypt(key, nonce, aad, plaintext) → (ciphertext, tag)

    1. Initialize sponge
    2. Absorb(0x04 || key || nonce)      # domain separator: 0x04 = aead
    3. Absorb(len(aad) || aad)           # associated data with length prefix
    4. Permute
    
    Duplex encryption (32-byte blocks):
    5. For each plaintext block P_i:
         K_i = Squeeze(len(P_i))         # keystream block
         C_i = P_i ⊕ K_i                 # ciphertext block
         Absorb(C_i)                     # feed ciphertext back for auth
    
    6. tag = Squeeze(16)                 # 128-bit authentication tag
    7. Return (C_0 || C_1 || ... || C_n, tag)


SpinAEAD.Decrypt(key, nonce, aad, ciphertext, tag) → plaintext | ERROR

    1-4. Same as Encrypt (absorb key, nonce, aad)
    
    Duplex decryption:
    5. For each ciphertext block C_i:
         K_i = Squeeze(len(C_i))
         P_i = C_i ⊕ K_i
         Absorb(C_i)                     # same feed-in as encrypt
    
    6. expected_tag = Squeeze(16)
    7. If expected_tag ≠ tag:
         Return ERROR (do not release plaintext)
         Wipe P_i buffers from memory.
    8. Return P_0 || P_1 || ... || P_n
```

**Critical property:** Ciphertext is absorbed back into the sponge state (step 5).
This means the authentication tag (step 6) depends on the entire ciphertext. Any
modification to the ciphertext, the AAD, or the nonce produces a different tag,
which the receiver detects. This is the sponge-native approach to AEAD, used by
Ketje and Keyak.

**Tag verification must be constant-time** to prevent timing oracles. The Rust
implementation should use the `subtle` crate's `ConstantTimeEq` for tag comparison.

---

## 8. Layer 2 — Spin Glass KEM

The Key Encapsulation Mechanism is the novel asymmetric component. It adapts the
Learning With Errors (LWE) framework, replacing the random matrix with a structured
coupling matrix drawn from a frustrated spin glass ensemble.

### 8.1 Hardness Assumption: SG-LWE

> **Definition (Spin Glass LWE).** Let J be an N×N coupling matrix drawn from a
> frustrated spin glass ensemble over Z_q with planted ground state σ\*. Let e be a
> noise vector sampled from error distribution χ^N. The SG-LWE problem is: given
> (J, h = J·σ\* + e mod q), recover σ\*.

**Justification for believed hardness:**

1. Finding the ground state of a general spin glass is NP-hard
   (Barahona, 1982 [1]).
2. Planted spin glass instances with sufficient frustration exhibit the Overlap Gap
   Property (OGP), which rules out stable algorithms including Approximate Message
   Passing and local MCMC methods (Gamarnik & Sudan, 2017 [2]).
3. The noise vector e provides information-theoretic hiding: even with unlimited
   computation, the noise makes the exact ground state unrecoverable from h alone
   (analogous to standard LWE).
4. The hardness does not depend on integer factoring or discrete logarithms, making
   it orthogonal to Shor's algorithm.

**Caveat:** Standard LWE with uniformly random matrices has ~20 years of sustained
cryptanalysis. SG-LWE with structured spin glass matrices is novel. The coupling
structure may introduce exploitable regularities that do not exist in random LWE.
Formal cryptanalysis of this specific assumption is an open problem. See
[Section 13](#13-security-analysis--hardness-assumptions) for further discussion.

### 8.2 Parameter Choices

| Parameter | Symbol | Value | Notes |
|---|---|---|---|
| Field modulus | q | 3329 | Prime; enables NTT; matches Kyber |
| Lattice dimension | N | 256 (16×16) | Number of spins |
| Lattice topology | — | Triangular, toroidal | Ensures frustration |
| Error distribution | χ | CBD(η=2) | Centered binomial, η=2 (same as Kyber-512) |
| Frustration noise | ψ | CBD(η=3) | Noise added during coupling construction |
| Shared secret size | — | 256 bits | Output of KEM |

**Public key size estimate:** J is sparse (each spin has 6 neighbors on a triangular
lattice), so J can be stored as 6N values in Z_q, plus h as N values in Z_q.
Total: 7N × ⌈log₂(q)⌉ bits = 7 × 256 × 12 ≈ 2.6 KB.

**Ciphertext size estimate:** (c₁, c₂) = N + N values in Z_q ≈ 768 bytes.

### 8.3 KeyGen

```
KeyGen() → (sk, pk)

    1. σ* ←$ Z_q^N                       # Random ground state (PRIVATE KEY)
                                          # Sampled from os.urandom
    
    2. Construct planted coupling matrix J:
       For each edge (i, j) in the triangular lattice:
           w_ij ←$ ψ                      # Frustration noise
           J_ij = σ*_i · σ*_j + w_ij     (mod q)
       
       The frustration noise w_ij ensures that σ* is a LOW-ENERGY state
       of the system defined by J, but not obviously so. Multiple 
       near-degenerate minima exist, obscuring the planted solution.
    
    3. Sample noise:
       e ←$ χ^N
    
    4. Compute noisy public field:
       h = J · σ* + e                     (mod q)
    
    5. Output:
       sk = σ*                            # Private key: planted ground state
       pk = (J, h)                        # Public key: couplings + noisy field
```

### 8.4 Encapsulate

```
Encaps(pk) → (ct, ss)

    Parse pk as (J, h).
    
    1. m ←$ {0, 1}^256                   # Random plaintext coin
    
    2. Derive deterministic randomness from m (for FO transform):
       (r, e₁, e₂) = SpinPRNG(SpinHash(0x10 || m || pk)).next(...)
       
       r  ∈ Z_q^N                         # Blinding vector
       e₁ ←$ χ^N                          # Noise (deterministic from m)
       e₂ ←$ χ                            # Noise (deterministic from m)
    
    3. Compute ciphertext:
       c₁ = Jᵀ · r + e₁                  (mod q)
       c₂ = hᵀ · r + e₂ + encode(m)      (mod q)
       
       where encode maps each bit of m to 0 or ⌊q/2⌋.
    
    4. Shared secret:
       ss = SpinHash(0x11 || m || c₁ || c₂)
    
    5. Output:
       ct = (c₁, c₂)
       ss = shared secret (256 bits)
```

### 8.5 Decapsulate

```
Decaps(sk, ct) → ss

    Parse ct as (c₁, c₂). Let sk = σ*.
    
    1. Recover noisy message:
       m̃  = c₂ - σ*ᵀ · c₁               (mod q)
       
       Algebraically:
         c₂ - σ*ᵀ · c₁
         = hᵀ·r + e₂ + encode(m) - σ*ᵀ·(Jᵀ·r + e₁)
         = (J·σ* + e)ᵀ·r + e₂ + encode(m) - σ*ᵀ·Jᵀ·r - σ*ᵀ·e₁
         = eᵀ·r + e₂ - σ*ᵀ·e₁ + encode(m)
         ≈ encode(m)
       
       The noise terms (eᵀ·r + e₂ - σ*ᵀ·e₁) are small when parameters
       are chosen correctly.
    
    2. Decode:
       m' = decode(m̃)
       
       For each coefficient: round to nearest 0 or ⌊q/2⌋, map back to
       bit value.
    
    3. Fujisaki-Okamoto re-encapsulation check:
       ct' = Encaps(pk, m'; using m' to derive deterministic randomness)
       
       If ct' ≠ ct:
           Return ss = SpinHash(0x12 || sk || ct)    # Implicit rejection
       
       This prevents chosen-ciphertext attacks. The implicit rejection
       (returning a key derived from sk) ensures the adversary cannot
       distinguish a valid from an invalid decapsulation.
    
    4. Shared secret:
       ss = SpinHash(0x11 || m' || c₁ || c₂)
```

### 8.6 Correctness

Decapsulation succeeds when the noise term `eᵀ·r + e₂ - σ*ᵀ·e₁` has magnitude
less than ⌊q/4⌋ in each coefficient. With CBD(η=2) noise and q = 3329, the
decryption failure probability is bounded by analysis identical to Kyber-512's,
since the algebraic structure is the same — only the matrix J differs. Target
failure rate: < 2^{-140}.

---

## 9. Layer 3 — Protocols

### 9.1 OPAQUE-Spin: Password-Authenticated Key Exchange

The PAKE protocol follows the OPAQUE framework (Jarecki et al., 2018 [3]), instantiated
with the Spin Glass KEM and SpinAEAD. OPAQUE is chosen over simpler PAKEs (SPAKE2,
SRP) because:

- It resists **offline dictionary attacks** even if the server is compromised.
- It does not require a group structure (works with any KEM).
- It has a security proof in the Universally Composable (UC) framework.

#### 9.1.1 Registration (one-time, requires a secure channel)

```
Client (Alice)                              Server (Bob)
══════════════                              ════════════

1. Choose password pw
2. Generate keypair:
   (sk_A, pk_A) = KeyGen()
3. Derive password key:
   pwk = SpinKDF(pw, salt=random_salt,
         info="qs-pake-envelope", length=32)
4. Encrypt private key:
   envelope = SpinAEAD.Encrypt(
     key=pwk, nonce=random,
     aad=pk_A.serialize(),
     plaintext=sk_A.serialize()
   )
                                            
         ─── (pk_A, envelope, salt) ──────▶

                                            5. Store registration record:
                                               record = {
                                                 client_id: "alice",
                                                 pk_A: pk_A,
                                                 envelope: envelope,
                                                 salt: salt
                                               }
```

The server never sees the password or the private key. It stores only the encrypted
envelope and the public key.

#### 9.1.2 Login (over insecure channel)

```
Client (Alice)                              Server (Bob)
══════════════                              ════════════

         ─── "alice" ─────────────────────▶
                                            1. Look up record for "alice"
                                            2. Generate server ephemeral:
                                               (esk_S, epk_S) = KeyGen()
         ◀── (pk_A, envelope, salt, epk_S)─

3. Recover private key:
   pwk = SpinKDF(pw, salt,
         "qs-pake-envelope", 32)
   sk_A = SpinAEAD.Decrypt(pwk, envelope)
   If decryption fails → wrong password → abort.

4. Generate client ephemeral:
   (esk_C, epk_C) = KeyGen()

5. Compute KEM shared secrets:
   (ct_s, ss_static) = Encaps(epk_S)       # to server's ephemeral
   
         ─── (epk_C, ct_s) ──────────────▶
                                            6. Compute shared secrets:
                                               ss_static = Decaps(esk_S, ct_s)
                                               (ct_c, ss_ephemeral) = Encaps(epk_C)
                                               (ct_a, ss_auth) = Encaps(pk_A)
                                               
         ◀── (ct_c, ct_a) ───────────────

7. Complete key agreement:
   ss_ephemeral = Decaps(esk_C, ct_c)
   ss_auth = Decaps(sk_A, ct_a)            # Only succeeds with real sk_A

8. Both sides derive session key:
   session_key = SpinKDF(
     key   = ss_static || ss_ephemeral || ss_auth,
     salt  = SpinHash(transcript),          # all messages exchanged
     info  = "qs-pake-session",
     length = 32
   )

         ◀══ ENCRYPTED SESSION ═══════════▶
```

**Authentication analysis:**
- `ss_auth` can only be computed by someone who possesses `sk_A`.
- `sk_A` can only be recovered by someone who knows the password.
- Therefore: successful session key derivation proves the client knows the password.
- No third party is involved at any stage.

### 9.2 Double Ratchet (Forward Secrecy)

Adapted from the Signal Protocol's Double Ratchet Algorithm (Marlinspike & Perrin,
2016 [4]), with the X25519 DH ratchet replaced by a KEM ratchet.

#### 9.2.1 Ratchet State

Each party maintains:

```
state = {
    root_key:        bytes,       # Root chain key (updated on KEM ratchet)
    send_chain_key:  bytes,       # Sending chain (updated per message)
    recv_chain_key:  bytes,       # Receiving chain (updated per message)
    my_kem_keypair:  (sk, pk),    # Current ephemeral KEM keypair
    peer_kem_pk:     PublicKey,   # Peer's latest ephemeral public key
    send_count:      int,         # Messages sent in current chain
    recv_count:      int,         # Messages received in current chain
    skipped_keys:    dict,        # Out-of-order message keys (bounded)
}
```

#### 9.2.2 KEM Ratchet Step (on reply turn)

When a party sends a message after receiving one (i.e., the conversation "turns"),
a KEM ratchet step occurs:

```
KEM_Ratchet(state, peer_new_pk):
    # 1. Receiving half: decapsulate against our current keypair
    #    (peer sent us a ciphertext against our public key)
    ss_recv = Decaps(state.my_kem_keypair.sk, received_ct)
    state.root_key, state.recv_chain_key = SpinKDF(
        key  = state.root_key,
        salt = ss_recv,
        info = "qs-ratchet-recv"
    )  →  (new_root_key: 32 bytes, chain_key: 32 bytes)
    
    state.root_key = new_root_key
    state.peer_kem_pk = peer_new_pk
    
    # 2. Sending half: generate new ephemeral, encapsulate to peer
    state.my_kem_keypair = KeyGen()          # Fresh ephemeral
    ct_send, ss_send = Encaps(state.peer_kem_pk)
    state.root_key, state.send_chain_key = SpinKDF(
        key  = state.root_key,
        salt = ss_send,
        info = "qs-ratchet-send"
    )
    
    # 3. Delete old KEM private key (forward secrecy)
    wipe(old_kem_sk)
    
    Return ct_send, state.my_kem_keypair.pk   # Sent with next message
```

#### 9.2.3 Symmetric Ratchet Step (per message)

Each message within a single turn advances the symmetric chain:

```
Symmetric_Ratchet(chain_key):
    new_chain_key = SpinKDF(chain_key, salt="", info="qs-chain-next",   length=32)
    message_key   = SpinKDF(chain_key, salt="", info="qs-chain-msgkey", length=32)
    
    Return (new_chain_key, message_key)
```

#### 9.2.4 Encrypt / Decrypt

```
Encrypt(state, plaintext, aad=""):
    # Advance symmetric ratchet
    state.send_chain_key, msg_key = Symmetric_Ratchet(state.send_chain_key)
    
    # Encrypt
    nonce = SpinHash(msg_key || state.send_count)[:16]
    ct = SpinAEAD.Encrypt(msg_key, nonce, aad, plaintext)
    
    # Build message header
    header = {
        kem_pk:     state.my_kem_keypair.pk,    # Our current ephemeral PK
        kem_ct:     state.pending_kem_ct,        # KEM ciphertext (if ratchet stepped)
        msg_number: state.send_count,
        prev_chain_length: ...,
    }
    
    state.send_count += 1
    wipe(msg_key)
    
    Return (header, ct)


Decrypt(state, header, ciphertext, aad=""):
    # If header.kem_pk differs from state.peer_kem_pk → KEM ratchet
    if header.kem_pk != state.peer_kem_pk:
        # Store any skipped message keys from current chain
        store_skipped_keys(state, header.prev_chain_length)
        # Perform KEM ratchet
        KEM_Ratchet(state, header.kem_pk)
    
    # Advance symmetric ratchet to the correct position
    while state.recv_count < header.msg_number:
        state.recv_chain_key, skipped = Symmetric_Ratchet(state.recv_chain_key)
        store_skipped_key(state, skipped)        # for out-of-order messages
        state.recv_count += 1
    
    state.recv_chain_key, msg_key = Symmetric_Ratchet(state.recv_chain_key)
    
    # Decrypt
    nonce = SpinHash(msg_key || header.msg_number)[:16]
    plaintext = SpinAEAD.Decrypt(msg_key, nonce, aad, ciphertext)
    
    state.recv_count += 1
    wipe(msg_key)
    
    Return plaintext
```

#### 9.2.5 Security Properties

| Property | Mechanism |
|---|---|
| **Confidentiality** | SpinAEAD encryption with unique per-message keys |
| **Integrity** | SpinAEAD authentication tag on every message |
| **Forward secrecy** | Old KEM private keys and chain keys are deleted. Compromising current state reveals nothing about past messages. |
| **Break-in recovery** | After a KEM ratchet step, the adversary must break a new KEM instance to continue reading messages. |
| **Out-of-order delivery** | Skipped message keys are cached (bounded) to allow decryption of reordered messages. |

---

## 10. Visual Fingerprinting

The visual fingerprint provides human-verifiable authentication without requiring
users to compare hex strings. Two modes are supported:

| Mode | Input | Output |
|------|-------|--------|
| **Plain** | Session key | Abstract lattice pattern (colours from session key) |
| **Identity-bound** | Session key + both parties' photos | Peer's face recognisable *through* the lattice colouring |

The identity-bound mode is the recommended default for user-facing applications.

### 10.1 Plain Fingerprint

```
VisualFingerprint(session_key, width=128, height=128) → Image

    1. Derive fingerprint seed:
       fp_seed = SpinKDF(session_key, salt="", info="qs-visual-fp", length=32)
    
    2. Initialize a display lattice (separate from the crypto lattice):
       display = SpinLattice(n=width, q=256)
       display.seed_from_bytes(fp_seed)
    
    3. Run simulation with annealing:
       For temp in [10.0, 9.5, ..., 0.5]:
           display.step()
    
    4. Render:
       For each spin σ_i in the display lattice:
           Map σ_i ∈ Z_256 to an HSV color:
             Hue        = σ_i / 256 × 360°
             Saturation = f(neighbor_variance)    # frustrated regions are vivid
             Value      = 0.7 + 0.3 × g(energy)  # low energy = brighter
           Set pixel (x, y) to the resulting RGB color.
    
    5. Return image
```

### 10.2 Identity-Bound Fingerprint

The identity-bound fingerprint superimposes a peer's identity photo onto the
quantum lattice simulation. The photo modulates the lattice **coupling structure**
(domain topology) while the session key determines the **spin colouring**
(hue/saturation/value). Changing either input produces an unrecognisable image.

```
IdentityFingerprint(session_key, my_photo, peer_photo, width, height) → Image

    1. Derive fingerprint seed (binds session + both identities):

       photo_hash_a = SpinHash(my_photo)
       photo_hash_b = SpinHash(peer_photo)
       combined     = sort_and_concat(photo_hash_a, photo_hash_b)
         // sorting makes the seed symmetric: A↔B produce the same seed

       fp_seed = SpinKDF(
           key  = session_key,
           salt = combined,
           info = "qs-identity-fingerprint",
           length = 32,
       )

    2. Derive coupling bias from the peer's photo:

       photo_gray = grayscale(peer_photo, resize to width × height)
       For each lattice site i:
           coupling_bias[i] = photo_gray[i]
         // bright pixels → stronger ferromagnetic coupling → larger domains
         // dark  pixels → weaker coupling → more frustrated, vivid boundaries
         // net effect: domain walls follow the photo's edges

    3. Initialize and bias the display lattice:

       display = SpinLattice(n=width, q=256)
       display.seed_from_bytes(fp_seed)
       For each edge (i,j):
           J_ij += coupling_bias[i] + coupling_bias[j]   (mod q)

    4. Anneal the lattice:

       For temp in [10.0, 9.5, ..., 0.5]:
           display.step(temperature=temp)

       The ground state now encodes BOTH the session key (via fp_seed)
       and the peer's face (via coupling bias).

    5. Render to RGBA using the same HSV mapping as the plain fingerprint.

    Result: The peer's face is visible through the domain structure —
    smooth same-hue regions follow bright areas of the photo; frustrated
    multi-colour boundaries follow the photo's edges.  The specific
    colours and fine structure are determined by the session key.
```

**What each party sees:**

```
Alice's screen                          Bob's screen
══════════════                          ════════════

Bob's face rendered through             Alice's face rendered through
the lattice colouring                   the lattice colouring

(Both seeded from the same fp_seed      (Identical fp_seed → identical
 → identical colour assignment)          colour assignment)
```

**Verification protocol:**

```
Alice (on phone): "I see Bob's face — left half blue-green, right half
                   orange, spiral near his chin."
Bob  (on phone):  "I see Alice's face — forehead is red, jawline is teal,
                   and there's a purple vortex on her left cheek."

Both: "My pattern is ..."  →  match confirms no MITM.
```

### 10.3 Photo Hash Exchange

For the identity-bound fingerprint to work, both parties must hold
byte-identical copies of both photos. During registration the application
should:

1. Each party computes `photo_hash(my_photo) → [u8; 32]` using SpinHash.
2. Exchange hashes over the authenticated channel (alongside the PAKE record).
3. Before generating the fingerprint, verify the peer's photo hash matches
   the hash received during registration.

This ensures a mismatched photo (e.g. from a JPEG re-encoding) is detected
*before* the visual comparison, rather than producing a confusing mismatch.

### 10.4 Properties

- **Sensitivity:** A single-bit change in the session key produces a visually
  unrecognisable fingerprint. Two MITM'd sessions will produce entirely different
  patterns with overwhelming probability.
- **Identity binding:** The photo hash is mixed into the KDF salt. An attacker
  who substitutes a different photo during MITM will produce a different seed,
  yielding different colours even if the session key accidentally matched.
- **Human comparability:** The image contains large-scale structures (domains,
  spirals, frustration boundaries) overlaid on a recognisable face — more
  intuitive to compare than abstract patterns or hex strings.
- **Determinism:** The same session key + same photos always produces the same
  image, allowing both parties to generate independently and compare.
- **Symmetry:** The hash combination is sorted, so Alice computing
  `identity_fingerprint(key, alice_photo, bob_photo)` and Bob computing
  `identity_fingerprint(key, bob_photo, alice_photo)` produce the same
  fingerprint seed — only the displayed overlay face differs.

### 10.5 Security Notes

- **Photos are not secret.** They are public identity anchors. The security of
  the fingerprint comes entirely from the session key.
- **Photo overlay must not obscure the lattice.** The coupling-bias approach
  ensures the photo shapes the *topology* of domains rather than being painted
  on top. The lattice colours remain the security-critical visual signal.
- **MITM detection.** An attacker who intercepts the key exchange holds a
  *different* session key. Even with correct photos, the colours will be
  completely different — detected during the out-of-band comparison.

---

## 11. Public API Surface

The public API is the only interface external code should use. All internal modules
are considered private. The library is implemented in Rust for memory safety,
performance, and future constant-time guarantees.

**Key types** — `PrivateKey` and `SharedSecret` implement `Zeroize + ZeroizeOnDrop`
so secret material is wiped from memory when values go out of scope.

```rust
use qs_crypto::*;

// ════════════════════════════════════════════════════════
// KEY MANAGEMENT
// ════════════════════════════════════════════════════════

let keypair: KeyPair = generate_keypair(&Params::default());
// KeyPair { public_key: PublicKey, private_key: PrivateKey }

let pk_bytes: Vec<u8> = keypair.public_key.to_bytes();
let pk: PublicKey = PublicKey::from_bytes(&pk_bytes)?;

let sk_bytes: Vec<u8> = keypair.private_key.to_bytes();   // handle with care
let sk: PrivateKey = PrivateKey::from_bytes(&sk_bytes)?;


// ════════════════════════════════════════════════════════
// RAW KEM (for protocol designers)
// ════════════════════════════════════════════════════════

let result: EncapsulationResult = encapsulate(&keypair.public_key);
// result.ciphertext  — send to key holder
// result.shared_secret — 256-bit SharedSecret (Zeroize on drop)

let shared: SharedSecret = decapsulate(&keypair.private_key, &result.ciphertext)?;
// Returns Error::DecapsulationFailed on FO rejection


// ════════════════════════════════════════════════════════
// PAKE: PASSWORD-AUTHENTICATED KEY EXCHANGE
// ════════════════════════════════════════════════════════

// Registration (one-time, over secure channel)
let record: RegistrationRecord = pake_register("shared_secret", &keypair);
let record_bytes = record.to_bytes();
let record = RegistrationRecord::from_bytes(&record_bytes)?;

// Login (over insecure channel)
let mut client = PakeClient::new("shared_secret");
let mut server = PakeServer::new(record);

let msg1: Vec<u8> = client.start();                         // client → server
let msg2: Vec<u8> = server.respond(&msg1)?;                 // server → client
let client_key: [u8; 32] = client.finalize(&msg2)?;
let server_key: [u8; 32] = server.finalize()?;
assert_eq!(client_key, server_key);


// ════════════════════════════════════════════════════════
// RATCHETED SESSION (forward-secret messaging)
// ════════════════════════════════════════════════════════

let mut session = Session::new(
    keypair,
    peer_public_key,
    &session_key,                                // From PAKE or direct KEM
);

let ciphertext: Vec<u8> = session.encrypt(b"attack at dawn");  // auto-ratchets
let plaintext:  Vec<u8> = session.decrypt(&ciphertext)?;       // auto-ratchets

// Session serialization (for persistence — output is SENSITIVE)
let state: Vec<u8> = session.save();
let session = Session::restore(&state)?;


// ════════════════════════════════════════════════════════
// VISUAL FINGERPRINT
// ════════════════════════════════════════════════════════

// Plain fingerprint (session key only):
let rgba_pixels: Vec<u8> = session.visual_fingerprint(128, 128);
// Also available as a standalone function:
let rgba = visual_fingerprint(&session_key, 128, 128);

// Identity-bound fingerprint (photo superimposed on lattice):
session.set_identity_photos(
    IdentityPhoto::new(my_photo_bytes),
    IdentityPhoto::new(peer_photo_bytes),
);
let rgba = session.identity_fingerprint(128, 128)?;
// Peer's face visible through spin-domain colouring.
// Also available standalone:
let rgba = identity_fingerprint(&session_key, &my_photo, &peer_photo, 128, 128);

// Verify both sides hold identical photo bytes before comparing:
let hash: [u8; 32] = photo_hash(&peer_photo);


// ════════════════════════════════════════════════════════
// LOW-LEVEL PRIMITIVES (for advanced users / testing)
// ════════════════════════════════════════════════════════

let digest: [u8; 32] = spin_hash(data);

let derived: Vec<u8> = spin_kdf(key, salt, info, /*length=*/ 32);

let ct: aead::AeadCiphertext = aead::encrypt(&key, &nonce, aad, plaintext);
let pt: Vec<u8> = aead::decrypt(&key, &nonce, aad, &ct.ciphertext, &ct.tag)?;
// Returns Error::AuthenticationFailed if tag verification fails

let mut prng = SpinPrng::new(&seed);
let random_bytes: Vec<u8> = prng.next_bytes(64);
```

---

## 12. Security Parameters

### 12.1 Recommended Parameter Sets

| Parameter | QS-128 | QS-192 | QS-256 |
|---|---|---|---|
| **Target security** | 128-bit | 192-bit | 256-bit |
| **Field modulus q** | 3329 | 3329 | 3329 |
| **Lattice side n** | 12 | 14 | 16 |
| **Total spins N** | 144 | 196 | 256 |
| **Sponge rate R** | 48 | 64 | 64 |
| **Sponge capacity C** | 96 | 132 | 192 |
| **Permutation rounds K** | 24 | 28 | 32 |
| **CBD noise η** | 2 | 2 | 2 |
| **Frustration noise η_f** | 3 | 3 | 3 |
| **Public key size** | ~1.5 KB | ~2.0 KB | ~2.6 KB |
| **Ciphertext size** | ~432 B | ~588 B | ~768 B |
| **KEM shared secret** | 256 bits | 256 bits | 256 bits |
| **AEAD tag** | 128 bits | 128 bits | 128 bits |

### 12.2 Default

The library defaults to **QS-256**. Users can select a parameter set at initialization:

```rust
let keypair = qs_crypto::generate_keypair(&Params::default());          // QS-256
let keypair = qs_crypto::generate_keypair(
    &Params::from_security_level(SecurityLevel::QS128),
);
```

---

## 13. Security Analysis & Hardness Assumptions

### 13.1 What Rests on Established Ground

| Component | Foundation | Confidence |
|---|---|---|
| Sponge construction | Same framework as Keccak/SHA-3 (Bertoni et al. [5]) | High — proven indifferentiability from random oracle (given ideal permutation) |
| AEAD (duplex sponge) | Same as Ketje/Keyak | High — proven secure in sponge model |
| OPAQUE PAKE | UC-secure framework (Jarecki et al. [3]) | High — standardized by IETF (RFC 9497) |
| Double Ratchet | Signal Protocol, formally analyzed (Cohn-Gordon et al. [6]) | High — deployed at scale |
| FO transform (CCA security) | Fujisaki-Okamoto (1999, 2013 [7]) | High — standard KEM construction |

### 13.2 What Is Novel and Unvetted

| Component | Assumption | Risk |
|---|---|---|
| **Spin lattice permutation** | That the spin dynamics achieve sufficient diffusion/confusion to behave as a pseudorandom permutation | **Medium** — must be validated empirically via NIST SP 800-22 and TestU01. Failure here breaks ALL layers. |
| **SG-LWE hardness** | That LWE remains hard when the matrix is a structured spin glass coupling matrix (not uniformly random) | **High** — the spin glass structure may introduce algebraic regularities exploitable by lattice reduction or physics-informed attacks. No formal reduction to standard LWE exists. |
| **Planted coupling construction** | That the coupling generation procedure `J_ij = σ*_i · σ*_j + w_ij` produces instances where ground-state recovery is hard on average | **High** — worst-case NP-hardness does not guarantee average-case hardness. The planted structure may leak information about σ\*. |

### 13.3 Mitigation: Hybrid Mode

For users who want the spin glass design but cannot accept an unvetted asymmetric
assumption, the library should offer a **hybrid mode**:

```
Hybrid KEM:
    (ct_spin, ss_spin) = SpinGlassKEM.Encaps(pk_spin)
    (ct_x25519, ss_x25519) = X25519_KEM.Encaps(pk_x25519)
    
    combined_ss = SpinKDF(ss_spin || ss_x25519, salt="hybrid")
    combined_ct = ct_spin || ct_x25519
```

The combined scheme is at least as strong as the stronger of the two components. If
SG-LWE is broken, X25519 provides a safety net (and vice versa for quantum
adversaries).

### 13.4 Required Validation Before Any Deployment

1. **Statistical testing of the sponge permutation.** Run NIST SP 800-22 and TestU01
   BigCrush on output from the SpinPRNG. All tests must pass.
2. **Known-answer tests (KATs).** Generate deterministic test vectors for all
   primitives and verify cross-implementation consistency.
3. **Lattice reduction attacks on SG-LWE.** Apply BKZ and sieving algorithms to
   the structured coupling matrix. Compare concrete bit-security to standard LWE
   with the same dimensions.
4. **Differential analysis of the sponge.** Measure differential propagation
   probability through the spin dynamics round function. Probability must decay
   exponentially with number of rounds.
5. **External cryptanalysis.** Publish the scheme and invite analysis from the
   cryptographic community before any real-world use.

---

## 14. Implementation Plan

The library is implemented in Rust for memory safety, zero-cost abstractions,
and a path to constant-time operations. The project is structured as a Cargo
workspace with layered modules (see Module Map above). Stub APIs with full
type signatures are in place; each phase fills in the implementations behind
those APIs.

### Phase 0: Scaffold (DONE)

- Rust crate structure mirroring the four-layer architecture.
- Public API types with `Zeroize`/`ZeroizeOnDrop` on secret material.
- Integration test suite (`tests/key_generation.rs`, `tests/encryption.rs`,
  `tests/decryption.rs`) — 9 structural tests passing, 25 crypto tests
  `#[ignore]`d pending implementation.
- Error type hierarchy via `thiserror`.
- Identity-bound visual fingerprint API (`IdentityPhoto`, `identity_fingerprint`,
  `photo_hash`, `Session::set_identity_photos`).

### Phase 1: Core Primitives

- Implement `SpinLattice` in `src/core/lattice.rs` — triangular topology,
  toroidal boundaries, synchronous Potts update step.
- Implement `SpinSponge` in `src/core/sponge.rs` — absorb/permute/squeeze.
- Implement `SpinHash`, `SpinPRNG`, `SpinKDF`, `SpinAEAD` in `src/primitives/`.
- Run NIST SP 800-22 and TestU01 on the sponge output.
- **Gate:** Sponge passes all statistical tests before proceeding.

### Phase 2: KEM

- Implement `generate_keypair` in `src/kem/keygen.rs` — planted coupling
  construction with frustration noise.
- Implement `encapsulate` in `src/kem/encaps.rs` — FO transform,
  deterministic re-encryption.
- Implement `decapsulate` in `src/kem/decaps.rs` — implicit rejection.
- Generate Known-Answer Test (KAT) vectors.
- Basic lattice reduction analysis (estimate concrete bit-security).
- **Gate:** KEM correctness tests pass; decryption failure rate < 2^{-140}.

### Phase 3: Protocols

- Implement OPAQUE-Spin PAKE in `src/protocols/pake.rs`.
- Implement Double Ratchet (KEM ratchet) in `src/protocols/ratchet.rs`.
- Implement Session state machine in `src/protocols/session.rs`.
- Un-ignore and pass all integration tests: full PAKE → Session →
  Encrypt/Decrypt cycle.

### Phase 4: Hardening

- Visual fingerprint renderer (`src/visual/fingerprint.rs`).
- Hybrid mode (SpinGlassKEM + X25519).
- Constant-time operations via `subtle` crate for tag comparison and key
  handling.
- `#[cfg(test)]` property-based tests via `proptest`.
- Fuzzing harness via `cargo-fuzz`.

### Phase 5: Publication

- Write specification document.
- Publish SG-LWE assumption paper for community review.
- Open-source the library with CI (cargo test, clippy, miri).

---

## 15. Open Questions

1. **Average-case hardness of SG-LWE.** Does the planted coupling construction
   produce hard instances with high probability over the randomness of σ\* and w_ij?
   Is there a reduction to a standard assumption (e.g., standard LWE or worst-case
   lattice problems)?

2. **Optimal round function design.** Should the spin dynamics include an explicit
   nonlinear substitution step (S-box), or is the modular arithmetic sufficient?
   What is the minimum number of rounds for full diffusion?

3. **Quantum annealing attacks.** Quantum annealers (D-Wave) are specifically designed
   to find spin glass ground states. Does this threaten SG-LWE concretely at current
   or near-future qubit counts? (Note: current quantum annealers are noisy and limited
   to ~5000 qubits with sparse connectivity, likely insufficient for the parameters
   proposed here, but this requires ongoing monitoring.)

4. **Parameter optimization.** The current parameters are derived by analogy to Kyber.
   A dedicated parameter selection process — modeling the coupling structure's impact
   on lattice reduction — is needed.

5. **Formal verification.** Can the protocol compositions (PAKE + Ratchet) be formally
   verified using tools like ProVerif or Tamarin?

---

## 16. References

[1] F. Barahona. "On the computational complexity of Ising spin glass models."
    *Journal of Physics A*, 15(10):3241, 1982.

[2] D. Gamarnik and M. Sudan. "Limits of local algorithms over sparse random graphs."
    *Annals of Probability*, 45(4):2353–2381, 2017.

[3] S. Jarecki, H. Krawczyk, and J. Xu. "OPAQUE: An Asymmetric PAKE Protocol
    Secure Against Pre-Computation Attacks." *Eurocrypt 2018*.
    See also: IETF RFC 9497.

[4] T. Perrin and M. Marlinspike. "The Double Ratchet Algorithm." 2016.
    https://signal.org/docs/specifications/doubleratchet/

[5] G. Bertoni, J. Daemen, M. Peeters, and G. Van Assche. "Sponge Functions."
    ECRYPT Hash Workshop, 2007.

[6] K. Cohn-Gordon, C. Cremers, B. Dowling, L. Garratt, and D. Stebila. "A Formal
    Security Analysis of the Signal Messaging Protocol." *IEEE EuroS&P*, 2017.

[7] E. Fujisaki and T. Okamoto. "Secure Integration of Asymmetric and Symmetric
    Encryption Schemes." *Journal of Cryptology*, 26(1):80–101, 2013.

---

## Appendix A: Notation Reference

| Symbol | Meaning |
|---|---|
| Z_q | Integers modulo q (the field) |
| σ_i | Spin value at lattice site i |
| σ\* | Planted ground state (private key) |
| J_ij | Coupling constant between spins i and j |
| J | Full coupling matrix (public key component) |
| h | Noisy public field vector = J·σ\* + e |
| e, e₁, e₂ | Noise vectors sampled from χ |
| χ | Error distribution (Centered Binomial, η=2) |
| ψ | Frustration noise distribution (CBD, η=3) |
| N | Number of lattice spins (n²) |
| n | Lattice side length |
| q | Field modulus (3329) |
| R | Sponge rate (number of spins) |
| C | Sponge capacity (number of spins) |
| K | Number of permutation rounds |
| CBD(η) | Centered Binomial Distribution with parameter η |
| ⊕ | XOR / addition in appropriate field |
| \|\| | Concatenation |
| ←$ | Sampled uniformly at random |

## Appendix B: Example Protocol Transcript

A complete example of two parties establishing a session:

```
═══════════════════════════════════════════════════════════════
 EXAMPLE: Alice and Bob establish a secure channel
═══════════════════════════════════════════════════════════════

 Prerequisites: Alice and Bob meet in person and agree on the
 password "correct horse battery staple".

 ── REGISTRATION (Alice, one-time) ──

 Alice:
   keypair_A = generate_keypair(params=QS_256)
   record = pake_register("correct horse battery staple", keypair_A)
   → sends record to Bob's server over a secure channel

 ── LOGIN ──

 Alice:                              Bob's Server:
   client = PAKEClient(password)     server = PAKEServer(record)
   msg1 = client.start()       ───▶
                                     msg2 = server.respond(msg1)
                               ◀───
   key_A = client.finalize(msg2)     key_B = server.finalize()
   
   assert key_A == key_B             # Both derived the same session key

 ── SESSION ──

 Alice:                              Bob:
   sess_A = Session(keypair_A,       sess_B = Session(keypair_B,
     peer_pk=pk_B, key=key_A)          peer_pk=pk_A, key=key_B)

 ── VISUAL VERIFICATION (optional, out-of-band) ──

   img_A = sess_A.fingerprint()      img_B = sess_B.fingerprint()
   img_A.save("fp.png")              img_B.save("fp.png")
   
   [Alice calls Bob on the phone]
   Alice: "I see a red spiral top-left, blue cluster bottom-right"
   Bob:   "Same here."
   → Session authenticated. No CA was involved.

 ── MESSAGING ──

   ct1 = sess_A.encrypt(b"Hello Bob")
                                ───▶ pt1 = sess_B.decrypt(ct1)
                                     ct2 = sess_B.encrypt(b"Hi Alice")
   pt2 = sess_A.decrypt(ct2)  ◀───

   # Each message used a unique key. Old keys are deleted.
   # Forward secrecy is maintained automatically.
```
