# QS-Crypto Specification

**Version:** 0.3
**Status:** Draft for Cryptographic Peer Review

---

## 1. Introduction

QS-Crypto is an experimental cryptographic library built on a novel permutation inspired by frustrated spin-glass lattice dynamics. It provides a complete protocol stack: hash, KDF, PRNG, AEAD (symmetric); Ring-LWE KEM with hybrid combiners (asymmetric); PAKE and double-ratchet session protocols.

This document precisely defines all algorithms with pseudocode, parameter sets, and security claims. The library is implemented in Rust.

---

## 2. Notation

| Symbol | Meaning |
|--------|---------|
| `q` | Field modulus: 3329 |
| `N` | Polynomial ring dimension (128 or 256) |
| `Z_q` | Integers modulo q |
| `R_q` | `Z_q[X]/(X^N + 1)` |
| `‖` | Concatenation |
| `⊕` | Bitwise XOR |
| `CBD(η)` | Centered Binomial Distribution with parameter η |
| `LE16(x)` | Little-endian encoding of 16-bit integer x |

---

## 3. Parameter Sets

| Parameter | QS-128 | QS-192 | QS-256 |
|-----------|--------|--------|--------|
| Security target (bits) | 128 | 192 | 256 |
| Level byte | `0x01` | `0x02` | `0x03` |
| `q` (field modulus) | 3329 | 3329 | 3329 |
| Lattice side `n` | 12 | 14 | 16 |
| Total spins `n²` | 144 | 196 | 256 |
| Ring dimension `N` | 128 | 256 | 256 |
| Sponge rate | 48 | 64 | 64 |
| Sponge capacity | 96 | 132 | 192 |
| Permutation rounds | 24 | 28 | 32 |
| CBD η | 2 | 2 | 2 |
| FO coin bytes | 16 | 24 | 32 |

All three levels share `q = 3329` for compatibility with the Kyber/ML-KEM NTT infrastructure.

---

## 4. The SpinLattice Permutation

### 4.1 Lattice Topology

An `n × n` triangular lattice with toroidal boundary conditions. Each spin `σ_i ∈ Z_q` has 6 neighbours (East, West, North, South, NorthEast, SouthWest). Coupling constants `J_{ij} ∈ Z_q` define the interaction strength.

### 4.2 Update Rule (Synchronous)

```
Input: spins σ[0..n²), couplings J, round constants rc
Output: updated spins σ'

For each spin i in parallel:
    1. h_eff ← Σ_{j ∈ neighbours(i)} J_{ij} · σ_j   (mod q)
    2. rc_i  ← i · 2654435761                          (mod q)
    3. t     ← h_eff + σ_i + rc_i                      (mod q)
    4. σ'_i  ← t³                                       (mod q)
```

The cubing S-box is a permutation on Z_q since gcd(3, q-1) = gcd(3, 3328) = 1.

### 4.3 Seeding

Coupling constants are deterministically generated from a seed via FNV-1a hash → SplitMix64 expansion. Spin values are then set to zero before sponge use.

---

## 5. Sponge Construction

### 5.1 State Partition

The `n²` spins are partitioned into:
- **Rate** `r` spins: indices `[0, r)` — data I/O region
- **Capacity** `c` spins: indices `[r, r+c)` — hidden security margin

### 5.2 Absorb

```
Input: message M
Procedure:
    1. Pad M with 10*1 padding to a multiple of r·2 bytes
    2. For each r-element block B:
        a. For i = 0 to r-1:
             σ_i ← σ_i + LE16(B[2i..2i+2])  (mod q)
        b. Run permutation for `rounds` steps
```

### 5.3 Squeeze (whitened, for PRNG)

```
Input: output_length L bytes
Output: L pseudorandom bytes
Procedure:
    While output < L bytes:
        1. Run permutation
        2. For i = 0 to r-1:
             Read σ_i, σ_{(i+7) mod n²}, σ_{(i+19) mod n²}
             Apply SplitMix64-style whitening mixer
             Emit 2 bytes
```

### 5.4 Squeeze Raw (standard sponge, for KDF/hash)

```
Input: output_length L bytes
Output: L bytes from rate region
Procedure:
    While output < L bytes:
        1. Run permutation
        2. For i = 0 to min(r, remaining/2):
             Emit LE16(σ_i)
```

---

## 6. Symmetric Primitives

### 6.1 SpinHash

```
SpinHash(M) → 32-byte digest:
    1. sponge ← new SpinSponge(QS-256)
    2. sponge.absorb([0x01, 0x01, 0x03] ‖ M)     // [version, Hash, QS-256]
    3. return sponge.squeeze(32)
```

### 6.2 SpinKDF

HKDF-style extract-then-expand:

```
SpinKDF(key, salt, info, length) → derived key:
  EXTRACT:
    1. sponge ← new SpinSponge(QS-256)
    2. sponge.absorb([0x01, 0x03, 0x03] ‖ salt ‖ key)
    3. PRK ← sponge.squeeze_raw(32)

  EXPAND:
    4. prev ← []
    5. For counter = 1, 2, ...:
         sponge ← new SpinSponge(QS-256)
         sponge.absorb(PRK ‖ prev ‖ info ‖ counter)
         block ← sponge.squeeze_raw(32)
         output ← output ‖ block
         prev ← block
    6. return output[0..length]
```

### 6.3 SpinPRNG

Sponge-based PRNG using whitened squeeze for uniformity.

### 6.4 Hybrid AEAD

```
AEAD.Encrypt(key, nonce, aad, plaintext):
    1. spin_subkey  ← SpinSponge([0x01,0x04,0x03] ‖ key ‖ nonce ‖ len(aad) ‖ aad).squeeze(32)
    2. shake_subkey ← SHAKE256([0x01,0x04,0x03] ‖ key ‖ nonce)[0:32]
    3. combined_key ← spin_subkey ⊕ shake_subkey
    4. chacha_nonce ← SHAKE256("qs-aead-nonce" ‖ key ‖ nonce)[0:12]
    5. (ct, tag)    ← ChaCha20-Poly1305.Encrypt(combined_key, chacha_nonce, aad, plaintext)
    6. return (ct, tag)
```

The hybrid key derivation ensures confidentiality even if SpinSponge is broken (SHAKE256 + ChaCha20-Poly1305 suffices) or vice versa.

---

## 7. Ring-LWE KEM

### 7.1 Key Generation

```
KeyGen(params) → (pk, sk):
    1. seed ← OS_Random(32)
    2. a    ← SHAKE256_Expand(seed, N)           // 12-bit rejection sampling, uniform in [0, q)
    3. s    ← CBD_SHAKE(η, N)                     // secret polynomial
    4. e    ← CBD_SHAKE(η, N)                     // error polynomial
    5. b    ← a·s + e   (mod X^N+1, mod q)
    6. pk   ← [level ‖ seed ‖ encode(b)]
    7. sk   ← [level ‖ encode(s) ‖ pk]
    8. return (pk, sk)
```

### 7.2 Encapsulation (Fujisaki-Okamoto)

```
Encaps(pk) → (ct, ss):
    1. Parse pk: level, seed, b
    2. coin ← OS_Random(coin_bytes)
    3. (r, e1, e2) ← DeriveBlinding(coin, SHAKE256(pk))
    4. a ← SHAKE256_Expand(seed, N)               // same 12-bit rejection as KeyGen
    5. c1 ← a·r + e1
    6. c2 ← b·r + e2 + Encode(coin)
    7. ct ← [level ‖ encode(c1) ‖ encode(c2)]
    8. ss ← SHAKE256(0x11 ‖ coin ‖ ct)
    9. return (ct, ss)
```

### 7.3 Decapsulation with Implicit Rejection

```
Decaps(sk, ct) → ss:
    1. Parse sk: level, s, embedded_pk
    2. Parse ct: level, c1, c2
    3. m̃ ← c2 - s·c1                              // noisy message
    4. m' ← Decode(m̃)                              // round to nearest
    5. (ct', ss_valid) ← Encaps_inner(pk, m')       // re-encapsulate
    6. ss_reject ← SHAKE256(0x12 ‖ sk ‖ ct)
    7. match ← CT_EQ(ct, ct')                       // constant-time
    8. ss ← CT_SELECT(match, ss_valid, ss_reject)
    9. return ss
```

### 7.4 Polynomial Multiplication

- **N=256**: 7-layer Cooley-Tukey NTT, ζ = 17 (primitive 256th root of unity mod 3329)
- **N=128**: 6-layer Cooley-Tukey NTT, ζ = 289 (primitive 128th root of unity mod 3329)

Both use Barrett reduction for constant-time modular arithmetic.

---

## 8. Hybrid KEM

### 8.1 Two-Way Hybrid (Spin + X25519)

```
combined_ss = SHAKE256(ss_spin ‖ ss_x25519 ‖ pk_spin ‖ pk_x25519 ‖ ct_spin ‖ ct_x25519 ‖ "qs-hybrid-v2")
```

### 8.2 Three-Way Hybrid (Spin + X25519 + ML-KEM-768)

```
combined_ss = SHAKE256(ss_spin ‖ ss_x25519 ‖ ss_mlkem ‖ pk_spin ‖ pk_x25519 ‖ ct_spin ‖ ct_x25519 ‖ ct_mlkem ‖ "qs-full-hybrid-v1")
```

The combined shared secret is at least as strong as the strongest component. The NIST SP 800-56Cr2 transcript binding ensures the combiner is secure even if one component is completely broken.

---

## 9. PAKE Protocol

Registration:
1. Client sends password and server generates keypair
2. Server encrypts private key under password-derived key (SHAKE256 → ChaCha20-Poly1305)
3. Server stores `(salt, nonce, encrypted_sk, pk)` as registration record

Authentication:
1. Client → Server: client nonce
2. Server → Client: salt, nonce, encrypted envelope, KEM ciphertext
3. Client derives password key, decrypts envelope, decapsulates KEM
4. Both derive session key from KEM shared secret + transcript

---

## 10. Double Ratchet

Symmetric ratchet using SHAKE256 KDF chains:
- `chain_key_{n+1}, message_key_n = KDF(chain_key_n, "qs-ratchet-sym")`
- KEM ratchet step: `new_root = SHAKE256(root_key ‖ kem_ss ‖ "qs-ratchet-kem")`

Forward secrecy: chain keys are zeroized after deriving message keys.
Break-in recovery: a KEM ratchet step introduces fresh entropy.

---

## 11. Security Claims

### Established (vetted components)
- AEAD confidentiality: reduces to ChaCha20-Poly1305 security (even if SpinSponge is broken)
- KEM IND-CCA2: reduces to Ring-LWE + SHAKE256 (FO transform, all blinding from SHAKE256)
- 3-way hybrid: at least as strong as ML-KEM-768 or X25519

### Novel (requires peer review)
- **SG-LWE Hardness Assumption**: recovering planted spin-glass couplings from noisy lattice observations is computationally hard
- SpinSponge permutation: no proof of indifferentiability; supported by NIST SP 800-22 + TestU01 BigCrush statistical evidence

### Mitigations
- Hybrid key derivation in AEAD ensures SHAKE256 is a fallback
- Hybrid KEM ensures X25519 or ML-KEM-768 protects if Ring-LWE/SG-LWE is broken
- Side-channel hardening: Barrett reduction, `black_box`, `#[inline(never)]`, constant-time comparisons

---

## 12. Test Vectors

KAT vectors are in `tests/kat_vectors.json`, covering:
- SpinHash (6 vectors)
- SpinKDF (5 vectors)
- AEAD (5 vectors)
- Sponge squeeze_raw (4 vectors)
- KEM encaps/decaps (9 vectors: 3 per security level)

---

## 13. References

1. Bertoni, G., Daemen, J., Peeters, M., Van Assche, G. "Sponge Functions." ECRYPT Hash Workshop, 2007.
2. NIST FIPS 202. "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions." 2015.
3. Bernstein, D.J. "ChaCha20-Poly1305." RFC 8439, 2018.
4. NIST FIPS 203. "Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)." 2024.
5. Langley, A. "X25519." RFC 7748, 2016.
6. Fujisaki, E., Okamoto, T. "Secure Integration of Asymmetric and Symmetric Encryption Schemes." CRYPTO 1999.
7. NIST SP 800-56Cr2. "Recommendation for Key-Derivation Methods in Key-Establishment Schemes." 2020.
8. NIST SP 800-22. "A Statistical Test Suite for Random and Pseudorandom Number Generators." 2010.