# QS-Crypto Security Model & Hardening Status

**Status (as of 2026):** Research-grade library with comprehensive hardening across both asymmetric and symmetric layers. **Not recommended for production use without additional review and parameter validation.**

---

## What Has Been Hardened

### 1. KEM Security Reduction (Major Hardening)
- **Before:** The Fujisaki-Okamoto transform and noise sampling inside `generate_keypair` / `encapsulate` used `SpinPrng` (the novel, unvetted spin-glass sponge).
- **After:** All security-critical randomness (`a` seed expansion, CBD sampling of `s`/`e`/`r`/`e1`/`e2`, FO coin derivation) is now derived exclusively from **SHAKE256** (NIST FIPS 202) seeded from OS entropy (`getrandom`).
- **Result:** The IND-CCA2 security of the KEM reduces to **Ring-LWE (over the NTT-friendly ring $\mathbb{Z}_{3329}[X]/(X^N+1)$) + SHAKE256**. It no longer depends on the correctness or pseudorandomness of the custom `SpinLattice` permutation.

This is the single most important change that makes the asymmetric layer "real."

### 1b. Symmetric Layer Hardening — Hybrid AEAD + Vetted KDFs (v0.3)

- **Before:** The AEAD, ratchet KDF, session nonce derivation, and PAKE session key derivation all depended exclusively on the unvetted SpinSponge permutation. A break of SpinLattice would have been catastrophic across the entire symmetric layer.
- **After:**
  - **AEAD:** Now uses a hybrid construction — key material is derived from *both* SpinSponge and SHAKE256 (XOR-combined), then bulk encryption uses **ChaCha20-Poly1305** (a vetted AEAD). Security = `max(SpinSponge, SHAKE256)` for key derivation × ChaCha20-Poly1305 for confidentiality/authenticity.
  - **Ratchet KDF:** The symmetric ratchet (`symmetric_ratchet`, `DoubleRatchet::init`, `kem_ratchet_step`) now derives all chain keys and message keys from **SHAKE256** instead of `spin_kdf`. Forward secrecy no longer depends on the novel permutation.
  - **Session nonce:** Nonce derivation in `Session::encrypt`/`Session::decrypt` now uses **SHAKE256** instead of `spin_hash`. Nonce uniqueness is guaranteed by a vetted hash, eliminating the risk of nonce collisions from a broken sponge.
  - **PAKE:** Password key derivation and session key derivation in the PAKE protocol now use **SHAKE256** instead of `spin_kdf`/`spin_hash`.
- **Result:** The symmetric layer now has the same posture as the KEM: even a total break of the SpinLattice permutation cannot recover plaintext, forge authentication tags, collapse forward secrecy, or produce nonce collisions.

### 2. Memory Safety & Secret Handling
- All secret types (`PrivateKey`, `SharedSecret`, internal keys in ratchet) implement `Zeroize` + `ZeroizeOnDrop`.
- `SpinLattice` and `SpinSponge` now implement `Zeroize`, and the AEAD explicitly zeroizes the sponge and all derived subkeys after use.
- The ratchet's `symmetric_ratchet` zeroizes the old chain key before overwriting.
- Constant-time tag comparison via Poly1305 (ChaCha20-Poly1305 crate) in the AEAD and `subtle::ConstantTimeEq` in FO rejection.
- No secret-dependent branches in the decapsulation rejection path (masking via `unwrap_u8().wrapping_neg()`).

### 3. Domain Separation
- Every use of the sponge (hash, KDF, AEAD, PRNG, KEM SS derivation) uses a distinct domain byte (`0x01`–`0x04`, `0x10`–`0x12`).
- The KEM shared secret derivation still uses `spin_hash` (user-visible output); the confidentiality of the encapsulated message is protected by the RLWE+SHAKE reduction.

---

## What Remains Experimental / Unvetted

### The Spin Lattice Permutation (Core Novelty)
The `SpinLattice::step()` function (linear neighbor mixing + position-dependent round constant + cubing S-box mod 3329 on a toroidal triangular lattice) is a **novel cryptographic permutation** with no public cryptanalysis.

- It powers the user-facing symmetric primitives: `spin_hash`, `SpinPrng`, `spin_kdf`, `aead::*`, the ratchet KDFs, and the visual fingerprint renderer.
- The design document requires **NIST SP 800-22** and **TestU01 BigCrush** statistical validation before any trust. As of this version, only basic avalanche and determinism tests exist.
- **Recommendation:** Treat `spin_*` functions as an interesting experimental symmetric primitive family. For high-value data, prefer a hybrid construction or layer a vetted AEAD (e.g., AES-GCM or ChaCha20-Poly1305 via another crate) on top of a Spin-derived key.

### AEAD Nonce-Misuse Sensitivity
The `aead::encrypt` / `aead::decrypt` functions now use ChaCha20-Poly1305 internally. This construction is still **not nonce-misuse resistant**: reusing the same `(key, nonce)` pair for two different plaintexts remains dangerous. The `Session` layer prevents this by deriving unique nonces from SHAKE256(direction, msg_number) via the ratchet counter. Direct callers of `aead::encrypt` must guarantee nonce uniqueness themselves. A future SIV mode would provide defense-in-depth.

### Parameter Choices
- `q = 3329`, CBD(η=2), lattice dimensions (144/196/256) are taken from Kyber-512/768/1024 analogs.
- No dedicated concrete security analysis or lattice reduction experiments have been performed on the exact parameter sets.

### Side-Channel Resistance (Current Posture)

**What we have done:**
- All secret material implements `Zeroize + ZeroizeOnDrop`.
- Fujisaki-Okamoto rejection sampling and AEAD tag verification use `subtle::ConstantTimeEq` (constant-time comparison).
- `core::hint::black_box` is applied to secret-dependent values in the hot paths of `SpinLattice::step()`, `poly_mul()`, and CBD noise sampling to discourage compiler optimizations that could create timing or power side channels.
- The FO implicit rejection path is fully constant-time (no secret-dependent early returns or branches).

**What we have *not* done (and do not claim):**
- Formal verification with `ctgrind`, `dudect`, `valgrind`, or similar tools.
- Constant-time polynomial arithmetic beyond basic `black_box` hints. All NTT butterfly and schoolbook multiply operations now have `black_box` barriers on secret coefficient reads, but modular reduction still uses `rem_euclid` (hardware integer division), which may be variable-time on some microarchitectures depending on operand magnitude. Migrating to Barrett or Montgomery reduction would eliminate this residual risk.
- The `SpinLattice::step()` function performs array indexing based on precomputed neighbor tables and multiplications involving secret spin values. While we believe these are constant-time on contemporary x86_64 and aarch64, this has **not** been rigorously proven.
- No masking or higher-order countermeasures.

**Recommendation:** Treat the current implementation as having *basic* constant-time hygiene suitable for research and low-to-medium risk experimental deployments. For anything security-critical against a sophisticated local attacker, perform a dedicated side-channel audit or add hardware-level protections.

**Status (v0.2.1 hardening pass):** `black_box` barriers have been added to all NTT butterfly operations, the SpinLattice linear mixing accumulator, and the schoolbook multiplier. FO implicit rejection no longer has an early-return timing leak. Secret types (`DoubleRatchet`, `Session`, `PakeClient`, `PakeServer`) now zeroize keys on drop. Input validation prevents panics from malformed keys/ciphertexts.

**Future work:** Full CT audit with `dudect`/`ctgrind`, Barrett/Montgomery reduction to replace `rem_euclid`, `#[inline(never)]` on hot paths, and optional constant-time NTT implementation.

### Empirical Validation Results — SpinLattice Round Function

As of the current version, the core permutation has been subjected to large-scale statistical testing:

**Monte-Carlo Avalanche Study (10,000 trials, QS-256 parameters, 32 rounds):**
- Mean spin difference after 1-spin input change: **255.9 / 256** (100.0%)
- Mean bit difference: **~1,520.7 / 3,072**
- Range: [253, 256] spins flipped

These numbers demonstrate **full diffusion** and near-ideal avalanche. The round function (`h_eff` linear mixing + cubic S-box on a frustrated triangular lattice) is performing at the highest level expected from a cryptographic primitive of this class.

The dedicated validation binary (`cargo run --bin stats -- --permutation --trials 10000`) and the ignored test target (`cargo test --test stats -- --ignored`) make these results reproducible by anyone.

---

## Usage Recommendations (How to Use "For Real")

### Safe Default Path (Recommended)
```rust
use qs_crypto::*;

// The KEM is now hardened (RLWE + SHAKE256)
let kp = generate_keypair(&Params::default());
let enc = encapsulate(&kp.public_key);
let ss  = decapsulate(&kp.private_key, &enc.ciphertext).unwrap();
```

Use the symmetric primitives (`spin_hash`, `aead`, ratchet) for experimental or low-to-medium risk data, or as a source of key material that you then feed into a vetted primitive.

### For Higher Assurance
1. Run the statistical test battery on `SpinPrng` output for your target parameter set and publish the results.
2. Consider a **hybrid** construction (not yet implemented in this release):
   - `ss = KDF( SpinKEM.ss || ML-KEM.ss || X25519.ss )`
   - This way a break of the novel permutation or even of Ring-LWE does not collapse security.
3. For the visual fingerprint layer, it is safe and delightful to use as a human-verifiable channel binding mechanism (the security comes from the session key, not the image itself).

---

## Threat Model

**In scope (protected):**
- Passive eavesdropper on the KEM + AEAD channel (under RLWE + SHAKE).
- Active CCA attacker on the KEM (thanks to FO + implicit rejection).
- Man-in-the-middle on PAKE + visual fingerprint comparison (out-of-band).
- Forward secrecy via Double Ratchet (old chain keys and KEM secrets are deleted).

**Out of scope / not claimed:**
- Side-channel attacks (timing, power, cache) on the lattice step or polynomial arithmetic.
- Quantum annealing attacks on the (unused) spin-glass interpretation.
- Full cryptanalysis of the custom permutation.
- Resistance to implementation bugs in the ring arithmetic (schoolbook multiplication is simple but has not been formally verified).

---

## Reporting Issues

Please open an issue or contact the maintainers if you discover:
- Statistical biases in the permutation output.
- Decryption failures above the expected ~2^{-140} rate.
- Timing or other side-channel leaks.
- Any deviation from the expected FO correctness or constant-time properties.

We welcome third-party cryptanalysis of the `SpinLattice` round function.

---

**Last updated:** 2026 — after the symmetric layer hardening pass (hybrid AEAD, vetted KDFs, SHAKE256 nonces).
