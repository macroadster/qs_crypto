# QS-Crypto Hardening Plan

## Status

- **Tier 1 — COMPLETE** (committed): Hybrid AEAD, vetted nonces/KDFs, zeroization
- **Tier 2 — COMPLETE** (committed): Standard sponge squeeze, SIV mode, auth tag rationale (Option B), versioned domain separators
- **Tier 3 — COMPLETE** (committed): Differential analysis, KAT vectors, NIST/BigCrush infrastructure
- **Tier 4 — COMPLETE** (committed): Barrett reduction, dudect harnesses, `#[inline(never)]`, proptest, cargo-fuzz
- **Tier 5 — TODO** (documented below)

---

## Tier 2 — Sponge Construction Correctness

These fix the sponge to match its formal security claims. No new dependencies needed.

### 2.1 Standard Sponge Squeeze

**File:** `src/core/sponge.rs` (the `squeeze()` method)

**Problem:** The current squeeze applies a SplitMix64-style whitening mixer over
3 spin values at offsets `(i, i+7, i+19)`. This is non-standard — the generic
sponge indifferentiability proof (Bertoni et al.) assumes raw rate extraction.
The whitening breaks the ability to cite that proof framework.

**Fix:** Add a `squeeze_raw()` method that reads the rate region directly as
LE-encoded u16 bytes, with a permutation between every rate-sized block
(standard sponge squeeze). Use `squeeze_raw()` in the AEAD's
`derive_spin_subkey()` and in `spin_kdf`. Keep the whitened `squeeze()` for
`SpinPrng` output where uniformity matters more than provability.

### 2.2 Nonce-Misuse Resistance (SIV Mode)

**Files:** `src/primitives/aead.rs`

**Problem:** The AEAD is not nonce-misuse resistant. Reusing `(key, nonce)`
degrades to plaintext XOR leakage. The Session layer prevents this via ratchet
counters, but there is no defense-in-depth.

**Fix:** Add an SIV wrapper: derive a synthetic IV from
`SHAKE256(key ‖ aad ‖ plaintext)`, use it as the ChaCha20-Poly1305 nonce.
Nonce reuse then degrades to deterministic encryption (leaks equality only)
rather than XOR-of-plaintexts. Expose as `aead::encrypt_siv` / `decrypt_siv`,
and switch `Session` to use it.

### 2.3 Larger or Dual Authentication Tag

**File:** `src/primitives/aead.rs`

**Problem:** The 128-bit Poly1305 tag is standard, but an unproven sponge
contributing to key derivation reduces the safety margin. If the sponge has
subtle biases that weaken the combined key, 128 bits may not be enough.

**Fix (choose one):**
- Option A: Append an HMAC-SHA256 tag (32 bytes) alongside the Poly1305 tag.
  Verify both on decrypt. Total overhead: +32 bytes per message.
- Option B: Accept 128-bit Poly1305 is sufficient given the SHAKE256 fallback
  in the hybrid key derivation. Document the rationale and close this item.

Recommendation: Option B (the hybrid key derivation already provides the safety
net; the Poly1305 tag is proven secure given a good key).

### 2.4 Version the Domain Separator

**Files:** `src/primitives/aead.rs`, `src/primitives/hash.rs`,
`src/primitives/kdf.rs`, `src/primitives/prng.rs`

**Problem:** Domain separator bytes (`0x01`–`0x04`) don't encode the algorithm
version or parameter set. A future parameter change could produce colliding
sponge states.

**Fix:** Change domain separators to multi-byte:
`[version_byte, primitive_id, security_level_byte]`. For v0.3:
`[0x01, 0x04, 0x03]` = version 1, AEAD, QS-256. This is a **breaking change**
to all primitive outputs. Coordinate with KAT vector regeneration (Tier 3.4).

---

## Tier 3 — Validate the Permutation

These are the "prove it works" tasks. They don't change code — they generate
evidence that reviewers and cryptanalysts need.

### 3.1 NIST SP 800-22 Statistical Test Suite

**Prereqs:** Install NIST STS (C source from NIST website) or use `dieharder`
(available via Homebrew: `brew install dieharder`).

**Steps:**
1. Generate streams: `cargo run --release --bin stats -- --megabytes 100 --streams 5`
2. Run dieharder: `dieharder -a -g 201 -f stats_out/spinprng_qs256_stream000.bin`
3. Or run NIST STS: `./assess 1000000` pointing at the binary files.
4. Capture all results into `benches/reports/v0.3/nist_sp800_22.md`.
5. Flag any p-values below 0.01 for investigation.

### 3.2 TestU01 BigCrush

**Prereqs:** Install TestU01 (C library, build from source or use a package
manager). Write a small C wrapper that reads from a SpinPrng-generated binary
file and feeds it to `bbattery_BigCrush`.

**Steps:**
1. Generate a large stream (≥1 GiB) for BigCrush.
2. Run BigCrush (takes ~4 hours on modern hardware).
3. Capture results into `benches/reports/v0.3/testu01_bigcrush.md`.
4. BigCrush runs 160 tests — document pass/fail for each.

### 3.3 Differential Cryptanalysis of the Round Function

**File:** Extend `src/bin/stats.rs` with a `--differential` mode.

**Steps:**
1. For each input differential weight (1-spin, 2-spin, 3-spin):
   - Run N trials, measure output differential weight distribution after R rounds.
   - Compute maximum differential probability `max_r DP(r)`.
2. Verify DP decays exponentially with round count.
3. Report the number of rounds where DP drops below `2^{-128}`.
4. Document in `benches/reports/v0.3/differential.md`.

### 3.4 Known-Answer Test (KAT) Vectors

**Files to create:**
- `tests/kat_vectors.json` — structured test vectors
- `tests/kat.rs` — test that loads and verifies all vectors
- `src/bin/gen_kat.rs` — binary that generates the vectors

**Vectors to include:**

```
spin_hash:
  - 5+ inputs (empty, 1-byte, "abc", 256-byte, 1024-byte)
  - Record: { input_hex, output_hex }

spin_kdf:
  - 5+ cases (varying key, salt, info, output length)
  - Record: { key_hex, salt_hex, info_ascii, length, output_hex }

aead (hybrid):
  - 5+ cases (empty pt, 1-byte, multi-block, empty aad, large aad)
  - Record: { key_hex, nonce_hex, aad_hex, plaintext_hex, ciphertext_hex, tag_hex }

kem (all security levels):
  - 3 cases per level (QS128, QS192, QS256)
  - Record: { level, pk_hex, sk_hex, ct_hex, ss_hex }
  - Verification: decaps(sk, ct) == ss

sponge:
  - 3+ cases: absorb known data, squeeze known length
  - Record: { input_hex, squeeze_len, output_hex }
```

The KAT test (`tests/kat.rs`) loads the JSON and asserts each vector matches.
Any code change that alters primitive output will cause a KAT failure, providing
automatic regression detection.

---

## Tier 4 — Side-Channel Hardening

### 4.1 Barrett/Montgomery Reduction

**Files:** `src/core/lattice.rs`, `src/kem/ring.rs`, `src/kem/ntt.rs`

Replace all `% q` / `rem_euclid` operations with constant-time Barrett or
Montgomery reduction. Hardware integer division may be variable-time on some
microarchitectures depending on operand magnitude.

Reference: Kyber reference implementation's `barrett_reduce` and
`montgomery_reduce` in `reduce.c`.

### 4.2 Formal Constant-Time Audit (dudect/ctgrind)

**Steps:**
1. Write `dudect` test harnesses for: `SpinLattice::step()`, `aead::encrypt`,
   `aead::decrypt`, the FO rejection path in `decaps.rs`.
2. Run with `cargo dudect` or a standalone C harness.
3. Report t-statistic and pass/fail for each function.
4. Document in `SECURITY.md` under a new "Constant-Time Audit Results" section.

### 4.3 `#[inline(never)]` on Hot Paths

**Files:** `src/core/lattice.rs` (`step()`), `src/primitives/aead.rs`
(`derive_spin_subkey`), `src/kem/decaps.rs` (FO rejection).

Add `#[inline(never)]` to prevent the compiler from inlining secret-dependent
code into larger functions where it could be optimized differently.

### 4.4 Property-Based Tests (proptest)

**File to create:** `tests/proptest_crypto.rs`

Add `proptest` dependency. Write property tests for:
- `aead::decrypt(key, nonce, aad, aead::encrypt(key, nonce, aad, pt)) == pt`
  for arbitrary (key, nonce, aad, pt).
- `decaps(sk, encaps(pk).ct) == encaps(pk).ss` for arbitrary keypairs.
- `Session` encrypt/decrypt roundtrip for arbitrary plaintext sequences.
- Tampered ciphertext always fails authentication.

### 4.5 Fuzzing Harness (cargo-fuzz)

**Directory to create:** `fuzz/`

Write fuzz targets for all deserialization paths:
- `Ciphertext::from_bytes(arbitrary)`
- `PublicKey::from_bytes(arbitrary)`
- `PrivateKey::from_bytes(arbitrary)`
- `Session::restore(arbitrary)`
- `RegistrationRecord::from_bytes(arbitrary)`
- `aead::decrypt(arbitrary_key, arbitrary_nonce, arbitrary_aad, arbitrary_ct, arbitrary_tag)`

Goal: no panics, no UB, all malformed inputs produce `Err`.

---

## Tier 5 — Complete the Hybrid Story + Publication

### 5.1 3-Way Hybrid KEM (Spin + X25519 + ML-KEM-768)

**Files:** `src/kem/hybrid.rs`

The `ml-kem` crate is already a `Cargo.toml` dependency. The `full_hybrid_*`
API stubs exist. Wire in actual ML-KEM-768 `encapsulate`/`decapsulate` calls
so the 3-way combiner is functional end-to-end:

```
combined_ss = SHAKE256(spin_ss ‖ x25519_ss ‖ mlkem_ss)
combined_ct = spin_ct ‖ x25519_ct ‖ mlkem_ct
```

### 5.2 NTT for Non-Power-of-2 Dimensions

**Files:** `src/kem/ntt.rs`, `src/kem/ring.rs`

QS128 (N=144) and QS192 (N=196) still use schoolbook polynomial multiplication.
Either:
- Option A: Add NTT support for these dimensions (requires finding suitable
  NTT-friendly moduli or using mixed-radix FFT).
- Option B: Migrate those security levels to power-of-2 ring dimensions
  (N=128 and N=256), adjusting parameters accordingly.

Recommendation: Option B is simpler and aligns with standard lattice crypto
practice.

### 5.3 Formal Verification (ProVerif/Tamarin)

Model the PAKE + Double Ratchet composition in ProVerif or Tamarin Prover.
Verify:
- Mutual authentication (PAKE).
- Session key secrecy.
- Forward secrecy (ratchet).
- Break-in recovery.

Low priority but high value for the publication narrative.

### 5.4 Specification Document + SG-LWE Paper

Write a formal specification document (separate from DESIGN_PROPOSAL.md) that
precisely defines all algorithms with pseudocode, test vectors, and security
claims. Publish the SG-LWE hardness assumption as a standalone paper for
community review.

### 5.5 CI Pipeline

Set up GitHub Actions:
- `cargo test` (all tests)
- `cargo clippy --all-targets -- -D warnings`
- `cargo fmt --check`
- `cargo miri test` (UB detection, requires nightly)
- KAT vector verification
- Optional: `cargo bench` with regression threshold alerts
