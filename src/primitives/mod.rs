//! Layer 1 — Symmetric Primitives
//!
//! Hash, PRNG, KDF, and AEAD — all built as modes of the
//! [`SpinSponge`](crate::core::sponge::SpinSponge). This mirrors the
//! Keccak/SHA-3 approach where a single permutation yields an entire
//! symmetric toolkit.

pub mod aead;
pub mod hash;
pub mod kdf;
pub mod prng;
