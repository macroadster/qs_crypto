//! # QS-Crypto
//!
//! Cryptographic library derived from spin glass quantum simulation.
//!
//! Two parties establish a private channel using asymmetric keys that
//! emerge from a single event — the construction of a planted spin
//! glass lattice. The coupling matrix is the **public key**; the
//! ground state is the **private key**. Recovering one from the other
//! requires solving an NP-hard optimisation problem (SG-LWE).
//!
//! ## Architecture
//!
//! | Layer | Module | Purpose |
//! |-------|--------|---------|
//! | 0 | [`core`] | Spin lattice engine + sponge construction |
//! | 1 | [`primitives`] | Hash, PRNG, KDF, AEAD (sponge modes) |
//! | 2 | [`kem`] | Key Encapsulation Mechanism (SG-LWE + FO) |
//! | 3 | [`protocols`] | PAKE, Double Ratchet, Session |
//! | — | [`visual`] | Fingerprint renderer for out-of-band auth |
//!
//! Each layer depends only on the layers below it.

pub mod core;
pub mod error;
pub mod kem;
pub mod params;
pub mod primitives;
pub mod protocols;
pub mod visual;

// ── Public re-exports ──────────────────────────────────────────────

pub use error::Error;
pub type Result<T> = std::result::Result<T, Error>;

// Layer 0
pub use core::lattice::SpinLattice;
pub use core::sponge::SpinSponge;

// Layer 1
pub use primitives::aead;
pub use primitives::hash::spin_hash;
pub use primitives::kdf::spin_kdf;
pub use primitives::prng::SpinPrng;

// Layer 2
pub use kem::types::{Ciphertext, EncapsulationResult, KeyPair, PrivateKey, PublicKey, SharedSecret};
pub use kem::{decapsulate, encapsulate, generate_keypair};

// Layer 3
pub use protocols::pake::{pake_register, PakeClient, PakeServer, RegistrationRecord};
pub use protocols::session::Session;

// Visual
pub use visual::fingerprint::{identity_fingerprint, photo_hash, visual_fingerprint, IdentityPhoto};

// Params
pub use params::{Params, SecurityLevel, FIELD_MODULUS};