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
//!
//! ## Quick Start
//!
//! ### KEM — Key Encapsulation / Decapsulation
//!
//! ```
//! use qs_crypto::*;
//!
//! let keypair = generate_keypair(&Params::default());
//! let result  = encapsulate(&keypair.public_key);
//! let shared  = decapsulate(&keypair.private_key, &result.ciphertext).unwrap();
//! assert_eq!(result.shared_secret.as_bytes(), shared.as_bytes());
//! ```
//!
//! ### Encrypted Session (forward secrecy)
//!
//! ```
//! use qs_crypto::*;
//!
//! let params = Params::default();
//! let alice_kp = generate_keypair(&params);
//! let bob_kp   = generate_keypair(&params);
//!
//! let alice_pk = alice_kp.public_key.clone();
//! let bob_pk   = bob_kp.public_key.clone();
//!
//! let session_key = [0x42u8; 32];
//! let mut alice = Session::new(alice_kp, bob_pk, &session_key);
//! let mut bob   = Session::new(bob_kp, alice_pk, &session_key);
//!
//! let ct = alice.encrypt(b"Hello Bob");
//! let pt = bob.decrypt(&ct).unwrap();
//! assert_eq!(&pt[..], b"Hello Bob");
//! ```
//!
//! ### PAKE — Password-Authenticated Key Exchange
//!
//! ```
//! use qs_crypto::*;
//!
//! let keypair  = generate_keypair(&Params::default());
//! let record   = pake_register("password", &keypair);
//!
//! let mut client = PakeClient::new("password");
//! let mut server = PakeServer::new(record);
//!
//! let msg1       = client.start();
//! let msg2       = server.respond(&msg1).unwrap();
//! let client_key = client.finalize(&msg2).unwrap();
//! let server_key = server.finalize().unwrap();
//! assert_eq!(client_key, server_key);
//! ```
//!
//! ### Symmetric Primitives
//!
//! ```
//! use qs_crypto::*;
//!
//! // Hash
//! let digest = spin_hash(b"hello world");
//! assert_eq!(digest.len(), 32);
//!
//! // KDF
//! let derived = spin_kdf(b"key", b"salt", b"info", 64);
//! assert_eq!(derived.len(), 64);
//!
//! // AEAD
//! let key   = [0x42u8; 32];
//! let nonce = [0x01u8; 16];
//! let ct = aead::encrypt(&key, &nonce, b"aad", b"secret");
//! let pt = aead::decrypt(&key, &nonce, b"aad", &ct.ciphertext, &ct.tag).unwrap();
//! assert_eq!(&pt[..], b"secret");
//! ```

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
pub use kem::types::{
    Ciphertext, EncapsulationResult, KeyPair, PrivateKey, PublicKey, SharedSecret,
};
pub use kem::{decapsulate, encapsulate, generate_keypair};

// Layer 3
pub use protocols::pake::{pake_register, PakeClient, PakeServer, RegistrationRecord};
pub use protocols::session::Session;

// Visual
pub use visual::fingerprint::{
    identity_fingerprint, photo_hash, visual_fingerprint, IdentityPhoto,
};

// Params
pub use params::{Params, SecurityLevel, FIELD_MODULUS};
