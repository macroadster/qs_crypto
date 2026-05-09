//! Layer 2 — Ring-LWE Key Encapsulation Mechanism (hardened)
//!
//! Standard Ring-LWE KEM over Z_3329[X]/(X^N+1) with schoolbook
//! multiplication and Centered Binomial noise. All internal randomness
//! is derived from SHAKE256, so the IND-CCA2 security reduction depends
//! only on Ring-LWE + SHAKE256 (not on the novel SpinSponge).
//! Fujisaki-Okamoto transform provides CCA2 security with implicit rejection.

pub mod hybrid;
pub mod types;

mod decaps;
mod encaps;
mod keygen;
pub(crate) mod ring;
mod xof;

mod ntt;

pub use decaps::decapsulate;
pub use encaps::encapsulate;
pub use keygen::generate_keypair;
pub use ring::{poly_mul, schoolbook_poly_mul, Poly};
pub use types::*;
