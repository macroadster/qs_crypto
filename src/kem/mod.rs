//! Layer 2 — Spin Glass Key Encapsulation Mechanism (KEM)
//!
//! Adapts the LWE framework with a structured coupling matrix drawn
//! from a frustrated spin glass ensemble. Security rests on the
//! SG-LWE hardness assumption. A Fujisaki-Okamoto transform provides
//! CCA2 security with implicit rejection.

pub mod types;

mod decaps;
mod encaps;
mod keygen;
pub(crate) mod ring;

pub use decaps::decapsulate;
pub use encaps::encapsulate;
pub use keygen::generate_keypair;
pub use types::*;
