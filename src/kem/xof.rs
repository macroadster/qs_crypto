//! Vetted extendable-output function (XOF) based on SHAKE256.
//!
//! Used exclusively for security-critical randomness inside the KEM
//! (key generation, Fujisaki-Okamoto coin derivation, noise sampling).
//! This ensures that the IND-CCA2 security reduction for the KEM
//! depends only on Ring-LWE + SHAKE256 (a NIST-standard primitive),
//! and does *not* depend on the correctness or strength of the novel
//! SpinSponge / SpinPrng construction.

use crate::core::reduce::barrett_reduce_unsigned;
use core::hint::black_box;
use sha3::digest::{ExtendableOutput, Update};
use sha3::Shake256;
use std::io::Read;

use super::ring::Poly;
use crate::params::Params;

/// A simple wrapper that squeezes bytes from a Shake256 instance.
pub struct ShakePrng {
    reader: sha3::Shake256Reader,
}

impl ShakePrng {
    /// Initialize a Shake256 XOF with the given seed material.
    pub fn new(seed: &[u8]) -> Self {
        let mut hasher = Shake256::default();
        hasher.update(seed);
        Self {
            reader: hasher.finalize_xof(),
        }
    }

    /// Squeeze the next `len` bytes.
    pub fn next_bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        self.reader
            .read_exact(&mut out)
            .expect("SHAKE256 XOF read must not fail");
        out
    }
}

/// Deterministically expand a 32-byte seed into a uniform polynomial
/// over Z_q using SHAKE256.  Used for the public 'a' polynomial in the
/// hardened KEM path.
pub fn expand_a_shake(seed: &[u8; 32], params: &Params) -> Poly {
    let n = params.total_spins;
    let mut xof = ShakePrng::new(seed);
    let raw = xof.next_bytes(n * 2);
    let mut coeffs = Vec::with_capacity(n);
    for chunk in raw.chunks(2) {
        coeffs.push(barrett_reduce_unsigned(
            u16::from_le_bytes([chunk[0], chunk[1]]) as u64,
        ));
    }
    Poly { coeffs, n }
}

/// Sample a polynomial from the Centered Binomial Distribution CBD(η)
/// using a SHAKE256 XOF.  Domain-separated by the provided label.
pub fn sample_cbd_shake(label: &[u8], eta: u8, n: usize) -> Poly {
    let bits_per_sample = 2 * eta as usize;
    let bytes_needed = (bits_per_sample * n).div_ceil(8);

    let mut xof = ShakePrng::new(label);
    let random = xof.next_bytes(bytes_needed);

    let mut coeffs = Vec::with_capacity(n);
    let mut bit_pos = 0usize;

    for _ in 0..n {
        let mut a: u32 = 0;
        let mut b: u32 = 0;
        for _ in 0..eta {
            let byte_idx = bit_pos / 8;
            let bit_idx = bit_pos % 8;
            if byte_idx < random.len() {
                a += black_box(((random[byte_idx] >> bit_idx) & 1) as u32);
            }
            bit_pos += 1;
        }
        for _ in 0..eta {
            let byte_idx = bit_pos / 8;
            let bit_idx = bit_pos % 8;
            if byte_idx < random.len() {
                b += black_box(((random[byte_idx] >> bit_idx) & 1) as u32);
            }
            bit_pos += 1;
        }
        coeffs.push(black_box(barrett_reduce_unsigned(
            (a + crate::params::FIELD_MODULUS as u32 - b) as u64,
        )));
    }
    Poly { coeffs, n }
}

/// Derive the Fujisaki-Okamoto blinding factors (r, e1, e2) from the
/// random coin `m` and the public key hash, using SHAKE256.
/// This is the critical step that must be deterministic for the FO check
/// but must also be unpredictable to an attacker.
pub fn derive_fo_materials(coin: &[u8], pk_hash: &[u8; 32], params: &Params) -> (Poly, Poly, Poly) {
    let n = params.total_spins;
    let eta = params.cbd_eta;

    // Domain separation: 0x10 || coin || pk_hash
    let mut seed = Vec::with_capacity(1 + coin.len() + 32);
    seed.push(0x10);
    seed.extend_from_slice(coin);
    seed.extend_from_slice(pk_hash);

    // We need three independent CBD samples + the message encoding is separate.
    // To keep sampling deterministic and non-overlapping, we use labeled prefixes.
    let mut xof = ShakePrng::new(&seed);

    // First 32 bytes for r seed
    let r_label = xof.next_bytes(32);
    let r = sample_cbd_shake(&r_label, eta, n);

    // Next for e1
    let e1_label = xof.next_bytes(32);
    let e1 = sample_cbd_shake(&e1_label, eta, n);

    // Next for e2
    let e2_label = xof.next_bytes(32);
    let e2 = sample_cbd_shake(&e2_label, eta, n);

    (r, e1, e2)
}
