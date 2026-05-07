//! Double Ratchet with KEM ratchet steps.
//!
//! Adapted from the Signal Protocol's Double Ratchet Algorithm, with
//! the X25519 DH ratchet replaced by Spin Glass KEM encaps/decaps.
//! Provides forward secrecy and break-in recovery.

use crate::kem::types::{KeyPair, PublicKey};

/// Per-party ratchet state.
///
/// Contains the root key, send/receive chain keys, the current
/// ephemeral KEM keypair, and a bounded cache of skipped message keys.
#[allow(dead_code)]
pub struct DoubleRatchet {
    root_key: [u8; 32],
    send_chain_key: [u8; 32],
    recv_chain_key: [u8; 32],
    my_keypair: KeyPair,
    peer_pk: PublicKey,
    send_count: u64,
    recv_count: u64,
}

impl DoubleRatchet {
    /// Initialize the ratchet from a session key established by PAKE or KEM.
    pub fn init(
        _session_key: &[u8; 32],
        _my_keypair: KeyPair,
        _peer_pk: PublicKey,
    ) -> Self {
        todo!("Layer 3: Double Ratchet initialization")
    }

    /// Advance the sending chain and return an encryption key for one message.
    pub fn next_send_key(&mut self) -> [u8; 32] {
        todo!("Layer 3: symmetric ratchet step (send)")
    }

    /// Advance the receiving chain and return a decryption key for one message.
    pub fn next_recv_key(&mut self) -> [u8; 32] {
        todo!("Layer 3: symmetric ratchet step (recv)")
    }

    /// Perform a KEM ratchet step: generate new ephemeral, encaps to
    /// peer, derive new root key and chain keys.
    pub fn kem_ratchet_step(&mut self) {
        todo!("Layer 3: KEM ratchet — fresh ephemeral, encaps, KDF chain")
    }

    pub fn send_count(&self) -> u64 {
        self.send_count
    }

    pub fn recv_count(&self) -> u64 {
        self.recv_count
    }
}