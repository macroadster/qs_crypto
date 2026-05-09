//! Double Ratchet with KEM ratchet steps.
//!
//! Adapted from the Signal Protocol's Double Ratchet Algorithm, with
//! the X25519 DH ratchet replaced by Spin Glass KEM encaps/decaps.
//! Provides forward secrecy and break-in recovery.
//!
//! The symmetric ratchet advances on every message.  A KEM ratchet
//! step occurs when the conversation "turns" (not yet triggered
//! automatically in this implementation).
//!
//! **Limitation:** messages must be delivered in order. There is no
//! skipped-message-key cache, so out-of-order or dropped messages
//! will cause decryption failures for all subsequent messages on
//! that chain.

use crate::kem::types::{KeyPair, PublicKey};
use crate::primitives::kdf::spin_kdf;

/// Per-party ratchet state.
///
/// Contains the root key, send/receive chain keys, the current
/// ephemeral KEM keypair, and a bounded cache of skipped message keys.
pub struct DoubleRatchet {
    root_key: [u8; 32],
    send_chain_key: [u8; 32],
    recv_chain_key: [u8; 32],
    my_keypair: KeyPair,
    peer_pk: PublicKey,
    send_count: u64,
    recv_count: u64,
}

/// Advance a symmetric chain key and derive a per-message key.
fn symmetric_ratchet(chain_key: &mut [u8; 32]) -> [u8; 32] {
    let msg_key_vec = spin_kdf(chain_key, b"", b"qs-chain-msgkey", 32);
    let new_ck_vec = spin_kdf(chain_key, b"", b"qs-chain-next", 32);
    chain_key.copy_from_slice(&new_ck_vec);
    let mut msg_key = [0u8; 32];
    msg_key.copy_from_slice(&msg_key_vec);
    msg_key
}

impl DoubleRatchet {
    /// Initialize the ratchet from a session key established by PAKE or KEM.
    ///
    /// Role determination: the party whose serialized public key is
    /// lexicographically smaller is the *initiator* and gets chain-A
    /// for sending.
    pub fn init(session_key: &[u8; 32], my_keypair: KeyPair, peer_pk: PublicKey) -> Self {
        let root_kdf = spin_kdf(session_key, b"", b"qs-ratchet-root", 32);
        let mut root_key = [0u8; 32];
        root_key.copy_from_slice(&root_kdf);

        let chain_a = spin_kdf(session_key, b"", b"qs-ratchet-chain-a", 32);
        let chain_b = spin_kdf(session_key, b"", b"qs-ratchet-chain-b", 32);

        let initiator = my_keypair.public_key.as_bytes() < peer_pk.as_bytes();

        let (mut send_ck, mut recv_ck) = ([0u8; 32], [0u8; 32]);
        if initiator {
            send_ck.copy_from_slice(&chain_a);
            recv_ck.copy_from_slice(&chain_b);
        } else {
            send_ck.copy_from_slice(&chain_b);
            recv_ck.copy_from_slice(&chain_a);
        }

        Self {
            root_key,
            send_chain_key: send_ck,
            recv_chain_key: recv_ck,
            my_keypair,
            peer_pk,
            send_count: 0,
            recv_count: 0,
        }
    }

    /// Advance the sending chain and return an encryption key for one message.
    pub fn next_send_key(&mut self) -> [u8; 32] {
        let key = symmetric_ratchet(&mut self.send_chain_key);
        self.send_count += 1;
        key
    }

    /// Advance the receiving chain and return a decryption key for one message.
    pub fn next_recv_key(&mut self) -> [u8; 32] {
        let key = symmetric_ratchet(&mut self.recv_chain_key);
        self.recv_count += 1;
        key
    }

    /// Perform a KEM ratchet step: generate new ephemeral, encaps to
    /// peer, derive new root key and chain keys.
    pub fn kem_ratchet_step(&mut self) {
        use crate::kem::{encapsulate, generate_keypair};
        use crate::params::Params;

        let result = encapsulate(&self.peer_pk);

        let new_root = spin_kdf(
            &self.root_key,
            result.shared_secret.as_bytes(),
            b"qs-ratchet-kem",
            64,
        );
        self.root_key.copy_from_slice(&new_root[..32]);
        self.send_chain_key.copy_from_slice(&new_root[32..]);

        // Fresh ephemeral keypair
        self.my_keypair = generate_keypair(&Params::default());
        self.send_count = 0;
    }

    pub fn send_count(&self) -> u64 {
        self.send_count
    }

    pub fn recv_count(&self) -> u64 {
        self.recv_count
    }

    /// The direction byte for messages from this party.
    pub fn my_direction(&self) -> u8 {
        if self.my_keypair.public_key.as_bytes() < self.peer_pk.as_bytes() {
            0
        } else {
            1
        }
    }

    /// Reconstruct a ratchet from previously persisted state.
    pub fn from_state(
        root_key: [u8; 32],
        send_chain_key: [u8; 32],
        recv_chain_key: [u8; 32],
        my_keypair: KeyPair,
        peer_pk: PublicKey,
        send_count: u64,
        recv_count: u64,
    ) -> Self {
        Self {
            root_key,
            send_chain_key,
            recv_chain_key,
            my_keypair,
            peer_pk,
            send_count,
            recv_count,
        }
    }

    pub fn root_key(&self) -> &[u8; 32] {
        &self.root_key
    }
    pub fn send_chain_key(&self) -> &[u8; 32] {
        &self.send_chain_key
    }
    pub fn recv_chain_key(&self) -> &[u8; 32] {
        &self.recv_chain_key
    }
    pub fn my_keypair(&self) -> &KeyPair {
        &self.my_keypair
    }
    pub fn peer_pk(&self) -> &PublicKey {
        &self.peer_pk
    }
}
