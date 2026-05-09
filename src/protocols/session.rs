//! Encrypted session with automatic ratcheting.
//!
//! The [`Session`] type composes the Double Ratchet with SpinAEAD
//! to provide a high-level encrypt/decrypt interface. Each message
//! uses a unique key derived from the ratchet; old keys are deleted
//! immediately after use.

use zeroize::Zeroize;

use crate::error::Error;
use crate::kem::types::{KeyPair, PrivateKey, PublicKey};
use crate::primitives::aead;
use crate::primitives::hash::spin_hash;
use crate::protocols::ratchet::DoubleRatchet;
use crate::visual::fingerprint::{self, IdentityPhoto};

fn write_len_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
    buf.extend_from_slice(data);
}

fn read_len_prefixed(buf: &[u8], offset: &mut usize) -> Result<Vec<u8>, Error> {
    if *offset + 4 > buf.len() {
        return Err(Error::Deserialization("truncated length".into()));
    }
    let len = u32::from_le_bytes(buf[*offset..*offset + 4].try_into().unwrap()) as usize;
    *offset += 4;
    if *offset + len > buf.len() {
        return Err(Error::Deserialization("truncated data".into()));
    }
    let data = buf[*offset..*offset + len].to_vec();
    *offset += len;
    Ok(data)
}

/// Wire format: `[direction(1) | msg_number(8) | ciphertext(var) | tag(16)]`
const HEADER_LEN: usize = 1 + 8; // direction + msg_number
const TAG_LEN: usize = 16;

/// An encrypted session between two parties.
///
/// Provides forward-secret, authenticated encryption. Each call to
/// [`encrypt`](Session::encrypt) or [`decrypt`](Session::decrypt)
/// advances the internal ratchet.
pub struct Session {
    ratchet: DoubleRatchet,
    session_key: [u8; 32],
    my_photo: Option<IdentityPhoto>,
    peer_photo: Option<IdentityPhoto>,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.session_key.zeroize();
    }
}

impl Session {
    /// Create a new session from a completed key exchange.
    pub fn new(my_keypair: KeyPair, peer_pk: PublicKey, session_key: &[u8; 32]) -> Self {
        let ratchet = DoubleRatchet::init(session_key, my_keypair, peer_pk);
        Self {
            ratchet,
            session_key: *session_key,
            my_photo: None,
            peer_photo: None,
        }
    }

    /// Attach identity photos for identity-bound fingerprinting.
    pub fn set_identity_photos(&mut self, my_photo: IdentityPhoto, peer_photo: IdentityPhoto) {
        self.my_photo = Some(my_photo);
        self.peer_photo = Some(peer_photo);
    }

    /// Encrypt `plaintext` and advance the sending ratchet.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let msg_key = self.ratchet.next_send_key();
        let direction = self.ratchet.my_direction();
        let msg_number = self.ratchet.send_count() - 1; // already incremented

        // Derive nonce from direction + message number
        let mut nonce_input = Vec::new();
        nonce_input.push(direction);
        nonce_input.extend_from_slice(&msg_number.to_le_bytes());
        let nonce_hash = spin_hash(&nonce_input);
        let nonce: [u8; 16] = nonce_hash[..16].try_into().unwrap();

        // AAD = header bytes (direction + msg_number)
        let mut header = Vec::with_capacity(HEADER_LEN);
        header.push(direction);
        header.extend_from_slice(&msg_number.to_le_bytes());

        let ct = aead::encrypt(&msg_key, &nonce, &header, plaintext);

        // Wire format: header ‖ ciphertext ‖ tag
        let mut message = header;
        message.extend_from_slice(&ct.ciphertext);
        message.extend_from_slice(&ct.tag);
        message
    }

    /// Decrypt an incoming message and advance the receiving ratchet.
    pub fn decrypt(&mut self, message: &[u8]) -> crate::Result<Vec<u8>> {
        if message.len() < HEADER_LEN + TAG_LEN {
            return Err(Error::AuthenticationFailed);
        }

        let header = &message[..HEADER_LEN];
        let direction = header[0];
        let msg_number = u64::from_le_bytes(header[1..9].try_into().unwrap());

        let body = &message[HEADER_LEN..];
        let ct_len = body.len() - TAG_LEN;
        let ciphertext = &body[..ct_len];
        let tag: [u8; 16] = body[ct_len..].try_into().unwrap();

        let msg_key = self.ratchet.next_recv_key();

        // Derive the same nonce
        let mut nonce_input = Vec::new();
        nonce_input.push(direction);
        nonce_input.extend_from_slice(&msg_number.to_le_bytes());
        let nonce_hash = spin_hash(&nonce_input);
        let nonce: [u8; 16] = nonce_hash[..16].try_into().unwrap();

        aead::decrypt(&msg_key, &nonce, header, ciphertext, &tag)
    }

    /// Serialize session state for persistence.
    ///
    /// **The output is sensitive** — it contains ratchet keys.
    pub fn save(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(0x01); // version

        buf.extend_from_slice(&self.session_key);
        buf.extend_from_slice(self.ratchet.root_key());
        buf.extend_from_slice(self.ratchet.send_chain_key());
        buf.extend_from_slice(self.ratchet.recv_chain_key());
        buf.extend_from_slice(&self.ratchet.send_count().to_le_bytes());
        buf.extend_from_slice(&self.ratchet.recv_count().to_le_bytes());

        write_len_prefixed(&mut buf, self.ratchet.my_keypair().public_key.as_bytes());
        write_len_prefixed(&mut buf, self.ratchet.my_keypair().private_key.as_bytes());
        write_len_prefixed(&mut buf, self.ratchet.peer_pk().as_bytes());

        match (&self.my_photo, &self.peer_photo) {
            (Some(my), Some(peer)) => {
                buf.push(0x01);
                write_len_prefixed(&mut buf, my.as_bytes());
                write_len_prefixed(&mut buf, peer.as_bytes());
            }
            _ => buf.push(0x00),
        }
        buf
    }

    /// Restore a session from serialized state.
    pub fn restore(data: &[u8]) -> Result<Self, Error> {
        let mut off = 0usize;
        if data.is_empty() || data[0] != 0x01 {
            return Err(Error::Session("unsupported session format".into()));
        }
        off += 1;

        let need = 32 * 4 + 8 * 2; // session_key + 3 ratchet keys + 2 counters
        if data.len() < off + need {
            return Err(Error::Session("truncated session data".into()));
        }

        let session_key: [u8; 32] = data[off..off + 32].try_into().unwrap();
        off += 32;
        let root_key: [u8; 32] = data[off..off + 32].try_into().unwrap();
        off += 32;
        let send_chain_key: [u8; 32] = data[off..off + 32].try_into().unwrap();
        off += 32;
        let recv_chain_key: [u8; 32] = data[off..off + 32].try_into().unwrap();
        off += 32;
        let send_count = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
        off += 8;
        let recv_count = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
        off += 8;

        let my_pk_bytes = read_len_prefixed(data, &mut off)?;
        let my_sk_bytes = read_len_prefixed(data, &mut off)?;
        let peer_pk_bytes = read_len_prefixed(data, &mut off)?;

        let my_keypair = KeyPair {
            public_key: PublicKey::from_bytes(&my_pk_bytes)?,
            private_key: PrivateKey::from_bytes(&my_sk_bytes)?,
        };
        let peer_pk = PublicKey::from_bytes(&peer_pk_bytes)?;

        let ratchet = DoubleRatchet::from_state(
            root_key,
            send_chain_key,
            recv_chain_key,
            my_keypair,
            peer_pk,
            send_count,
            recv_count,
        );

        if off >= data.len() {
            return Err(Error::Session("truncated session data".into()));
        }
        let has_photos = data[off];
        off += 1;

        let (my_photo, peer_photo) = if has_photos == 0x01 {
            let my_bytes = read_len_prefixed(data, &mut off)?;
            let peer_bytes = read_len_prefixed(data, &mut off)?;
            (
                Some(IdentityPhoto::new(my_bytes)),
                Some(IdentityPhoto::new(peer_bytes)),
            )
        } else {
            (None, None)
        };

        Ok(Self {
            ratchet,
            session_key,
            my_photo,
            peer_photo,
        })
    }

    // ── Visual fingerprints ────────────────────────────────────────

    /// Plain visual fingerprint — session key only.
    pub fn visual_fingerprint(&self, width: u32, height: u32) -> Vec<u8> {
        fingerprint::visual_fingerprint(&self.session_key, width, height)
    }

    /// Identity-bound visual fingerprint.
    pub fn identity_fingerprint(&self, width: u32, height: u32) -> crate::Result<Vec<u8>> {
        let my_photo = self.my_photo.as_ref().ok_or_else(|| {
            Error::Session("identity photos not set — call set_identity_photos first".into())
        })?;
        let peer_photo = self.peer_photo.as_ref().ok_or_else(|| {
            Error::Session("identity photos not set — call set_identity_photos first".into())
        })?;
        Ok(fingerprint::identity_fingerprint(
            &self.session_key,
            my_photo,
            peer_photo,
            width,
            height,
        ))
    }
}
