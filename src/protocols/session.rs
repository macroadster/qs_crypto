//! Encrypted session with automatic ratcheting.
//!
//! The [`Session`] type composes the Double Ratchet with SpinAEAD
//! to provide a high-level encrypt/decrypt interface. Each message
//! uses a unique key derived from the ratchet; old keys are deleted
//! immediately after use.

use crate::error::Error;
use crate::kem::types::{KeyPair, PublicKey};
use crate::visual::fingerprint::IdentityPhoto;

/// An encrypted session between two parties.
///
/// Provides forward-secret, authenticated encryption. Each call to
/// [`encrypt`](Session::encrypt) or [`decrypt`](Session::decrypt)
/// advances the internal ratchet.
///
/// Optionally holds identity photos for both parties so that
/// identity-bound visual fingerprints can be generated at any time.
pub struct Session {
    _my_keypair: KeyPair,
    _peer_pk: PublicKey,
    _session_key: [u8; 32],
    my_photo: Option<IdentityPhoto>,
    peer_photo: Option<IdentityPhoto>,
}

impl Session {
    /// Create a new session from a completed key exchange.
    ///
    /// `session_key` is typically the output of a PAKE or raw KEM handshake.
    pub fn new(
        my_keypair: KeyPair,
        peer_pk: PublicKey,
        session_key: &[u8; 32],
    ) -> Self {
        Self {
            _my_keypair: my_keypair,
            _peer_pk: peer_pk,
            _session_key: *session_key,
            my_photo: None,
            peer_photo: None,
        }
    }

    /// Attach identity photos for identity-bound fingerprinting.
    ///
    /// Both photos must be byte-identical to the copies held by the
    /// peer.  Applications should exchange
    /// [`photo_hash`](crate::visual::fingerprint::photo_hash) values
    /// during registration and verify them before calling this.
    pub fn set_identity_photos(
        &mut self,
        my_photo: IdentityPhoto,
        peer_photo: IdentityPhoto,
    ) {
        self.my_photo = Some(my_photo);
        self.peer_photo = Some(peer_photo);
    }

    /// Encrypt `plaintext` and advance the sending ratchet.
    ///
    /// Returns a self-contained message (header + ciphertext + tag)
    /// that the peer can decrypt.
    pub fn encrypt(&mut self, _plaintext: &[u8]) -> Vec<u8> {
        todo!("Layer 3: Session encrypt — ratchet step, AEAD encrypt, build message")
    }

    /// Decrypt an incoming message and advance the receiving ratchet.
    ///
    /// Returns `Error::AuthenticationFailed` if the tag does not verify.
    pub fn decrypt(&mut self, _message: &[u8]) -> crate::Result<Vec<u8>> {
        todo!("Layer 3: Session decrypt — parse header, ratchet, AEAD decrypt")
    }

    /// Serialize session state for persistence.
    ///
    /// **The output is sensitive** — it contains ratchet keys.
    /// Encrypt it at rest.
    pub fn save(&self) -> Vec<u8> {
        todo!("Layer 3: Session serialization")
    }

    /// Restore a session from serialized state.
    pub fn restore(_data: &[u8]) -> Result<Self, Error> {
        todo!("Layer 3: Session deserialization")
    }

    // ── Visual fingerprints ────────────────────────────────────────

    /// Plain visual fingerprint — session key only.
    ///
    /// Returns raw RGBA pixel data (`width × height × 4` bytes).
    pub fn visual_fingerprint(&self, _width: u32, _height: u32) -> Vec<u8> {
        todo!("Visual: plain fingerprint from session key")
    }

    /// Identity-bound visual fingerprint.
    ///
    /// The peer's photo modulates the lattice couplings so their face
    /// is recognisable through the spin-domain colouring.  The session
    /// key determines the colours; the photo determines the domain
    /// topology.
    ///
    /// Requires [`set_identity_photos`](Session::set_identity_photos)
    /// to have been called first.
    ///
    /// Returns raw RGBA pixel data (`width × height × 4` bytes).
    pub fn identity_fingerprint(
        &self,
        width: u32,
        height: u32,
    ) -> crate::Result<Vec<u8>> {
        let my_photo = self.my_photo.as_ref().ok_or_else(|| {
            Error::Session("identity photos not set — call set_identity_photos first".into())
        })?;
        let peer_photo = self.peer_photo.as_ref().ok_or_else(|| {
            Error::Session("identity photos not set — call set_identity_photos first".into())
        })?;
        let _ = (my_photo, peer_photo, width, height);
        todo!(
            "Visual: KDF(session_key, hash(my) ‖ hash(peer)) → \
             seed lattice, bias couplings from peer photo, anneal, render"
        )
    }
}