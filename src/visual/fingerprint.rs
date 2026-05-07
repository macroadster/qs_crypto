//! Visual fingerprint renderer.
//!
//! Two flavours:
//!
//! - **Plain fingerprint** — session key alone drives the lattice.
//!   Produces an abstract pattern for comparison.
//! - **Identity-bound fingerprint** — each party's photo modulates the
//!   lattice couplings so the peer's face is recognisable *through* the
//!   spin-domain colouring.  The session key determines the colours;
//!   the photo determines the domain topology.  Change either input and
//!   the image is unrecognisable.
//!
//! ## Identity-bound generation
//!
//! ```text
//! IdentityFingerprint(session_key, my_photo, peer_photo, size) → RGBA
//!
//!   1. fp_seed = SpinKDF(
//!          key  = session_key,
//!          salt = SpinHash(my_photo) ‖ SpinHash(peer_photo),
//!          info = "qs-identity-fingerprint",
//!      )
//!
//!   2. photo_gray = grayscale(peer_photo, resized to lattice dims)
//!      For each lattice site i:
//!          coupling_bias[i] = photo_gray[i]
//!
//!   3. display = SpinLattice::new(size)
//!      display.seed_from_bytes(fp_seed)
//!      Apply coupling_bias  → photo shapes the energy landscape
//!
//!   4. Anneal → ground state reflects session key + photo structure
//!
//!   5. Map spins → HSV → RGBA
//! ```

/// Peer identity photo used for identity-bound fingerprints.
///
/// The raw bytes are hashed — only the hash enters the KDF, so the
/// exact encoding (PNG, JPEG, etc.) must be identical on both sides.
/// Applications should store a canonical copy of each peer's photo
/// and transmit its [`SpinHash`](crate::primitives::hash::spin_hash)
/// during registration so both parties can verify they hold the same
/// image before generating the fingerprint.
#[derive(Debug, Clone)]
pub struct IdentityPhoto {
    data: Vec<u8>,
}

impl IdentityPhoto {
    /// Wrap raw image bytes (PNG, JPEG, …).
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// The raw image bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

/// Plain visual fingerprint — session key only.
///
/// Returns raw RGBA pixel data (`width × height × 4` bytes).
/// Two parties who derived the same session key will produce
/// identical images.
pub fn visual_fingerprint(
    _session_key: &[u8; 32],
    _width: u32,
    _height: u32,
) -> Vec<u8> {
    todo!("Visual: seed display lattice, anneal, map spins → HSV → RGBA pixels")
}

/// Identity-bound visual fingerprint.
///
/// The peer's photo modulates the lattice coupling structure so their
/// face/image is recognisable through the spin-domain colouring.
/// The session key determines the colours; the photo determines the
/// domain topology.
///
/// Both parties must supply the photos in the same canonical byte
/// representation.  The `my_photo` / `peer_photo` distinction ensures
/// each side sees the *other* party's face, while both derive the
/// same fingerprint seed (the hashes are combined in sorted order
/// internally so the result is symmetric).
///
/// Returns raw RGBA pixel data (`width × height × 4` bytes).
pub fn identity_fingerprint(
    _session_key: &[u8; 32],
    _my_photo: &IdentityPhoto,
    _peer_photo: &IdentityPhoto,
    _width: u32,
    _height: u32,
) -> Vec<u8> {
    todo!(
        "Visual: KDF(session_key, hash(photo_a) ‖ hash(photo_b)) → \
         seed lattice, bias couplings from peer photo grayscale, anneal, render"
    )
}

/// Compute the photo hash that should be exchanged during registration
/// so both parties can verify they hold identical copies of the same
/// image before generating an identity-bound fingerprint.
pub fn photo_hash(_photo: &IdentityPhoto) -> [u8; 32] {
    todo!("Visual: SpinHash(photo bytes)")
}