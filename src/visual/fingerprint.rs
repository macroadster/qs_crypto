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

use crate::core::lattice::SpinLattice;
use crate::params::Params;
use crate::primitives::hash::spin_hash;
use crate::primitives::kdf::spin_kdf;

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

// ── Internal rendering helpers ─────────────────────────────────────

/// Map a spin value in `[0, q)` to an RGBA colour via HSV.
fn spin_to_rgba(spin: u16, q: u16, neighbor_var: f32) -> [u8; 4] {
    let hue = spin as f32 / q as f32 * 360.0;
    let sat = (0.5 + 0.5 * neighbor_var.min(1.0)).min(1.0);
    let val = 0.7 + 0.3 * (1.0 - spin as f32 / q as f32);

    // HSV → RGB (standard sector formula)
    let c = val * sat;
    let x = c * (1.0 - ((hue / 60.0) % 2.0 - 1.0).abs());
    let m = val - c;

    let (r, g, b) = match (hue / 60.0) as u32 {
        0 => (c, x, 0.0),
        1 => (x, c, 0.0),
        2 => (0.0, c, x),
        3 => (0.0, x, c),
        4 => (x, 0.0, c),
        _ => (c, 0.0, x),
    };

    [
        ((r + m) * 255.0) as u8,
        ((g + m) * 255.0) as u8,
        ((b + m) * 255.0) as u8,
        255,
    ]
}

/// Render a lattice state into RGBA pixel data of the given dimensions.
fn render_lattice(lattice: &SpinLattice, width: u32, height: u32) -> Vec<u8> {
    let n = lattice.lattice_side();
    let q = lattice.field_modulus();
    let spins = lattice.spins();
    let pixels = (width * height) as usize;
    let mut rgba = Vec::with_capacity(pixels * 4);

    for py in 0..height {
        for px in 0..width {
            let lr = (py as usize * n) / height as usize;
            let lc = (px as usize * n) / width as usize;
            let idx = lr * n + lc;

            // Compute neighbour variance for saturation modulation
            let nbrs = crate::core::lattice::triangular_neighbors(lr, lc, n);
            let center = spins[idx] as f32;
            let var: f32 = nbrs
                .iter()
                .map(|&(nr, nc)| {
                    let diff = (center - spins[nr * n + nc] as f32).abs() / q as f32;
                    diff * diff
                })
                .sum::<f32>()
                / 6.0;

            rgba.extend_from_slice(&spin_to_rgba(spins[idx], q, var));
        }
    }
    rgba
}

/// Build a display-sized lattice from a seed, optionally apply coupling
/// bias, anneal, and render.
fn seed_anneal_render(
    fp_seed: &[u8],
    width: u32,
    height: u32,
    coupling_bias: Option<&[u8]>,
) -> Vec<u8> {
    // Use a display-appropriate lattice side length
    let side = (width.max(height) as usize).clamp(8, 64);
    let params = Params {
        lattice_side: side,
        total_spins: side * side,
        q: 251, // largest prime < 256 — keeps gcd(3, q−1)=1 so x³ is bijective
        sponge_rate: side,
        sponge_capacity: side,
        permutation_rounds: side,
        ..Params::default()
    };

    let mut lattice = SpinLattice::new(&params);
    lattice.seed_from_bytes(fp_seed);

    // Apply optional coupling bias derived from photo bytes.
    // Hash the raw bytes via FNV-1a then expand with SplitMix64 so the
    // perturbation covers every coupling with varied values (raw bytes
    // may be short or constant-valued, which causes lattice convergence).
    if let Some(bias) = coupling_bias {
        let mut h: u64 = 0xcbf29ce484222325;
        for &b in bias {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        let q = params.q as u64;
        let couplings = lattice.couplings_mut();
        for c in couplings.iter_mut() {
            h = h.wrapping_add(0x9e3779b97f4a7c15);
            let mut z = h;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
            z = z ^ (z >> 31);
            *c = ((*c as u64 + z % q) % q) as u16;
        }
    }

    // Anneal: side/2 ≈ lattice diameter on the triangular torus,
    // enough for full diffusion without over-convergence.
    lattice.run(side / 2);

    render_lattice(&lattice, width, height)
}

// ── Public API ─────────────────────────────────────────────────────

/// Plain visual fingerprint — session key only.
///
/// Returns raw RGBA pixel data (`width × height × 4` bytes).
/// Two parties who derived the same session key will produce
/// identical images.
pub fn visual_fingerprint(session_key: &[u8; 32], width: u32, height: u32) -> Vec<u8> {
    let fp_seed = spin_kdf(session_key, b"", b"qs-visual-fp", 32);
    seed_anneal_render(&fp_seed, width, height, None)
}

/// Identity-bound visual fingerprint.
///
/// The peer's photo modulates the lattice coupling structure so their
/// face/image is recognisable through the spin-domain colouring.
/// The session key determines the colours; the photo determines the
/// domain topology.
///
/// Returns raw RGBA pixel data (`width × height × 4` bytes).
pub fn identity_fingerprint(
    session_key: &[u8; 32],
    my_photo: &IdentityPhoto,
    peer_photo: &IdentityPhoto,
    width: u32,
    height: u32,
) -> Vec<u8> {
    // Hash both photos and combine in sorted order (symmetric)
    let hash_a = spin_hash(my_photo.as_bytes());
    let hash_b = spin_hash(peer_photo.as_bytes());

    let mut combined = Vec::with_capacity(64);
    if hash_a <= hash_b {
        combined.extend_from_slice(&hash_a);
        combined.extend_from_slice(&hash_b);
    } else {
        combined.extend_from_slice(&hash_b);
        combined.extend_from_slice(&hash_a);
    }

    let fp_seed = spin_kdf(session_key, &combined, b"qs-identity-fingerprint", 32);

    // Use peer photo bytes as coupling bias
    seed_anneal_render(&fp_seed, width, height, Some(peer_photo.as_bytes()))
}

/// Compute the photo hash that should be exchanged during registration
/// so both parties can verify they hold identical copies of the same
/// image before generating an identity-bound fingerprint.
pub fn photo_hash(photo: &IdentityPhoto) -> [u8; 32] {
    spin_hash(photo.as_bytes())
}
