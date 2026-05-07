//! KEM data types — keys, ciphertext, shared secret.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::Error;

// ── Keys ───────────────────────────────────────────────────────────

/// Public key: coupling matrix J (sparse) + noisy field vector h.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    data: Vec<u8>,
}

impl PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() {
            return Err(Error::Deserialization("empty public key".into()));
        }
        Ok(Self {
            data: bytes.to_vec(),
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.data.clone()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

/// Private key: planted ground state σ*.
///
/// Implements [`Zeroize`] + [`ZeroizeOnDrop`] so the secret material
/// is wiped from memory when the key is dropped.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey {
    data: Vec<u8>,
}

impl PrivateKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() {
            return Err(Error::Deserialization("empty private key".into()));
        }
        Ok(Self {
            data: bytes.to_vec(),
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.data.clone()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        // Constant-time comparison would be preferred here;
        // for the stub we use a plain comparison.
        self.data == other.data
    }
}
impl Eq for PrivateKey {}

/// A keypair containing both the public and private components.
#[derive(Debug, Clone)]
pub struct KeyPair {
    pub public_key: PublicKey,
    pub private_key: PrivateKey,
}

// ── Ciphertext & Shared Secret ─────────────────────────────────────

/// Ciphertext produced by KEM encapsulation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ciphertext {
    data: Vec<u8>,
}

impl Ciphertext {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() {
            return Err(Error::Deserialization("empty ciphertext".into()));
        }
        Ok(Self {
            data: bytes.to_vec(),
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.data.clone()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

/// 256-bit shared secret derived from a KEM operation.
///
/// Zeroized on drop so the secret never lingers in memory.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret([u8; 32]);

impl SharedSecret {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl PartialEq for SharedSecret {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl Eq for SharedSecret {}

impl std::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SharedSecret([REDACTED])")
    }
}

// ── Encapsulation result ───────────────────────────────────────────

/// Output of [`super::encapsulate`]: a ciphertext to send and the
/// shared secret both parties will derive.
#[derive(Debug)]
pub struct EncapsulationResult {
    pub ciphertext: Ciphertext,
    pub shared_secret: SharedSecret,
}