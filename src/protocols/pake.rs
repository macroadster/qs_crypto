//! OPAQUE-Spin — Password-Authenticated Key Exchange.
//!
//! Follows the OPAQUE framework (Jarecki et al., 2018) instantiated
//! with the Spin Glass KEM and SpinAEAD. Resists offline dictionary
//! attacks even if the server is compromised.

use crate::error::Error;
use crate::kem::types::KeyPair;

/// Server-side registration record.
///
/// Stores the client's public key and an AEAD-encrypted envelope of
/// the private key (encrypted under a password-derived key). The
/// server never sees the password or the raw private key.
#[derive(Debug, Clone)]
pub struct RegistrationRecord {
    data: Vec<u8>,
}

impl RegistrationRecord {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() {
            return Err(Error::Deserialization(
                "empty registration record".into(),
            ));
        }
        Ok(Self {
            data: bytes.to_vec(),
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.data.clone()
    }
}

/// One-time registration: encrypt the keypair under the password and
/// produce a [`RegistrationRecord`] for server storage.
pub fn pake_register(_password: &str, _keypair: &KeyPair) -> RegistrationRecord {
    todo!("Layer 3: OPAQUE registration — KDF(password) → AEAD-encrypt sk")
}

// ── Client ─────────────────────────────────────────────────────────

/// Client-side PAKE state machine.
pub struct PakeClient {
    _password: String,
}

impl PakeClient {
    pub fn new(password: &str) -> Self {
        Self {
            _password: password.to_owned(),
        }
    }

    /// Produce the first protocol message (client → server).
    pub fn start(&mut self) -> Vec<u8> {
        todo!("Layer 3: PAKE client start — send client_id")
    }

    /// Consume the server's response and derive the session key.
    pub fn finalize(&mut self, _server_msg: &[u8]) -> crate::Result<[u8; 32]> {
        todo!("Layer 3: PAKE client finalize — recover sk, KEM exchanges, derive session key")
    }
}

// ── Server ─────────────────────────────────────────────────────────

/// Server-side PAKE state machine.
pub struct PakeServer {
    _record: RegistrationRecord,
}

impl PakeServer {
    pub fn new(record: RegistrationRecord) -> Self {
        Self { _record: record }
    }

    /// Consume the client's first message and produce the server response.
    pub fn respond(&mut self, _client_msg: &[u8]) -> crate::Result<Vec<u8>> {
        todo!("Layer 3: PAKE server respond — look up record, generate ephemerals, send back")
    }

    /// Derive the session key after `respond` has been called.
    pub fn finalize(&mut self) -> crate::Result<[u8; 32]> {
        todo!("Layer 3: PAKE server finalize — derive session key from three shared secrets")
    }
}