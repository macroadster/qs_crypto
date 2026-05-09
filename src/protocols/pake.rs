//! Simplified PAKE — Password-Authenticated Key Exchange.
//!
//! Inspired by the OPAQUE framework (Jarecki et al., 2018) but
//! significantly simplified: no OPRF blinding, no client identity in
//! the first message, and a 2-message flow instead of the full
//! 3-message OPAQUE protocol. Instantiated with the Spin Glass KEM
//! and SpinAEAD.
//!
//! ## Protocol sketch
//!
//! **Registration (one-time, secure channel):**
//!   1. Client derives `pwk = SpinKDF(password, salt, "qs-pake-envelope")`
//!   2. Client encrypts `sk` under `pwk` → envelope
//!   3. Server stores `(pk, envelope, salt, nonce)`
//!
//! **Login (insecure channel):**
//!   1. Client sends identity (msg1)
//!   2. Server encapsulates against `pk` → (ct, ss), sends record back (msg2)
//!   3. Client decrypts envelope → `sk`, decapsulates ct → ss
//!   4. Both derive `session_key = SpinHash(ss ‖ transcript)`

use sha3::digest::{ExtendableOutput, Update};
use sha3::Shake256;
use std::io::Read;
use zeroize::Zeroize;

use crate::error::Error;
use crate::kem::types::KeyPair;
use crate::kem::{decapsulate, encapsulate};
use crate::primitives::aead;

/// Derive a 32-byte key from input material using SHAKE256.
///
/// Replaces `spin_kdf` in security-critical paths so that password key
/// derivation and session key derivation do not depend on the unvetted
/// SpinSponge permutation.
fn shake_kdf(domain: &[u8], key: &[u8], salt: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(domain);
    hasher.update(&(key.len() as u64).to_le_bytes());
    hasher.update(key);
    hasher.update(&(salt.len() as u64).to_le_bytes());
    hasher.update(salt);
    hasher.update(info);
    let mut reader = hasher.finalize_xof();
    let mut out = vec![0u8; len];
    reader.read_exact(&mut out).expect("SHAKE256 read must not fail");
    out
}

/// Derive a 32-byte session key hash from transcript material using SHAKE256.
fn shake_session_hash(domain_byte: u8, shared_secret: &[u8], transcript: &[u8]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(&[domain_byte]);
    hasher.update(shared_secret);
    hasher.update(transcript);
    let mut reader = hasher.finalize_xof();
    let mut out = [0u8; 32];
    reader.read_exact(&mut out).expect("SHAKE256 read must not fail");
    out
}

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
            return Err(Error::Deserialization("empty registration record".into()));
        }
        Ok(Self {
            data: bytes.to_vec(),
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.data.clone()
    }
}

// Wire format helpers — all lengths are u32 LE.
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

/// One-time registration: encrypt the keypair under the password and
/// produce a [`RegistrationRecord`] for server storage.
pub fn pake_register(password: &str, keypair: &KeyPair) -> RegistrationRecord {
    // Salt + nonce from OS entropy
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut salt).expect("OS RNG failed");
    getrandom::getrandom(&mut nonce).expect("OS RNG failed");

    // Derive password key via SHAKE256 (vetted)
    let pwk_vec = shake_kdf(b"qs-pake-envelope", password.as_bytes(), &salt, b"", 32);
    let pwk: [u8; 32] = pwk_vec.try_into().unwrap();

    // Encrypt private key
    let sk_bytes = keypair.private_key.to_bytes();
    let pk_bytes = keypair.public_key.to_bytes();
    let envelope = aead::encrypt(&pwk, &nonce, &pk_bytes, &sk_bytes);

    // Record = [pk, envelope_ct, envelope_tag, salt, nonce]
    let mut data = Vec::new();
    write_len_prefixed(&mut data, &pk_bytes);
    write_len_prefixed(&mut data, &envelope.ciphertext);
    data.extend_from_slice(&envelope.tag);
    data.extend_from_slice(&salt);
    data.extend_from_slice(&nonce);

    RegistrationRecord { data }
}

// ── Client ─────────────────────────────────────────────────────────

/// Client-side PAKE state machine.
pub struct PakeClient {
    password: String,
}

impl Drop for PakeClient {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

impl PakeClient {
    pub fn new(password: &str) -> Self {
        Self {
            password: password.to_owned(),
        }
    }

    /// Produce the first protocol message (client → server).
    pub fn start(&mut self) -> Vec<u8> {
        // In a full implementation, this would contain a client identifier.
        // For the 2-message protocol: just a marker.
        vec![0x01]
    }

    /// Consume the server's response and derive the session key.
    ///
    /// msg2 = [record_data, kem_ct]
    pub fn finalize(&mut self, server_msg: &[u8]) -> crate::Result<[u8; 32]> {
        let mut off = 0usize;

        // Parse record fields from server message
        let pk_bytes = read_len_prefixed(server_msg, &mut off)?;
        let envelope_ct = read_len_prefixed(server_msg, &mut off)?;
        if off + 16 + 32 + 16 > server_msg.len() {
            return Err(Error::Pake("message too short".into()));
        }
        let tag: [u8; 16] = server_msg[off..off + 16].try_into().unwrap();
        off += 16;
        let salt: [u8; 32] = server_msg[off..off + 32].try_into().unwrap();
        off += 32;
        let nonce: [u8; 16] = server_msg[off..off + 16].try_into().unwrap();
        off += 16;
        let kem_ct_bytes = read_len_prefixed(server_msg, &mut off)?;

        // Recover private key via SHAKE256 (vetted — must match registration)
        let pwk_vec = shake_kdf(b"qs-pake-envelope", self.password.as_bytes(), &salt, b"", 32);
        let pwk: [u8; 32] = pwk_vec.try_into().unwrap();
        let sk_bytes = aead::decrypt(&pwk, &nonce, &pk_bytes, &envelope_ct, &tag)
            .map_err(|_| Error::Pake("wrong password or corrupted envelope".into()))?;

        let sk = crate::kem::types::PrivateKey::from_bytes(&sk_bytes)?;
        let ct = crate::kem::types::Ciphertext::from_bytes(&kem_ct_bytes)?;

        // Decapsulate to get shared secret
        let ss = decapsulate(&sk, &ct)?;

        // Derive session key via SHAKE256 (vetted)
        Ok(shake_session_hash(0x20, ss.as_bytes(), server_msg))
    }
}

// ── Server ─────────────────────────────────────────────────────────

/// Server-side PAKE state machine.
pub struct PakeServer {
    record: RegistrationRecord,
    shared_secret: Option<[u8; 32]>,
    response_bytes: Option<Vec<u8>>,
}

impl Drop for PakeServer {
    fn drop(&mut self) {
        if let Some(ref mut ss) = self.shared_secret {
            ss.zeroize();
        }
    }
}

impl PakeServer {
    pub fn new(record: RegistrationRecord) -> Self {
        Self {
            record,
            shared_secret: None,
            response_bytes: None,
        }
    }

    /// Consume the client's first message and produce the server response.
    pub fn respond(&mut self, _client_msg: &[u8]) -> crate::Result<Vec<u8>> {
        // Parse the stored record to extract the public key
        let rec = &self.record.data;
        let mut off = 0usize;
        let pk_bytes = read_len_prefixed(rec, &mut off)?;
        let pk = crate::kem::types::PublicKey::from_bytes(&pk_bytes)?;

        // KEM encapsulation against the client's registered public key
        let result = encapsulate(&pk);
        let ss = *result.shared_secret.as_bytes();
        let ct_bytes = result.ciphertext.to_bytes();

        // Build server message: record_data ‖ kem_ct
        let mut msg = self.record.data.clone();
        write_len_prefixed(&mut msg, &ct_bytes);

        self.shared_secret = Some(ss);
        self.response_bytes = Some(msg.clone());
        Ok(msg)
    }

    /// Derive the session key after `respond` has been called.
    pub fn finalize(&mut self) -> crate::Result<[u8; 32]> {
        let ss = self
            .shared_secret
            .ok_or_else(|| Error::Pake("respond() not called".into()))?;
        let resp = self
            .response_bytes
            .as_ref()
            .ok_or_else(|| Error::Pake("respond() not called".into()))?;

        Ok(shake_session_hash(0x20, &ss, resp))
    }
}
