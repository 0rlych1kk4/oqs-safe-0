//! Hybrid crypto helpers.
//!
//! This module provides a simple combiner for PQC + classical shared secrets.
//! Real-world deployments often use hybrid key exchange during migration.

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

#[derive(Clone, Debug, Zeroize)]
#[zeroize(drop)]
pub struct HybridSharedSecret {
    bytes: Vec<u8>,
}

impl HybridSharedSecret {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Combines a PQC shared secret and a classical shared secret using SHA-256.
///
/// This is useful for hybrid migration designs such as:
/// - ML-KEM + X25519
/// - ML-KEM + ECDH
///
/// SECURITY NOTE:
/// This is only a combiner helper. Protocol-level binding, transcript hashing,
/// authentication, and downgrade protection must be handled by the caller.
pub fn combine_shared_secrets(pqc_secret: &[u8], classical_secret: &[u8]) -> HybridSharedSecret {
    let mut hasher = Sha256::new();

    hasher.update(b"oqs-safe hybrid secret v1");
    hasher.update((pqc_secret.len() as u64).to_be_bytes());
    hasher.update(pqc_secret);
    hasher.update((classical_secret.len() as u64).to_be_bytes());
    hasher.update(classical_secret);

    HybridSharedSecret::new(hasher.finalize().to_vec())
}
