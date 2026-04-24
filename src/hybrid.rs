//! Hybrid crypto helpers.
//!
//! This module provides a secure combiner for PQC + classical shared secrets.
//! Real-world deployments SHOULD use hybrid key exchange during migration,
//! e.g. ML-KEM + X25519.
//!
//! This implementation uses HKDF-SHA256 with domain separation.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

/// A zeroized hybrid shared secret.
///
/// This represents the output of combining:
/// - a PQC shared secret (e.g. ML-KEM)
/// - a classical shared secret (e.g. X25519)
///
/// The memory is securely wiped on drop.
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

/// Derives a hybrid shared secret using HKDF-SHA256.
///
/// This is the recommended approach for combining:
/// - PQC secret (ML-KEM)
/// - Classical secret (X25519 / ECDH)
///
/// # Parameters
/// - `pqc_secret`: ML-KEM shared secret
/// - `classical_secret`: X25519 or ECDH shared secret
/// - `context`: domain separation label (protocol-specific)
///
/// # Security Properties
/// - Uses HKDF (not raw hashing)
/// - Domain-separated
/// - Supports variable output length
/// - Intermediate material is zeroized
///
/// # Example context labels
/// - b"oqs-safe-v0.4-hybrid"
/// - b"tls13 hybrid handshake"
///
/// # WARNING
/// This function does NOT provide:
/// - Authentication
/// - Transcript binding
/// - Downgrade protection
///
/// These MUST be handled at the protocol layer.
pub fn derive_hybrid_secret(
    pqc_secret: &[u8],
    classical_secret: &[u8],
    context: &[u8],
) -> HybridSharedSecret {
    // Combine input key material (IKM)
    let mut ikm = Zeroizing::new(Vec::with_capacity(
        pqc_secret.len() + classical_secret.len(),
    ));

    ikm.extend_from_slice(pqc_secret);
    ikm.extend_from_slice(classical_secret);

    // HKDF extract + expand
    let hk = Hkdf::<Sha256>::new(Some(context), &ikm);

    let mut okm = vec![0u8; 32]; // default 256-bit output

    hk.expand(b"oqs-safe hybrid derived secret", &mut okm)
        .expect("hkdf expand failure");

    HybridSharedSecret::new(okm)
}

/// Same as `derive_hybrid_secret` but allows custom output length.
///
/// Useful for deriving:
/// - AES-256 keys (32 bytes)
/// - ChaCha20 keys (32 bytes)
/// - Longer key material for session splitting
pub fn derive_hybrid_secret_with_len(
    pqc_secret: &[u8],
    classical_secret: &[u8],
    context: &[u8],
    out_len: usize,
) -> HybridSharedSecret {
    let mut ikm = Zeroizing::new(Vec::with_capacity(
        pqc_secret.len() + classical_secret.len(),
    ));

    ikm.extend_from_slice(pqc_secret);
    ikm.extend_from_slice(classical_secret);

    let hk = Hkdf::<Sha256>::new(Some(context), &ikm);

    let mut okm = vec![0u8; out_len];

    hk.expand(b"oqs-safe hybrid derived secret", &mut okm)
        .expect("hkdf expand failure");

    HybridSharedSecret::new(okm)
}
