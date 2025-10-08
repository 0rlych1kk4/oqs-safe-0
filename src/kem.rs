// Copyright (c) 2025 Orlando Trajano
// SPDX-License-Identifier: MIT OR Apache-2.0

//! KEM API with safe accessors and feature-gated RNG for the mock backend.

use crate::OqsError;
use zeroize::Zeroize;

#[cfg(not(feature = "liboqs"))]
use rand_core::{OsRng, RngCore};

/// Public key newtype
#[derive(Clone, Debug)]
pub struct PublicKey(pub(crate) Vec<u8>);

/// Secret key newtype (zeroizes on drop)
#[derive(Clone, Debug, Zeroize)]
#[zeroize(drop)]
pub struct SecretKey(pub(crate) Vec<u8>);

/// Ciphertext newtype
#[derive(Clone, Debug)]
pub struct Ciphertext(pub(crate) Vec<u8>);

/// Shared secret newtype
#[derive(Clone, Debug)]
pub struct SharedSecret(pub(crate) Vec<u8>);

/// Read-only accessors (avoid exposing tuple fields directly)
impl PublicKey {
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
impl SecretKey {
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
impl Ciphertext {
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
impl SharedSecret {
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// KEM trait
pub trait Kem {
    fn keypair() -> Result<(PublicKey, SecretKey), OqsError>;
    fn encapsulate(pk: &PublicKey) -> Result<(Ciphertext, SharedSecret), OqsError>;
    fn decapsulate(ct: &Ciphertext, sk: &SecretKey) -> Result<SharedSecret, OqsError>;
}

/// Kyber768 implementation
pub struct Kyber768;

impl Kem for Kyber768 {
    fn keypair() -> Result<(PublicKey, SecretKey), OqsError> {
        #[cfg(feature = "liboqs")]
        {
            let (pk, sk) = crate::ffi::kyber768_keypair()?;
            Ok((PublicKey(pk), SecretKey(sk)))
        }
        #[cfg(not(feature = "liboqs"))]
        {
            // Mock path: size-faithful random buffers for CI / no-liboqs environments.
            let mut pk = vec![0u8; 1184]; // Kyber768 pk size
            let mut sk = vec![0u8; 2400]; // Kyber768 sk size
            OsRng.fill_bytes(&mut pk);
            OsRng.fill_bytes(&mut sk);
            Ok((PublicKey(pk), SecretKey(sk)))
        }
    }

    fn encapsulate(pk: &PublicKey) -> Result<(Ciphertext, SharedSecret), OqsError> {
        #[cfg(feature = "liboqs")]
        {
            crate::ffi::kyber768_encapsulate(pk.as_bytes())
                .map(|(c, s)| (Ciphertext(c), SharedSecret(s)))
        }
        #[cfg(not(feature = "liboqs"))]
        {
            if pk.len() != 1184 {
                return Err(OqsError::InvalidLength);
            }
            let mut ct = vec![0u8; 1088]; // Kyber768 ct size
            let mut ss = vec![0u8; 32]; // Shared secret size (bytes)
            OsRng.fill_bytes(&mut ct);
            OsRng.fill_bytes(&mut ss);
            Ok((Ciphertext(ct), SharedSecret(ss)))
        }
    }

    fn decapsulate(ct: &Ciphertext, sk: &SecretKey) -> Result<SharedSecret, OqsError> {
        #[cfg(feature = "liboqs")]
        {
            crate::ffi::kyber768_decapsulate(ct.as_bytes(), sk.as_bytes()).map(SharedSecret)
        }
        #[cfg(not(feature = "liboqs"))]
        {
            if ct.len() != 1088 || sk.len() != 2400 {
                return Err(OqsError::InvalidLength);
            }
            let mut ss = vec![0u8; 32];
            OsRng.fill_bytes(&mut ss);
            Ok(SharedSecret(ss))
        }
    }
}
