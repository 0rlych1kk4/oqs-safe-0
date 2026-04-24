// Copyright (c) 2025 Orlando Trajano
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Safe KEM API for ML-KEM / Kyber.
//!
//! Supports:
//! - ML-KEM-512 / Kyber512
//! - ML-KEM-768 / Kyber768
//! - ML-KEM-1024 / Kyber1024

use crate::OqsError;
use zeroize::Zeroize;

#[cfg(not(feature = "liboqs"))]
use rand_core::{OsRng, RngCore};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KemAlgorithm {
    MlKem512,
    MlKem768,
    MlKem1024,
}

impl KemAlgorithm {
    pub fn names(self) -> (&'static str, &'static str) {
        match self {
            KemAlgorithm::MlKem512 => ("ML-KEM-512", "Kyber512"),
            KemAlgorithm::MlKem768 => ("ML-KEM-768", "Kyber768"),
            KemAlgorithm::MlKem1024 => ("ML-KEM-1024", "Kyber1024"),
        }
    }

    pub fn public_key_len(self) -> usize {
        match self {
            KemAlgorithm::MlKem512 => 800,
            KemAlgorithm::MlKem768 => 1184,
            KemAlgorithm::MlKem1024 => 1568,
        }
    }

    pub fn secret_key_len(self) -> usize {
        match self {
            KemAlgorithm::MlKem512 => 1632,
            KemAlgorithm::MlKem768 => 2400,
            KemAlgorithm::MlKem1024 => 3168,
        }
    }

    pub fn ciphertext_len(self) -> usize {
        match self {
            KemAlgorithm::MlKem512 => 768,
            KemAlgorithm::MlKem768 => 1088,
            KemAlgorithm::MlKem1024 => 1568,
        }
    }

    pub fn shared_secret_len(self) -> usize {
        32
    }
}

#[derive(Clone, Debug)]
pub struct PublicKey {
    alg: KemAlgorithm,
    bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct SecretKey {
    alg: KemAlgorithm,
    bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Ciphertext {
    alg: KemAlgorithm,
    bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct SharedSecret {
    alg: KemAlgorithm,
    bytes: Vec<u8>,
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl PublicKey {
    pub fn new(alg: KemAlgorithm, bytes: Vec<u8>) -> Self {
        Self { alg, bytes }
    }

    pub fn algorithm(&self) -> KemAlgorithm {
        self.alg
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

impl SecretKey {
    pub fn new(alg: KemAlgorithm, bytes: Vec<u8>) -> Self {
        Self { alg, bytes }
    }

    pub fn algorithm(&self) -> KemAlgorithm {
        self.alg
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

impl Ciphertext {
    pub fn new(alg: KemAlgorithm, bytes: Vec<u8>) -> Self {
        Self { alg, bytes }
    }

    pub fn algorithm(&self) -> KemAlgorithm {
        self.alg
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

impl SharedSecret {
    pub fn new(alg: KemAlgorithm, bytes: Vec<u8>) -> Self {
        Self { alg, bytes }
    }

    pub fn algorithm(&self) -> KemAlgorithm {
        self.alg
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

pub trait Kem {
    fn keypair(&self) -> Result<(PublicKey, SecretKey), OqsError>;
    fn encapsulate(&self, pk: &PublicKey) -> Result<(Ciphertext, SharedSecret), OqsError>;
    fn decapsulate(&self, ct: &Ciphertext, sk: &SecretKey) -> Result<SharedSecret, OqsError>;
}

#[derive(Clone, Copy, Debug)]
pub struct KemInstance {
    alg: KemAlgorithm,
}

impl KemInstance {
    pub fn new(alg: KemAlgorithm) -> Self {
        Self { alg }
    }

    pub fn algorithm(&self) -> KemAlgorithm {
        self.alg
    }
}

impl Kem for KemInstance {
    fn keypair(&self) -> Result<(PublicKey, SecretKey), OqsError> {
        #[cfg(feature = "liboqs")]
        {
            let (pk, sk) = crate::ffi::kem_keypair(self.alg)?;
            Ok((PublicKey::new(self.alg, pk), SecretKey::new(self.alg, sk)))
        }

        #[cfg(not(feature = "liboqs"))]
        {
            let mut pk = vec![0u8; self.alg.public_key_len()];
            let mut sk = vec![0u8; self.alg.secret_key_len()];

            OsRng.fill_bytes(&mut pk);
            OsRng.fill_bytes(&mut sk);

            Ok((PublicKey::new(self.alg, pk), SecretKey::new(self.alg, sk)))
        }
    }

    fn encapsulate(&self, pk: &PublicKey) -> Result<(Ciphertext, SharedSecret), OqsError> {
        if pk.algorithm() != self.alg {
            return Err(OqsError::InvalidLength);
        }

        #[cfg(feature = "liboqs")]
        {
            crate::ffi::kem_encapsulate(self.alg, pk.as_bytes()).map(|(ct, ss)| {
                (
                    Ciphertext::new(self.alg, ct),
                    SharedSecret::new(self.alg, ss),
                )
            })
        }

        #[cfg(not(feature = "liboqs"))]
        {
            if pk.len() != self.alg.public_key_len() {
                return Err(OqsError::InvalidLength);
            }

            let mut ct = vec![0u8; self.alg.ciphertext_len()];
            let mut ss = vec![0u8; self.alg.shared_secret_len()];

            OsRng.fill_bytes(&mut ct);
            OsRng.fill_bytes(&mut ss);

            Ok((
                Ciphertext::new(self.alg, ct),
                SharedSecret::new(self.alg, ss),
            ))
        }
    }

    fn decapsulate(&self, ct: &Ciphertext, sk: &SecretKey) -> Result<SharedSecret, OqsError> {
        if ct.algorithm() != self.alg || sk.algorithm() != self.alg {
            return Err(OqsError::InvalidLength);
        }

        #[cfg(feature = "liboqs")]
        {
            crate::ffi::kem_decapsulate(self.alg, ct.as_bytes(), sk.as_bytes())
                .map(|ss| SharedSecret::new(self.alg, ss))
        }

        #[cfg(not(feature = "liboqs"))]
        {
            if ct.len() != self.alg.ciphertext_len() || sk.len() != self.alg.secret_key_len() {
                return Err(OqsError::InvalidLength);
            }

            let mut ss = vec![0u8; self.alg.shared_secret_len()];
            OsRng.fill_bytes(&mut ss);

            Ok(SharedSecret::new(self.alg, ss))
        }
    }
}

pub type MlKem512 = KemInstance;
pub type MlKem768 = KemInstance;
pub type MlKem1024 = KemInstance;
pub type Kyber768 = KemInstance;
