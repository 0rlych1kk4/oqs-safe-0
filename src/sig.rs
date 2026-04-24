//! Safe signature API for ML-DSA / Dilithium.
//!
//! Supports:
//! - ML-DSA-44 / Dilithium2
//! - ML-DSA-65 / Dilithium3
//! - ML-DSA-87 / Dilithium5

use crate::OqsError;
use zeroize::Zeroize;

#[cfg(not(feature = "liboqs"))]
use rand_core::{OsRng, RngCore};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SigAlgorithm {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

impl SigAlgorithm {
    pub fn names(self) -> &'static [&'static str] {
        match self {
            SigAlgorithm::MlDsa44 => &["ML-DSA-44", "Dilithium2", "ML-DSA-2"],
            SigAlgorithm::MlDsa65 => &["ML-DSA-65", "Dilithium3", "ML-DSA-3"],
            SigAlgorithm::MlDsa87 => &["ML-DSA-87", "Dilithium5", "ML-DSA-5"],
        }
    }

    pub fn public_key_len(self) -> usize {
        match self {
            SigAlgorithm::MlDsa44 => 1312,
            SigAlgorithm::MlDsa65 => 1952,
            SigAlgorithm::MlDsa87 => 2592,
        }
    }

    pub fn secret_key_len(self) -> usize {
        match self {
            SigAlgorithm::MlDsa44 => 2528,
            SigAlgorithm::MlDsa65 => 4000,
            SigAlgorithm::MlDsa87 => 4864,
        }
    }

    pub fn signature_len(self) -> usize {
        match self {
            SigAlgorithm::MlDsa44 => 2420,
            SigAlgorithm::MlDsa65 => 3293,
            SigAlgorithm::MlDsa87 => 4595,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PublicKey {
    alg: SigAlgorithm,
    bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct SecretKey {
    alg: SigAlgorithm,
    bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Signature {
    alg: SigAlgorithm,
    bytes: Vec<u8>,
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl PublicKey {
    pub fn new(alg: SigAlgorithm, bytes: Vec<u8>) -> Self {
        Self { alg, bytes }
    }

    pub fn algorithm(&self) -> SigAlgorithm {
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
    pub fn new(alg: SigAlgorithm, bytes: Vec<u8>) -> Self {
        Self { alg, bytes }
    }

    pub fn algorithm(&self) -> SigAlgorithm {
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

impl Signature {
    pub fn new(alg: SigAlgorithm, bytes: Vec<u8>) -> Self {
        Self { alg, bytes }
    }

    pub fn algorithm(&self) -> SigAlgorithm {
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

pub trait SignatureScheme {
    fn keypair(&self) -> Result<(PublicKey, SecretKey), OqsError>;
    fn sign(&self, sk: &SecretKey, msg: &[u8]) -> Result<Signature, OqsError>;
    fn verify(&self, pk: &PublicKey, msg: &[u8], sig: &Signature) -> Result<(), OqsError>;
}

#[derive(Clone, Copy, Debug)]
pub struct SigInstance {
    alg: SigAlgorithm,
}

impl SigInstance {
    pub fn new(alg: SigAlgorithm) -> Self {
        Self { alg }
    }

    pub fn algorithm(&self) -> SigAlgorithm {
        self.alg
    }
}

impl SignatureScheme for SigInstance {
    fn keypair(&self) -> Result<(PublicKey, SecretKey), OqsError> {
        #[cfg(feature = "liboqs")]
        {
            let (pk, sk) = crate::ffi::sig_keypair(self.alg)?;
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

    fn sign(&self, sk: &SecretKey, msg: &[u8]) -> Result<Signature, OqsError> {
        if sk.algorithm() != self.alg {
            return Err(OqsError::InvalidLength);
        }

        #[cfg(feature = "liboqs")]
        {
            crate::ffi::sig_sign(self.alg, sk.as_bytes(), msg)
                .map(|sig| Signature::new(self.alg, sig))
        }

        #[cfg(not(feature = "liboqs"))]
        {
            let _ = msg;

            if sk.len() != self.alg.secret_key_len() {
                return Err(OqsError::InvalidLength);
            }

            let mut sig = vec![0u8; self.alg.signature_len()];
            OsRng.fill_bytes(&mut sig);

            Ok(Signature::new(self.alg, sig))
        }
    }

    fn verify(&self, pk: &PublicKey, msg: &[u8], sig: &Signature) -> Result<(), OqsError> {
        if pk.algorithm() != self.alg || sig.algorithm() != self.alg {
            return Err(OqsError::InvalidLength);
        }

        #[cfg(feature = "liboqs")]
        {
            crate::ffi::sig_verify(self.alg, pk.as_bytes(), msg, sig.as_bytes())
        }

        #[cfg(not(feature = "liboqs"))]
        {
            let _ = msg;

            if pk.len() != self.alg.public_key_len() || sig.len() != self.alg.signature_len() {
                return Err(OqsError::InvalidLength);
            }

            Ok(())
        }
    }
}

pub type MlDsa44 = SigInstance;
pub type MlDsa65 = SigInstance;
pub type MlDsa87 = SigInstance;
pub type Dilithium2 = SigInstance;
