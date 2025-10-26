//! Signature API with safe accessors and feature-gated RNG for the mock backend.

use crate::OqsError;
use zeroize::Zeroize;

#[cfg(not(feature = "liboqs"))]
use rand_core::{OsRng, RngCore};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PublicKey(pub(crate) Vec<u8>);

#[derive(Clone, Debug, Zeroize)]
#[zeroize(drop)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SecretKey(pub(crate) Vec<u8>);

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Signature(pub(crate) Vec<u8>);

// ---- Read-only accessors ----
impl PublicKey {
    #[inline] pub fn as_bytes(&self) -> &[u8] { &self.0 }
    #[inline] pub fn len(&self) -> usize { self.0.len() }
    #[inline] pub fn is_empty(&self) -> bool { self.0.is_empty() }
}
impl SecretKey {
    #[inline] pub fn as_bytes(&self) -> &[u8] { &self.0 }
    #[inline] pub fn len(&self) -> usize { self.0.len() }
    #[inline] pub fn is_empty(&self) -> bool { self.0.is_empty() }
}
impl Signature {
    #[inline] pub fn as_bytes(&self) -> &[u8] { &self.0 }
    #[inline] pub fn len(&self) -> usize { self.0.len() }
    #[inline] pub fn is_empty(&self) -> bool { self.0.is_empty() }
}

pub trait SignatureScheme {
    fn keypair() -> Result<(PublicKey, SecretKey), OqsError>;
    fn sign(sk: &SecretKey, msg: &[u8]) -> Result<Signature, OqsError>;
    fn verify(pk: &PublicKey, msg: &[u8], sig: &Signature) -> Result<(), OqsError>;
}

pub struct Dilithium2;

impl SignatureScheme for Dilithium2 {
    fn keypair() -> Result<(PublicKey, SecretKey), OqsError> {
        #[cfg(feature = "liboqs")]
        {
            let (pk, sk) = crate::ffi::dilithium2_keypair()?;
            Ok((PublicKey(pk), SecretKey(sk)))
        }
        #[cfg(not(feature = "liboqs"))]
        {
            // Mock path: size-faithful random buffers for CI / no-liboqs environments.
            let mut pk = vec![0u8; 1312];
            let mut sk = vec![0u8; 2528];
            OsRng.fill_bytes(&mut pk);
            OsRng.fill_bytes(&mut sk);
            Ok((PublicKey(pk), SecretKey(sk)))
        }
    }

    fn sign(sk: &SecretKey, msg: &[u8]) -> Result<Signature, OqsError> {
        #[cfg(feature = "liboqs")]
        {
            crate::ffi::dilithium2_sign(sk.as_bytes(), msg).map(Signature)
        }
        #[cfg(not(feature = "liboqs"))]
        {
            // Silence unused warnings on mock path
            let _ = (sk, msg);
            let mut sig = vec![0u8; 2420];
            OsRng.fill_bytes(&mut sig);
            Ok(Signature(sig))
        }
    }

    fn verify(pk: &PublicKey, msg: &[u8], sig: &Signature) -> Result<(), OqsError> {
        #[cfg(feature = "liboqs")]
        {
            crate::ffi::dilithium2_verify(pk.as_bytes(), msg, sig.as_bytes())
        }
        #[cfg(not(feature = "liboqs"))]
        {
            // Silence unused warnings on mock path
            let _ = (pk, msg);
            if sig.len() != 2420 {
                return Err(OqsError::InvalidLength);
            }
            Ok(())
        }
    }
}
