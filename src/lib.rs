//! # oqs-safe
//!
//! A Post-Quantum Cryptography (PQC) toolkit in Rust built on top of libOQS.
//!
//! This crate provides safe, minimal abstractions for:
//! - Post-quantum key exchange (ML-KEM)
//! - Post-quantum signatures (ML-DSA)
//! - Hybrid cryptography (X25519 + ML-KEM)
//! - Secure session key derivation (HKDF)
//!
//! ## Features
//!
//! - ML-KEM (512 / 768 / 1024)
//! - ML-DSA (44 / 65 / 87)
//! - Hybrid cryptography (classical + PQC)
//! - Zeroized secret handling
//! - Mock backend (default) + liboqs backend
//!
//! ## Quick Example (KEM)
//!
//! ```rust
//! use oqs_safe::kem::{Kem, KemAlgorithm, KemInstance};
//!
//! let kem = KemInstance::new(KemAlgorithm::MlKem768);
//!
//! let (pk, sk) = kem.keypair().unwrap();
//! let (ct, ss1) = kem.encapsulate(&pk).unwrap();
//! let ss2 = kem.decapsulate(&ct, &sk).unwrap();
//!
//! assert_eq!(ss1.len(), ss2.len());
//! ```
//!
//! ## Signature Example (ML-DSA)
//!
//! ```rust
//! use oqs_safe::sig::{SigAlgorithm, SigInstance, SignatureScheme};
//!
//! let sig = SigInstance::new(SigAlgorithm::MlDsa44);
//!
//! let (pk, sk) = sig.keypair().unwrap();
//! let msg = b"hello pqc";
//!
//! let signature = sig.sign(&sk, msg).unwrap();
//! sig.verify(&pk, msg, &signature).unwrap();
//! ```
//!
//! ## Hybrid Example (Recommended for PQC Migration)
//!
//! Run the full hybrid example:
//!
//! ```text
//! cargo run --example hybrid_x25519_mlkem
//! ```
//!
//! Run the TLS-style hybrid handshake example:
//!
//! ```text
//! cargo run --example hybrid_handshake
//! ```
//!
//! ## Modules
//!
//! - [`kem`] - Post-quantum key exchange (ML-KEM)
//! - [`sig`] - Post-quantum signatures (ML-DSA)
//! - [`hybrid`] - Hybrid cryptography helpers
//! - [`handshake`] - TLS-style hybrid handshake abstraction
//! - [`session`] - Secure session key derivation
//! - [`classical`] - Classical cryptography helpers such as X25519
//! - [`error`] - Error types
//!
//! ## Backends
//!
//! - Default: mock backend (no native dependencies, for CI/dev)
//! - Optional: `liboqs` feature for real PQC operations
//!
//! ## Security Notes
//!
//! - Always derive keys using HKDF before use
//! - Use hybrid cryptography (X25519 + ML-KEM) for migration
//! - Hybrid cryptography does not replace authentication
//! - Bind identities and transcripts in real protocols
//! - Do not rely on PQC-only deployments yet
//! - Avoid logging or serializing secret material
//!
//! This crate is not formally audited.
#![deny(unsafe_op_in_unsafe_fn)]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod error;
pub mod handshake;
pub mod hybrid;
pub mod kem;
pub mod sig;

// Expose session module publicly.
pub mod session;

// Expose classical crypto helpers such as X25519.
pub mod classical;

#[cfg(feature = "liboqs")]
pub(crate) mod ffi;

pub use error::OqsError;
