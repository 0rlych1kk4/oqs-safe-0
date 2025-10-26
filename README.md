# oqs-safe

[![Crates.io](https://img.shields.io/crates/v/oqs-safe.svg)](https://crates.io/crates/oqs-safe)
[![Release](https://img.shields.io/github/v/release/0rlych1kk4/oqs-safe-0?sort=semver)](https://github.com/0rlych1kk4/oqs-safe-0/releases)
[![Docs.rs](https://docs.rs/oqs-safe/badge.svg)](https://docs.rs/oqs-safe)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)  
[![CI](https://github.com/0rlych1kk4/oqs-safe-0/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/0rlych1kk4/oqs-safe-0/actions/workflows/ci.yml)

**oqs-safe** is a stable, minimal **safe Rust wrapper** over [libOQS] for NIST Post-Quantum Cryptography (PQC):

- **KEM:** ML-KEM-768 (Kyber768)  
- **SIG:** ML-DSA-44 (Dilithium2)

> Zeroizes secrets • Safe newtypes • Compile-time guardrails • Resilient to liboqs naming drift (“ML-KEM-768” ↔ “Kyber768”, “ML-DSA-44” ↔ “Dilithium2”)

---

## Install

### 1. Add the crate

- **Default (mock backend for CI/dev):**
  ```toml
  oqs-safe = { version = "0.2", features = ["kyber768", "dilithium2"] }

- **Production (real liboqs backend):**

  oqs-safe = { version = "0.2", default-features = false, features = ["liboqs", "kyber768", "dilithium2"] }

### 2. (Prod only) Install libOQS

  git clone https://github.com/open-quantum-safe/liboqs
  cd liboqs && mkdir build && cd build
  cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DOQS_DIST_BUILD=ON -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX="$HOME/.local/liboqs" ..
  ninja && ninja install

- **Make oqs-safe find and load liboqs:**
  export LIBOQS_DIR="$HOME/.local/liboqs"

- **macOS: ensure runtime linking finds liboqs.dylib:**
  export DYLD_FALLBACK_LIBRARY_PATH="$HOME/.local/liboqs/lib:${DYLD_FALLBACK_LIBRARY_PATH}"

- **Optional: pkg-config:**
  export PKG_CONFIG_PATH="$HOME/.local/liboqs/lib/pkgconfig:${PKG_CONFIG_PATH}"

## Quickstart
### KEM round-trip (Kyber / ML-KEM-768)

   use oqs_safe::kem::{Kem, Kyber768};

   let (pk, sk) = Kyber768::keypair()?;
   let (ct, ss1) = Kyber768::encapsulate(&pk)?;
   let ss2 = Kyber768::decapsulate(&ct, &sk)?;
   assert_eq!(ss1.len(), ss2.len());

### Sign & verify (Dilithium / ML-DSA-44)

   use oqs_safe::sig::{Dilithium2, SignatureScheme};

   let (pk, sk) = Dilithium2::keypair()?;
   let msg = b"hello pqc";
   let sig = Dilithium2::sign(&sk, msg)?;
   Dilithium2::verify(&pk, msg, &sig)?;

### Derive session keys (HKDF over shared secret)

   use oqs_safe::kem::{Kem, Kyber768};
   use hkdf::Hkdf;
   use sha2::Sha256;

   let (_, sk) = Kyber768::keypair()?;
   let (ct, ss1) = Kyber768::encapsulate(&Kyber768::keypair()?.0)?;
   let ss = Kyber768::decapsulate(&ct, &sk)?;
   let hk = Hkdf::<Sha256>::new(Some(b"oqs-safe context"), ss.as_bytes());
   let mut key = [0u8; 32];
   hk.expand(b"aes256-gcm key", &mut key)?;

## Examples

- **Mock backend (fast, no native deps):**
  cargo run --example kem_roundtrip --features "kyber768"
  cargo run --example dsa_sign_verify --features "dilithium2"

- **Real backend:**
  cargo run --example kem_roundtrip --features "liboqs,kyber768"
  cargo run --example dsa_sign_verify --features "liboqs,dilithium2"
- **Tests:**
- **Mock + negative-path tests:**
  cargo test --features "mock,kyber768,dilithium2,testing"

- **Real liboqs:**
  cargo test --features "liboqs,kyber768,dilithium2"

- **Linking Tips:**
- **macOS:**
- **To ensure binaries find liboqs.dylib, embed an rpath:**
- **.cargo/config.toml:**
  [target.aarch64-apple-darwin]
  rustflags = ["-C", "link-arg=-Wl,-rpath,@executable_path/../lib"]

- **Linux:**
- **Use PKG_CONFIG_PATH or LD_LIBRARY_PATH=$HOME/.local/liboqs/lib.:**

## Security Notes
- **Always derive session keys via HKDF (or similar) before use.:**
- **Bind identities and protocol transcripts to KEM exchanges.:**
- **All secret materials (SecretKey, etc.) are zeroized on drop.:**
- **Avoid serializing or logging secrets.:**

## MSRV & License

- **MSRV: Rust 1.70+:**

## License: MIT OR Apache-2.0

## Acknowledgements
- **Built atop libOQS from the Open Quantum Safe project.:- **
- **Contributions welcome for expanded PQC algorithms and integration with secure enclaves, blockchain key stores, or HSM interfaces.:**

