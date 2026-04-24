# oqs-safe

[![Crates.io](https://img.shields.io/crates/v/oqs-safe.svg)](https://crates.io/crates/oqs-safe)
[![Release](https://img.shields.io/github/v/release/0rlych1kk4/oqs-safe-0?sort=semver)](https://github.com/0rlych1kk4/oqs-safe-0/releases)
[![Docs.rs](https://docs.rs/oqs-safe/badge.svg)](https://docs.rs/oqs-safe)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)  
[![CI](https://github.com/0rlych1kk4/oqs-safe-0/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/0rlych1kk4/oqs-safe-0/actions/workflows/ci.yml)

---

##  oqs-safe v0.4.0

**oqs-safe** is a **production-oriented Post-Quantum Cryptography (PQC) toolkit in Rust**, built on top of [libOQS].

It provides safe, minimal abstractions for:
- Post-quantum key exchange (ML-KEM)
- Post-quantum signatures (ML-DSA)
- Hybrid cryptography (classical + PQC)
- Secure session key derivation

> Zeroizes secrets • Safe newtypes • Hybrid-ready • Migration-focused

---

##  Features

###  Post-Quantum Algorithms

- **KEM:**  
  - ML-KEM-512  
  - ML-KEM-768  
  - ML-KEM-1024  

- **Signatures:**  
  - ML-DSA-44  
  - ML-DSA-65  
  - ML-DSA-87  

---

###  Hybrid Cryptography (NEW)

Supports **hybrid key exchange** combining:

- Classical cryptography: **X25519**
- Post-quantum cryptography: **ML-KEM**

 This is the **recommended real-world migration approach**.

- HKDF-based secret derivation
- Domain separation
- Zeroized secrets

---

###  Secure Session Derivation (NEW)

- `SecureSession` abstraction
- Derive symmetric keys from shared secrets
- Client/server key separation

---

### ️ Backends

- **Mock backend (default)**  
  - No native dependencies  
  - Fast CI/testing  

- **liboqs backend**  
  - Real PQC operations  
  - Production-like testing  

---

## Install

### 1. Add the crate

- **Default (mock backend for CI/dev):**
  ```toml
  oqs-safe = { version = "0.4", features = ["ml_kem_768", "ml_dsa_44"] }

- **Production (real liboqs backend):**

  oqs-safe = { version = "0.4", default-features = false, features = ["liboqs", "ml_kem_768", "ml_dsa_44"] }

### 2. (Prod only) Install libOQS

```rust
  git clone https://github.com/open-quantum-safe/liboqs
  cd liboqs && mkdir build && cd build
  cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DOQS_DIST_BUILD=ON -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX="$HOME/.local/liboqs" ..
  ninja && ninja install
```
- **Make oqs-safe find and load liboqs:**
```rust  
  export LIBOQS_DIR="$HOME/.local/liboqs"
```
- **macOS: ensure runtime linking finds liboqs.dylib:**
```rust  
  export DYLD_FALLBACK_LIBRARY_PATH="$HOME/.local/liboqs/lib:${DYLD_FALLBACK_LIBRARY_PATH}"
```
- **Optional: pkg-config:**
```rust
  export PKG_CONFIG_PATH="$HOME/.local/liboqs/lib/pkgconfig:${PKG_CONFIG_PATH}"
```
## Quickstart
### ML-KEM Key Exchange
```rust
   use oqs_safe::kem::{Kem, KemAlgorithm, KemInstance};

   let kem = KemInstance::new(KemAlgorithm::MlKem768);
   let (pk, sk) = kem.keypair()?;
   let (ct, ss1) = kem.encapsulate(&pk)?;
   let ss2 = kem.decapsulate(&ct, &sk)?;
   assert_eq!(ss1.len(), ss2.len());
```
### ML-DSA Sign & Verify
```rust
  use oqs_safe::sig::{SigAlgorithm, SigInstance, SignatureScheme};
  let sig = SigInstance::new(SigAlgorithm::MlDsa44);
  let (pk, sk) = sig.keypair()?;
  let msg = b"hello pqc";
  let signature = sig.sign(&sk, msg)?;
  sig.verify(&pk, msg, &signature)?;
```
### Hybrid X25519 + ML-KEM

```rust
cargo run --example hybrid_x25519_mlkem
```
- **This demonstrates:**
- **Classical X25519 key exchange**
- **ML-KEM encapsulation**
- **HKDF-based hybrid secret derivation**

### Derive session keys

   use oqs_safe::session::SecureSession;

   let session = SecureSession::new(shared_secret);

   let (client_key, server_key) = session.derive_client_server_keys(); 
---
## Examples

- **Mock backend:**
```rust
cargo run --example kem_roundtrip --features "ml_kem_768"
cargo run --example dsa_sign_verify --features "ml_dsa_44"
cargo run --example hybrid_x25519_mlkem
```

- **Real backend:**
```rust
cargo run --example kem_roundtrip --features "liboqs,ml_kem_768"
cargo run --example dsa_sign_verify --features "liboqs,ml_dsa_44"
cargo run --example hybrid_x25519_mlkem --features "liboqs"
```
---
## Testing
```rust
cargo test
cargo test --features "liboqs"
```
---
## Security Notes
- **Always derive keys via HKDF before use**
- **Bind identities and transcripts in real protocols**
- **Hybrid crypto does NOT replace authentication**
- **Secrets are zeroized on drop**
- **Avoid logging or serializing secrets**
- **This crate is not formally audited**
---
## Migration Guidance
- **For real-world deployments:**
- **Use hybrid X25519 + ML-KEM**
- **Do NOT rely on PQC-only yet**
- **Add authentication (TLS, signatures, etc.)**
- **Protect against downgrade attacks** 
---
## MSRV & License

- **MSRV: Rust 1.70+:**
---
## License: MIT OR Apache-2.0
---
## Acknowledgements
- **Built on [libOQS] from the Open Quantum Safe project**
- **Designed for real-world PQC migration scenarios**
---
## Contributing
- **Contributions welcome for:**
- **Additional PQC algorithms**
- **TLS-style handshake patterns**
- **HSM / enclave integrations**
- **Blockchain / wallet integrations**
---
