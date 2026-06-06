# Changelog

# oqs-safe v0.7.0

## Added
- Added authenticated hybrid handshake example.
- Added transcript authentication pattern using ML-DSA.
- Added hybrid X25519 + ML-KEM session derivation example with transcript binding.
- Added directional session key derivation using HKDF.

## Improved
- Clarified that hybrid key exchange does not replace identity authentication.
- Improved practical PQC migration guidance through a complete handshake example.

## Security
- Demonstrates transcript signing and verification.
- Reinforces authentication on top of hybrid key exchange.
- Notes that mock ML-KEM mode does not produce matching shared secrets.

## [0.6.1] - 2026-05-17

### Fixed

- Updated README release wording for crates.io.
- Corrected README references from v0.5.0 to the current v0.6.x release line.
- Refreshed install examples to use `version = "0.6"`.

### Notes

- This is a documentation patch release for crates.io package metadata and README display.
- No cryptographic API changes from v0.6.0.

## [0.6.0] - 2026-05-17

### Added

- Added authenticated hybrid handshake transcript binding.
- Added optional handshake message serialization via the `serialization` feature.
- Added optional AEAD helpers for `SecureSession` via the `aead` feature.
- Added `ClientHello::to_bytes()` and `ClientHello::from_bytes()`.
- Added `ServerHello::to_bytes()` and `ServerHello::from_bytes()`.
- Added `SecureSession::encrypt()` and `SecureSession::decrypt()` using ChaCha20Poly1305.
- Added transcript-binding and AEAD failure-mode tests.

### Security

- Hybrid session derivation is now bound to the selected KEM algorithm, client handshake message, server handshake message, and KEM ciphertext.
- AEAD helpers derive encryption keys from the session master secret using HKDF with a dedicated label.

## v0.6.0 Roadmap

The next development milestone focuses on strengthening the handshake and secure-session layer before expanding algorithm coverage.

Planned improvements:

- Add authenticated handshake transcript binding.
- Add serialization support for handshake messages.
- Add AEAD helper using derived session keys.
- Expand libOQS backend documentation.
- Add optional SLH-DSA support for broader NIST-standard signature coverage.
## [0.5.1] - 2026-05-16

### Documentation
- Improved README formatting for crates.io readability.
- Fixed Markdown code fence labels for TOML, shell, text, and Rust examples.
- Added architecture documentation referencing `assets/Architecture.png`.
- Expanded example commands for:
  - `hybrid_handshake`
  - `hkdf_handshake`
  - `hybrid_x25519_mlkem`
  - `kem_roundtrip`
  - `dsa_sign_verify`
- Clarified libOQS installation steps.
- Clarified macOS runtime linking instructions for `liboqs.dylib`.
- Clarified `pkg-config` setup for libOQS.
- Clarified security notes and production-use guidance.
- Improved crate-level documentation for hybrid examples.

### Fixed
- Fixed rustdoc warning caused by an empty Rust code block in `src/lib.rs`.
- Replaced the hybrid example command block from a Rust `no_run` block to a `text` block.
- Ensured documentation builds cleanly with `cargo doc --no-deps`.

### Notes
- No public API changes.
- No dependency changes.
- No behavior changes.
- Fully compatible with `0.5.0`.

## [0.5.0] - 2026-05-10

### Added
- Added `handshake` module.
- Added `HybridClient` and `HybridServer`.
- Added TLS-style hybrid handshake flow:
  - client hello
  - server response
  - session derivation
- Added `examples/hybrid_handshake.rs`.
- Added handshake tests.

### Security
- Hybrid handshake derives session material from both:
  - X25519 classical shared secret
  - ML-KEM post-quantum shared secret
- Session keys are derived using HKDF through `SecureSession`.
- The default mock backend is for CI/dev only and is not suitable for real cryptographic use.
- Real cryptographic use requires the `liboqs` feature.
- The handshake abstraction does not replace protocol-level authentication, transcript binding, identity verification, or downgrade protection.

## [0.4.0] - 2026-04-24

### Added
- Full ML-KEM support (512, 768, 1024)
- Full ML-DSA support (44, 65, 87)
- Hybrid key exchange (X25519 + ML-KEM)
- HKDF-based hybrid secret derivation
- SecureSession helper for key derivation
- New examples:
  - hybrid_x25519_mlkem.rs
  - secure session usage patterns

### Changed
- Upgraded hybrid combiner from SHA256 to HKDF-based design

### Security
- Improved domain separation in hybrid derivation
- Explicit zeroization of hybrid secrets

## 0.2.5 – 2025-11-13

- Hardening: enabled `#![deny(unsafe_op_in_unsafe_fn)]` for stricter safety guarantees around any future unsafe usage.
- Metadata: updated descriptions/keywords to clarify support for NIST ML-KEM and ML-DSA families.
- Documentation: added production-usage notes and clarified backend (mock vs liboqs) expectations.
- Internal: zero API changes; fully backward compatible.

## 0.2.4 – 2025-10-26

- Release stabilization and cleanup before wider CI adoption.
- Improved MSRV metadata.
- Updated examples and docs.rs feature flags.

## 0.2.3 – 2025-10-18

- Tightened mock-mode detection in release builds to prevent accidental shipping of mock crypto.
- Added guardrails requiring explicit allowance via `RUSTFLAGS='--cfg allow_mock_release'`.

## 0.2.2 – 2025-10-10

- Updated liboqs compatibility layer to handle upstream naming changes.
- Improved build.rs detection and fallback for link modes.

## 0.2.1 – 2025-10-01

- Documentation cleanup on KEM/SIG usage.
- Expanded examples and added hex encoding helpers in dev-dependencies.

## 0.2.0 – 2025-09-20

- Major internal cleanup before publishing stable series.
- Separated `kem`, `sig`, and `error` modules with safer type boundaries.
- Added feature-gated algorithms: `kyber768`, `kyber1024`, `dilithium3`, `dilithium5`.
- Introduced `strict` build mode and `selftest_at_startup` feature.

## 0.1.0 – 2025-09-01

- Initial release: Kyber768 (ML-KEM-768) and Dilithium2 (ML-DSA-44) via liboqs, with mock fallback.
- Generic factory + legacy name fallbacks.
- Safe accessors; zeroize on secrets; examples; CI.
