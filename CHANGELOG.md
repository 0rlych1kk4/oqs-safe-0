# Changelog

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
