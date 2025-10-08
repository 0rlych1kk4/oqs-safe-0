# oqs-safe

Safe, minimal Rust wrapper over [libOQS] for post-quantum KEM/SIG:
- **Kyber / ML-KEM-768**
- **Dilithium / ML-DSA-44**

Works with **current and legacy libOQS names** and supports a **mock fallback** for CI without libOQS.

[libOQS]: https://openquantumsafe.org/

## Features

- `liboqs` — enable real liboqs FFI (default: off)
- KEM: `kyber768` (alias: `ml_kem_768`)
- SIG: `dilithium2` (alias: `ml_dsa_44`)

## Quickstart

```bash
# Install/build liboqs (if not using your system package):
git clone https://github.com/open-quantum-safe/liboqs
cd liboqs && mkdir build && cd build
cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DOQS_DIST_BUILD=ON -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX="$HOME/.local/liboqs" ..
ninja && ninja install

export PKG_CONFIG_PATH="$HOME/.local/liboqs/lib/pkgconfig:$PKG_CONFIG_PATH"
export DYLD_LIBRARY_PATH="$HOME/.local/liboqs/lib:$DYLD_LIBRARY_PATH"  # macOS

# KEM
cargo run --example kem_roundtrip --no-default-features --features liboqs,kyber768

# SIG
cargo run --example dsa_sign_verify --no-default-features --features liboqs,dilithium2

# Mock mode (no liboqs)
cargo test --features kyber768,dilithium2

# MSRV
Rust 1.70+.

# License
Dual-licensed under MIT or Apache-2.0.
