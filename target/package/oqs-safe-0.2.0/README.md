# oqs-safe

Stable, minimal **safe Rust wrapper** over [libOQS] for PQC:
- **KEM:** ML-KEM-768 (Kyber768)
- **SIG:** ML-DSA-44 (Dilithium2)

>  Zeroizes secrets  Safe newtypes  Compile-time guardrails (no mock in release)  Resilient to liboqs naming drift (“ML-KEM-768” ↔ “Kyber768”, “ML-DSA-44” ↔ “Dilithium2”)

## Install libOQS

```bash
git clone https://github.com/open-quantum-safe/liboqs
cd liboqs && mkdir build && cd build
cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DOQS_DIST_BUILD=ON -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX="$HOME/.local/liboqs" ..
ninja && ninja install
export LIBOQS_DIR="$HOME/.local/liboqs"
# macOS
export DYLD_FALLBACK_LIBRARY_PATH="$HOME/.local/liboqs/lib:${DYLD_FALLBACK_LIBRARY_PATH}"
# pkg-config (optional)
export PKG_CONFIG_PATH="$HOME/.local/liboqs/lib/pkgconfig:${PKG_CONFIG_PATH}"
