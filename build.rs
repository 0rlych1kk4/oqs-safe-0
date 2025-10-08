// build.rs — robust liboqs discovery via LIBOQS_DIR or pkg-config

use std::env;

fn main() {
    // Prefer explicit LIBOQS_DIR if provided (bypasses pkg-config).
    if let Ok(dir) = env::var("LIBOQS_DIR") {
        println!("cargo:rustc-link-search=native={}/lib", dir);
        println!("cargo:rustc-link-lib=dylib=oqs");
        println!("cargo:rerun-if-env-changed=LIBOQS_DIR");
        return;
    }

    // Otherwise rely on pkg-config (respects PKG_CONFIG_PATH).
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");
    match pkg_config::Config::new()
        .print_system_libs(true)
        .cargo_metadata(true)
        .probe("liboqs")
    {
        Ok(_lib) => {
            // Link flags already emitted via cargo_metadata(true).
            // (Version checks removed for compatibility across pkg-config crate versions.)
        }
        Err(e) => {
            // If the real backend is requested, fail with clear instructions.
            if env::var("CARGO_FEATURE_LIBOQS").is_ok() {
                panic!(
"liboqs not found via pkg-config:
{e}

Hints:
- Build and install liboqs:
    git clone https://github.com/open-quantum-safe/liboqs
    cd liboqs && mkdir build && cd build
    cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DOQS_DIST_BUILD=ON -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=\"$HOME/.local/liboqs\" ..
    ninja && ninja install
- Then set one of:
    export LIBOQS_DIR=\"$HOME/.local/liboqs\"
    # or
    export PKG_CONFIG_PATH=\"$HOME/.local/liboqs/lib/pkgconfig:$PKG_CONFIG_PATH\"
"
                );
            }
        }
    }
}
