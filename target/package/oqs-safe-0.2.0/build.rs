// build.rs — robust liboqs discovery via LIBOQS_DIR or pkg-config

use std::env;

fn main() {
    println!("cargo:rerun-if-env-changed=LIBOQS_DIR");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");
    println!("cargo:rustc-cfg=oqs_build_script");
    println!("cargo:links=oqs");

    let wants_liboqs = env::var_os("CARGO_FEATURE_LIBOQS").is_some();

    // Prefer explicit LIBOQS_DIR if provided (bypasses pkg-config).
    if let Ok(dir) = env::var("LIBOQS_DIR") {
        if wants_liboqs {
            println!("cargo:rustc-link-search=native={}/lib", dir);
            println!("cargo:rustc-link-lib=dylib=oqs");
        }
        return;
    }

    // Otherwise rely on pkg-config (respects PKG_CONFIG_PATH).
    match pkg_config::Config::new()
        .print_system_libs(true)
        .cargo_metadata(true)
        .probe("liboqs")
    {
        Ok(_lib) => { /* Link flags already emitted */ }
        Err(e) if wants_liboqs => {
            panic!(
"liboqs not found via pkg-config:

{e}

Build hints:
  git clone https://github.com/open-quantum-safe/liboqs
  cd liboqs && mkdir build && cd build
  cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DOQS_DIST_BUILD=ON -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=\"$HOME/.local/liboqs\" ..
  ninja && ninja install

Then set one of:
  export LIBOQS_DIR=\"$HOME/.local/liboqs\"
  # or
  export PKG_CONFIG_PATH=\"$HOME/.local/liboqs/lib/pkgconfig:$PKG_CONFIG_PATH\"
"
            );
        }
        Err(_) => { /* mock build OK */ }
    }
}
