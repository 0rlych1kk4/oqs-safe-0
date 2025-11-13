#![deny(unsafe_op_in_unsafe_fn)]
#![cfg_attr(feature = "strict", deny(warnings, clippy::all, clippy::pedantic))]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(all(not(feature = "liboqs"), not(feature = "mock")))]
compile_error!("No backend selected. Enable `features=[\"liboqs\"]` for real crypto or `mock` for CI/examples.");

#[cfg(all(feature = "mock", not(debug_assertions)))]
#[cfg(not(allow_mock_release))]
compile_error!("`mock` backend in release build. Use RUSTFLAGS='--cfg allow_mock_release' if you truly intend to ship a mock.");

pub mod error;
pub mod kem;
pub mod sig;

#[cfg(feature = "liboqs")]
pub(crate) mod ffi;

#[cfg(feature = "selftest_at_startup")]
mod selftest;

#[cfg(feature = "selftest_at_startup")]
#[ctor::ctor]
fn _oqs_safe_selftest() {
    let _ = std::panic::catch_unwind(|| selftest::check());
}

pub use error::OqsError;
