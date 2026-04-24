#![deny(unsafe_op_in_unsafe_fn)]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod error;
pub mod hybrid;
pub mod kem;
pub mod sig;

#[cfg(feature = "liboqs")]
pub(crate) mod ffi;

pub use error::OqsError;
