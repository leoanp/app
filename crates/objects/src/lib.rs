//! Content-addressed object store with fs-verity (spec section 5).
//!
//! [`digest`] computes fs-verity digests in pure Rust (any platform); the
//! [`store`] itself needs Linux and a filesystem with fs-verity (ext4 with
//! the `verity` feature, or btrfs).

pub mod digest;
#[cfg(target_os = "linux")]
pub mod store;

pub use digest::Digest;
#[cfg(target_os = "linux")]
pub use store::{Error, Store, seal};

#[cfg(all(test, target_os = "linux"))]
mod store_tests;
