//! composefs images: an app's file tree as a small EROFS image whose
//! files point into the shared object store (spec section 5, steps 4 and 5).
//!
//! The tree is read by our own code, as untrusted input, and written as a
//! composefs dump file with fixed ownership (0:0), fixed times (0) and no
//! setuid/setgid bits, so the same files always give the same image. The
//! image itself is made by `mkcomposefs` and mounted by `mount.composefs`
//! with the image digest and fs-verity on every file required.

mod tree;
pub use tree::{Node, Tree};

#[cfg(target_os = "linux")]
mod image;
#[cfg(target_os = "linux")]
pub use image::{Error, build_image, mount, tool};
