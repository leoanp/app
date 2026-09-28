//! composefs tests on a real kernel: building, reproducibility, mounting,
//! and tamper detection. They need root (mounting) and a filesystem with
//! fs-verity, so they are ignored by default; run tests/vm/storage-tests.sh.

#![cfg(target_os = "linux")]
// Test code: a panic is how a test fails.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::io::Write;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;

use app_composefs::{Node, Tree, build_image, mount};
use app_objects::Store;

const REASON: &str = "needs root and fs-verity; run tests/vm/storage-tests.sh";

struct Env {
    dir: tempfile::TempDir,
    store: Store,
}

impl Env {
    fn new() -> Env {
        let base = std::env::var("APP_TEST_DIR").unwrap_or_else(|_| "/var/tmp".into());
        let dir = tempfile::tempdir_in(base).unwrap();
        let store = Store::open(dir.path().join("store")).unwrap();
        Env { dir, store }
    }

    fn path(&self, p: &str) -> PathBuf {
        self.dir.path().join(p)
    }

    /// A small app: a program, a bundled library, an empty file, a symlink, an odd name.
    fn sample(&self, name: &str) -> PathBuf {
        let src = self.path(name);
        fs::create_dir_all(src.join("bin")).unwrap();
        fs::create_dir_all(src.join("lib")).unwrap();
        fs::create_dir_all(src.join("share/odd name")).unwrap();
        fs::write(src.join("bin/app"), b"#!/bin/sh\necho hello\n").unwrap();
        fs::set_permissions(src.join("bin/app"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(src.join("lib/libfoo.so.1"), vec![0x42; 20_000]).unwrap();
        fs::write(src.join("share/empty"), b"").unwrap();
        fs::write(src.join("share/odd name/f=1"), b"x").unwrap();
        symlink("libfoo.so.1", src.join("lib/libfoo.so")).unwrap();
        src
    }

    fn mountpoint(&self, name: &str) -> PathBuf {
        let m = self.path(name);
        fs::create_dir_all(&m).unwrap();
        m
    }
}

struct Mounted(PathBuf);

impl Drop for Mounted {
    fn drop(&mut self) {
        let _ = Command::new("umount")
            .arg(&self.0)
            .stderr(std::process::Stdio::null())
            .status();
    }
}

fn is_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .any(|l| l.starts_with("Uid:") && l.split_whitespace().nth(1) == Some("0"))
}

#[test]
#[ignore = "needs root and fs-verity; run tests/vm/storage-tests.sh"]
fn build_mount_and_read_back() {
    assert!(is_root(), "{REASON}");
    let env = Env::new();
    let src = env.sample("src");
    let tree = Tree::import_dir(&env.store, &src).unwrap();
    let image = env.path("app.cfs");
    let digest = build_image(&tree, &image).unwrap();
    let mnt = env.mountpoint("mnt");
    mount(&image, &env.store.objects_dir(), &mnt, &digest).unwrap();
    let _guard = Mounted(mnt.clone());

    assert_eq!(
        fs::read(mnt.join("bin/app")).unwrap(),
        b"#!/bin/sh\necho hello\n"
    );
    assert_eq!(
        fs::read(mnt.join("lib/libfoo.so.1")).unwrap(),
        vec![0x42; 20_000]
    );
    assert_eq!(fs::read(mnt.join("share/empty")).unwrap(), b"");
    assert_eq!(fs::read(mnt.join("share/odd name/f=1")).unwrap(), b"x");
    assert_eq!(
        fs::read_link(mnt.join("lib/libfoo.so")).unwrap(),
        Path::new("libfoo.so.1")
    );
    let meta = fs::metadata(mnt.join("bin/app")).unwrap();
    assert_eq!(meta.permissions().mode() & 0o7777, 0o755);
    use std::os::unix::fs::MetadataExt;
    assert_eq!((meta.uid(), meta.gid(), meta.mtime()), (0, 0, 0));
    // Read-only.
    assert!(fs::write(mnt.join("bin/new"), b"x").is_err());
    let running = Command::new(mnt.join("bin/app")).output().unwrap();
    assert_eq!(running.stdout, b"hello\n");
}

#[test]
#[ignore = "needs root and fs-verity; run tests/vm/storage-tests.sh"]
fn same_files_give_the_same_image() {
    assert!(is_root(), "{REASON}");
    let env = Env::new();
    let a = env.sample("a");
    let b = env.sample("b");
    // Different owners and times on the second copy must not matter.
    std::os::unix::fs::chown(b.join("bin/app"), Some(1234), Some(1234)).unwrap();
    Command::new("touch")
        .args(["-d", "2001-01-01"])
        .arg(b.join("lib/libfoo.so.1"))
        .status()
        .unwrap();
    let da = build_image(
        &Tree::import_dir(&env.store, &a).unwrap(),
        &env.path("a.cfs"),
    )
    .unwrap();
    let db = build_image(
        &Tree::import_dir(&env.store, &b).unwrap(),
        &env.path("b.cfs"),
    )
    .unwrap();
    assert_eq!(da, db);
    assert_eq!(
        fs::read(env.path("a.cfs")).unwrap(),
        fs::read(env.path("b.cfs")).unwrap()
    );
}

#[test]
#[ignore = "needs root and fs-verity; run tests/vm/storage-tests.sh"]
fn setuid_is_dropped_and_special_files_refused() {
    assert!(is_root(), "{REASON}");
    let env = Env::new();
    let src = env.sample("src");
    fs::set_permissions(src.join("bin/app"), fs::Permissions::from_mode(0o4755)).unwrap();
    let tree = Tree::import_dir(&env.store, &src).unwrap();
    assert!(matches!(
        tree.entries[&b"bin/app"[..]],
        Node::File { mode: 0o755, .. }
    ));

    let fifo = src.join("pipe");
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    assert!(matches!(
        Tree::import_dir(&env.store, &src),
        Err(app_composefs::Error::SpecialFile(_))
    ));
    fs::remove_file(&fifo).unwrap();
    assert!(
        Command::new("mknod")
            .arg(src.join("null"))
            .args(["c", "1", "3"])
            .status()
            .unwrap()
            .success()
    );
    assert!(matches!(
        Tree::import_dir(&env.store, &src),
        Err(app_composefs::Error::SpecialFile(_))
    ));
}

#[test]
#[ignore = "needs root and fs-verity; run tests/vm/storage-tests.sh"]
fn wrong_image_digest_does_not_mount() {
    assert!(is_root(), "{REASON}");
    let env = Env::new();
    let tree = Tree::import_dir(&env.store, &env.sample("src")).unwrap();
    let image = env.path("app.cfs");
    build_image(&tree, &image).unwrap();
    let other = build_image(&Tree::new(), &env.path("empty.cfs")).unwrap();
    let mnt = env.mountpoint("mnt");
    let result = mount(&image, &env.store.objects_dir(), &mnt, &other);
    let _guard = Mounted(mnt);
    assert!(
        result.is_err(),
        "a mismatching image digest must refuse the mount"
    );
}

#[test]
#[ignore = "needs root and fs-verity; run tests/vm/storage-tests.sh"]
fn changed_image_does_not_mount() {
    assert!(is_root(), "{REASON}");
    let env = Env::new();
    let tree = Tree::import_dir(&env.store, &env.sample("src")).unwrap();
    let image = env.path("app.cfs");
    let digest = build_image(&tree, &image).unwrap();
    // Copy the image, flip one byte in its metadata, and try it with the original digest.
    let mut bytes = fs::read(&image).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    let evil = env.path("evil.cfs");
    fs::File::create(&evil).unwrap().write_all(&bytes).unwrap();
    app_objects::seal(&evil).unwrap();
    let mnt = env.mountpoint("mnt");
    let result = mount(&evil, &env.store.objects_dir(), &mnt, &digest);
    let _guard = Mounted(mnt);
    assert!(result.is_err(), "a changed image must refuse the mount");
}

/// The kernel checks every file on every read: a swapped object gives a read error.
#[test]
#[ignore = "needs root and fs-verity; run tests/vm/storage-tests.sh"]
fn changed_file_gives_read_error() {
    assert!(is_root(), "{REASON}");
    let env = Env::new();
    let tree = Tree::import_dir(&env.store, &env.sample("src")).unwrap();
    let image = env.path("app.cfs");
    let digest = build_image(&tree, &image).unwrap();
    let Node::File {
        digest: Some(lib), ..
    } = &tree.entries[&b"lib/libfoo.so.1"[..]]
    else {
        panic!()
    };
    let Node::File {
        digest: Some(app), ..
    } = &tree.entries[&b"bin/app"[..]]
    else {
        panic!()
    };

    // Library: replaced by different content with its own valid fs-verity.
    let lib_path = env.store.path(lib);
    fs::remove_file(&lib_path).unwrap();
    fs::write(&lib_path, vec![0x43; 20_000]).unwrap();
    app_objects::seal(&lib_path).unwrap();
    // Program: replaced by a file without fs-verity at all.
    let app_path = env.store.path(app);
    fs::remove_file(&app_path).unwrap();
    fs::write(&app_path, b"#!/bin/sh\necho evil\n").unwrap();

    let mnt = env.mountpoint("mnt");
    mount(&image, &env.store.objects_dir(), &mnt, &digest).unwrap();
    let _guard = Mounted(mnt.clone());
    let lib_read = fs::read(mnt.join("lib/libfoo.so.1"));
    let app_read = fs::read(mnt.join("bin/app"));
    assert!(
        lib_read.is_err(),
        "swapped library must not be readable: {lib_read:?}"
    );
    assert!(
        app_read.is_err(),
        "unprotected program must not be readable: {app_read:?}"
    );
    // Untouched files still read fine.
    assert_eq!(fs::read(mnt.join("share/odd name/f=1")).unwrap(), b"x");
}
