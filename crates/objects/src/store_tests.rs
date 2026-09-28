//! Store tests. They need a filesystem with fs-verity, so they are ignored
//! by default; `tests/vm/storage-tests.sh` runs them in the VM with
//! `APP_TEST_DIR` on btrfs.

// Test code: a panic is how a test fails.
#![allow(clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::fs;
use std::io::Write;

use crate::{Store, digest};

fn test_dir() -> tempfile::TempDir {
    let base = std::env::var("APP_TEST_DIR").unwrap_or_else(|_| "/var/tmp".into());
    tempfile::tempdir_in(base).unwrap()
}

#[test]
#[ignore = "needs a filesystem with fs-verity; run tests/vm/storage-tests.sh"]
fn imports_once_and_names_by_digest() {
    let dir = test_dir();
    let store = Store::open(dir.path().join("store")).unwrap();
    let data = vec![7u8; 10_000];
    let a = store.import(&data[..]).unwrap();
    let b = store.import(&data[..]).unwrap();
    assert_eq!(a, b);
    assert_eq!(a, digest::compute(&data[..]).unwrap());
    assert!(store.verify(&a).unwrap());
    assert_eq!(fs::read(store.path(&a)).unwrap(), data);
    let objects: Vec<_> = walk(&store.objects_dir());
    assert_eq!(objects.len(), 1, "identical content is stored once");
}

#[test]
#[ignore = "needs a filesystem with fs-verity; run tests/vm/storage-tests.sh"]
fn stored_objects_cannot_be_changed() {
    let dir = test_dir();
    let store = Store::open(dir.path().join("store")).unwrap();
    let d = store.import(&b"sealed"[..]).unwrap();
    // The kernel refuses to open a verity file for writing.
    let opened = fs::OpenOptions::new().write(true).open(store.path(&d));
    assert!(
        opened.is_err(),
        "writing to a verity-protected object must fail"
    );
}

#[test]
#[ignore = "needs a filesystem with fs-verity; run tests/vm/storage-tests.sh"]
fn damaged_object_is_detected_and_repaired() {
    let dir = test_dir();
    let store = Store::open(dir.path().join("store")).unwrap();
    let d = store.import(&b"original"[..]).unwrap();
    // Swap in a different, unprotected file under the same name.
    let path = store.path(&d);
    fs::remove_file(&path).unwrap();
    fs::File::create(&path)
        .unwrap()
        .write_all(b"tampered")
        .unwrap();
    assert!(!store.verify(&d).unwrap());
    assert_eq!(store.import(&b"original"[..]).unwrap(), d);
    assert!(store.verify(&d).unwrap());
    assert_eq!(fs::read(&path).unwrap(), b"original");
}

#[test]
#[ignore = "needs a filesystem with fs-verity; run tests/vm/storage-tests.sh"]
fn gc_removes_only_unreferenced() {
    let dir = test_dir();
    let store = Store::open(dir.path().join("store")).unwrap();
    let keep = store.import(&b"keep me"[..]).unwrap();
    let drop = store.import(&b"drop me"[..]).unwrap();
    let removed = store.gc(&BTreeSet::from([keep])).unwrap();
    assert_eq!(removed, 1);
    assert!(store.verify(&keep).unwrap());
    assert!(!store.verify(&drop).unwrap());
}

#[test]
#[ignore = "needs a filesystem with fs-verity; run tests/vm/storage-tests.sh"]
fn verity_support_is_detected() {
    let dir = test_dir();
    Store::open(dir.path().join("store"))
        .unwrap()
        .check_verity_support()
        .unwrap();
    // tmpfs has no fs-verity: the store must say so, and imports must fail.
    let shm = tempfile::tempdir_in("/dev/shm").unwrap();
    let store = Store::open(shm.path().join("store")).unwrap();
    assert!(matches!(
        store.check_verity_support(),
        Err(crate::Error::VerityUnsupported(_))
    ));
    assert!(matches!(
        store.import(&b"x"[..]),
        Err(crate::Error::VerityUnsupported(_))
    ));
}

#[test]
#[ignore = "needs a filesystem with fs-verity; run tests/vm/storage-tests.sh"]
fn seal_matches_computed_digest() {
    let dir = test_dir();
    let path = dir.path().join("image");
    fs::write(&path, vec![3u8; 9000]).unwrap();
    let sealed = crate::seal(&path).unwrap();
    assert_eq!(sealed, digest::compute(&vec![3u8; 9000][..]).unwrap());
    assert_eq!(
        crate::seal(&path).unwrap(),
        sealed,
        "sealing twice is harmless"
    );
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for e in fs::read_dir(dir).unwrap().flatten() {
        if e.file_type().unwrap().is_dir() {
            out.extend(walk(&e.path()));
        } else {
            out.push(e.path());
        }
    }
    out
}

#[test]
#[ignore = "needs a filesystem with fs-verity; run tests/vm/storage-tests.sh"]
fn import_file_refuses_symlinks_and_special_files() {
    let dir = test_dir();
    let store = Store::open(dir.path().join("store")).unwrap();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink("/etc/passwd", &link).unwrap();
    assert!(
        store.import_file(&link).is_err(),
        "a symlink must not be followed"
    );
    let fifo = dir.path().join("fifo");
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    // Must return at once (a pipe opened for reading would block).
    assert!(matches!(
        store.import_file(&fifo),
        Err(crate::Error::NotRegular(_))
    ));
    assert!(matches!(
        store.import_file(dir.path()),
        Err(crate::Error::NotRegular(_))
    ));
}

/// The race the import guards against, made deterministic: the entry is
/// checked, then swapped for a symlink to an outside file before reading.
/// The pinned handle still reads the original file.
#[test]
#[ignore = "needs a filesystem with fs-verity; run tests/vm/storage-tests.sh"]
fn swapped_entry_cannot_pull_in_an_outside_file() {
    let dir = test_dir();
    let store = Store::open(dir.path().join("store")).unwrap();
    let name = std::path::Path::new("lib.so");
    let path = dir.path().join(name);
    fs::write(&path, b"the app's own file").unwrap();
    let parent = fs::File::open(dir.path()).unwrap();

    let pinned = crate::pin(&parent, name).unwrap();
    fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink("/etc/passwd", &path).unwrap();

    let file = crate::reopen_for_reading(&pinned, &path).unwrap();
    let d = store.import(file).unwrap();
    assert_eq!(fs::read(store.path(&d)).unwrap(), b"the app's own file");
    // And a fresh attempt now refuses the symlink outright.
    assert!(crate::open_regular(&parent, name).is_err());
}

/// Imports while another thread keeps starting programs. Each started
/// program briefly holds copies of this process's open files, which makes
/// the kernel refuse to seal a file ("opened for writing"). Without the
/// retry in `enable_verity`, about 1 in 5 imports failed here.
#[test]
#[ignore = "needs a filesystem with fs-verity; run tests/vm/storage-tests.sh"]
fn imports_survive_programs_started_concurrently() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    let dir = test_dir();
    let store = Store::open(dir.path().join("store")).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let spawner = {
        let stop = stop.clone();
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let _ = std::process::Command::new("/usr/bin/true").status();
            }
        })
    };
    let failures: Vec<String> = (0..300u32)
        .filter_map(|i| {
            store
                .import(&i.to_le_bytes()[..])
                .err()
                .map(|e| e.to_string())
        })
        .collect();
    stop.store(true, Ordering::Relaxed);
    spawner.join().unwrap();
    assert!(
        failures.is_empty(),
        "{} imports failed, first: {}",
        failures.len(),
        failures[0]
    );
}
