//! The shared object store (spec section 5, "Storage on the device", steps
//! 2, 3 and 6): every file stored once, named by its fs-verity digest,
//! with fs-verity enabled so the kernel checks it on every read.
//!
//! Layout (composefs): `<root>/objects/ab/cdef…`, plus `<root>/tmp/` for
//! imports in progress. The root is closed to everyone but its owner
//! (root): apps read their files only through their composefs mounts.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

use std::os::fd::{AsFd, AsRawFd, OwnedFd};

use rustix::fs::{CWD, FileType, Mode, OFlags, fstat, openat};

use composefs_ioctls::fsverity::{EnableVerityError, fs_ioc_enable_verity, fs_ioc_measure_verity};

use crate::digest::{self, BLOCK_SIZE, Digest};

const SHA256: u8 = 1;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{context}: {source}")]
    Io { context: String, source: io::Error },
    #[error("the filesystem holding {0} does not support fs-verity")]
    VerityUnsupported(PathBuf),
    #[error("fs-verity failed on {path}: {message}")]
    Verity { path: PathBuf, message: String },
    #[error("`{0}` is not a regular file")]
    NotRegular(PathBuf),
    #[error("stored data does not match: computed {computed}, kernel measured {measured}")]
    Mismatch { computed: Digest, measured: Digest },
}

fn io_err(context: impl std::fmt::Display) -> impl FnOnce(io::Error) -> Error {
    move |source| Error::Io {
        context: context.to_string(),
        source,
    }
}

/// A content-addressed store of fs-verity-protected files.
#[derive(Clone, Debug)]
pub struct Store {
    root: PathBuf,
}

impl Store {
    /// Opens the store at `root`, creating it (mode 0700) if needed.
    pub fn open(root: impl Into<PathBuf>) -> Result<Store, Error> {
        let root = root.into();
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        for dir in [root.clone(), root.join("objects"), root.join("tmp")] {
            builder.create(&dir).map_err(io_err(dir.display()))?;
        }
        Ok(Store { root })
    }

    /// The folder composefs mounts use as their `basedir`.
    pub fn objects_dir(&self) -> PathBuf {
        self.root.join("objects")
    }

    /// Where the object with this digest lives.
    pub fn path(&self, d: &Digest) -> PathBuf {
        self.objects_dir().join(d.object_path())
    }

    /// Fails unless the store's filesystem can enable fs-verity. The
    /// runtime refuses to install or run apps otherwise (fail closed).
    pub fn check_verity_support(&self) -> Result<(), Error> {
        let tmp = self.root.join("tmp");
        let mut f = tempfile::NamedTempFile::new_in(&tmp).map_err(io_err(tmp.display()))?;
        f.write_all(b"verity probe").map_err(io_err("probe"))?;
        let path = f.into_temp_path();
        let file = File::open(&path).map_err(io_err("probe"))?;
        match enable_verity(&file) {
            Ok(()) => Ok(()),
            Err(EnableVerityError::FilesystemNotSupported) => {
                Err(Error::VerityUnsupported(self.root.clone()))
            }
            Err(e) => Err(Error::Verity {
                path: self.root.clone(),
                message: e.to_string(),
            }),
        }
    }

    /// Copies a regular file into the store and returns its digest. A file
    /// already stored (by any app) is not stored again. `src` itself must
    /// not be a symlink (see [`open_regular`]).
    pub fn import_file(&self, src: &Path) -> Result<Digest, Error> {
        self.import(open_regular(CWD, src)?)
    }

    /// Stores everything `reader` yields and returns its digest.
    pub fn import(&self, reader: impl Read) -> Result<Digest, Error> {
        let tmp_dir = self.root.join("tmp");
        let mut tmp = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o644))
            .tempfile_in(&tmp_dir)
            .map_err(io_err(tmp_dir.display()))?;
        // One pass: hash while copying.
        let computed = digest::compute(Tee {
            inner: reader,
            copy: tmp.as_file_mut(),
        })
        .map_err(io_err("copying into the store"))?;
        tmp.as_file().sync_all().map_err(io_err("syncing"))?;

        if self.verify(&computed)? {
            return Ok(computed); // already stored and intact
        }
        // fs-verity needs the file closed for writing.
        let tmp_path = tmp.into_temp_path();
        let file = File::open(&tmp_path).map_err(io_err("reopening"))?;
        match enable_verity(&file) {
            Ok(()) => {}
            Err(EnableVerityError::FilesystemNotSupported) => {
                return Err(Error::VerityUnsupported(self.root.clone()));
            }
            Err(e) => {
                return Err(Error::Verity {
                    path: tmp_path.to_path_buf(),
                    message: e.to_string(),
                });
            }
        }
        let measured = measure(&file, &tmp_path)?;
        if measured != computed {
            return Err(Error::Mismatch { computed, measured });
        }
        let dest = self.path(&computed);
        if let Some(parent) = dest.parent() {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .map_err(io_err(parent.display()))?;
        }
        // Atomic; replaces a damaged copy if one was there.
        tmp_path.persist(&dest).map_err(|e| Error::Io {
            context: dest.display().to_string(),
            source: e.error,
        })?;
        Ok(computed)
    }

    /// Whether the object is present, has fs-verity enabled, and the kernel
    /// measures exactly this digest.
    pub fn verify(&self, d: &Digest) -> Result<bool, Error> {
        let path = self.path(d);
        let file = match OpenOptions::new().read(true).open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(e) => {
                return Err(Error::Io {
                    context: path.display().to_string(),
                    source: e,
                });
            }
        };
        Ok(fs_ioc_measure_verity::<32>(&file, SHA256).is_ok_and(|m| Digest(m) == *d))
    }

    /// Deletes every object not in `keep`, and leftovers of interrupted
    /// imports. Returns how many objects were deleted.
    pub fn gc(&self, keep: &BTreeSet<Digest>) -> Result<u64, Error> {
        let mut removed = 0;
        let objects = self.objects_dir();
        for prefix in fs::read_dir(&objects).map_err(io_err(objects.display()))? {
            let prefix = prefix.map_err(io_err(objects.display()))?;
            let prefix_name = prefix.file_name().to_string_lossy().into_owned();
            for obj in fs::read_dir(prefix.path()).map_err(io_err(prefix.path().display()))? {
                let obj = obj.map_err(io_err(prefix.path().display()))?;
                let name = format!("{prefix_name}{}", obj.file_name().to_string_lossy());
                let wanted = name.parse::<Digest>().is_ok_and(|d| keep.contains(&d));
                if !wanted {
                    fs::remove_file(obj.path()).map_err(io_err(obj.path().display()))?;
                    removed += 1;
                }
            }
            // Empty prefix folders go too; a non-empty one simply stays.
            let _ = fs::remove_dir(prefix.path());
        }
        let tmp = self.root.join("tmp");
        for entry in fs::read_dir(&tmp).map_err(io_err(tmp.display()))?.flatten() {
            let _ = fs::remove_file(entry.path());
        }
        Ok(removed)
    }
}

/// Opens `name` (relative to `dir`) for reading only if it is a regular
/// file, without following a symlink and without ever opening anything
/// else: the entry is first pinned with `O_PATH | O_NOFOLLOW`, its type is
/// checked on that handle, and only then is exactly that file reopened for
/// reading. A file swapped for a symlink or a device while this runs can
/// therefore never be read in its place.
pub fn open_regular(dir: impl AsFd, name: &Path) -> Result<File, Error> {
    let pinned = pin(dir, name)?;
    let st = fstat(&pinned).map_err(|e| io_err(name.display())(e.into()))?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        return Err(Error::NotRegular(name.to_owned()));
    }
    reopen_for_reading(&pinned, name)
}

/// Opens an entry as a bare handle (`O_PATH`), never following a final symlink.
pub fn pin(dir: impl AsFd, name: &Path) -> Result<OwnedFd, Error> {
    openat(
        dir,
        name,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| io_err(name.display())(e.into()))
}

/// Opens exactly the file behind a pinned handle for reading.
pub fn reopen_for_reading(pinned: &OwnedFd, name: &Path) -> Result<File, Error> {
    let magic = format!("/proc/self/fd/{}", pinned.as_raw_fd());
    let fd = rustix::fs::open(&magic, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
        .map_err(|e| io_err(name.display())(e.into()))?;
    let (a, b) = (
        fstat(pinned).map_err(|e| io_err(name.display())(e.into()))?,
        fstat(&fd).map_err(|e| io_err(name.display())(e.into()))?,
    );
    if (a.st_dev, a.st_ino) != (b.st_dev, b.st_ino) {
        return Err(Error::NotRegular(name.to_owned()));
    }
    Ok(File::from(fd))
}

/// Enables fs-verity, retrying briefly while the file is "busy". The kernel
/// refuses while any descriptor holds the file open for writing. When this
/// process starts another program, the child briefly holds copies of our
/// descriptors (closed again as that program starts), which can collide
/// with an import running in another thread.
fn enable_verity(file: &File) -> Result<(), EnableVerityError> {
    const TRIES: u32 = 100;
    for _ in 1..TRIES {
        match fs_ioc_enable_verity(file, SHA256, BLOCK_SIZE as u32) {
            Err(EnableVerityError::FileOpenedForWrite) => {
                std::thread::sleep(std::time::Duration::from_millis(10))
            }
            other => return other,
        }
    }
    fs_ioc_enable_verity(file, SHA256, BLOCK_SIZE as u32)
}

/// Asks the kernel for a file's fs-verity digest.
pub fn measure(file: &File, path: &Path) -> Result<Digest, Error> {
    fs_ioc_measure_verity::<32>(file, SHA256)
        .map(Digest)
        .map_err(|e| Error::Verity {
            path: path.to_owned(),
            message: e.to_string(),
        })
}

/// Enables fs-verity on a finished file (such as a composefs image) and
/// returns the kernel's digest. The file must not be open for writing.
pub fn seal(path: &Path) -> Result<Digest, Error> {
    let file = File::open(path).map_err(io_err(path.display()))?;
    match enable_verity(&file) {
        Ok(()) | Err(EnableVerityError::AlreadyEnabled) => {}
        Err(EnableVerityError::FilesystemNotSupported) => {
            return Err(Error::VerityUnsupported(path.to_owned()));
        }
        Err(e) => {
            return Err(Error::Verity {
                path: path.to_owned(),
                message: e.to_string(),
            });
        }
    }
    measure(&file, path)
}

/// A reader that writes everything it reads to `copy`.
struct Tee<'a, R> {
    inner: R,
    copy: &'a mut File,
}

impl<R: Read> Read for Tee<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.copy.write_all(&buf[..n])?;
        Ok(n)
    }
}
