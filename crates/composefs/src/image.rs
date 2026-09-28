//! Building and mounting composefs images (Linux only).

use std::ffi::OsStr;
use std::fs;
use std::io::{self, Write};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use app_objects::{Digest, Store};
use rustix::fs::{Dir, FileType, Mode, OFlags, fstat, openat, readlinkat};

use crate::{Node, Tree};

/// Folders searched for external tools. `PATH` is ignored: this code runs
/// as root and must not run whatever a caller's `PATH` points to.
const TOOL_DIRS: &[&str] = &["/usr/bin", "/usr/sbin", "/bin", "/sbin"];

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{context}: {source}")]
    Io { context: String, source: io::Error },
    #[error(transparent)]
    Store(#[from] app_objects::Error),
    #[error("`{0}` is a device file, socket or pipe; bundles may not contain those")]
    SpecialFile(PathBuf),
    #[error("required tool `{0}` is not installed (looked in {TOOL_DIRS:?})")]
    MissingTool(&'static str),
    #[error("`{tool}` failed: {message}")]
    Tool { tool: &'static str, message: String },
}

fn io_err(context: impl std::fmt::Display) -> impl FnOnce(io::Error) -> Error {
    move |source| Error::Io {
        context: context.to_string(),
        source,
    }
}

/// The full path of an external tool, from [`TOOL_DIRS`] only.
pub fn tool(name: &'static str) -> Result<PathBuf, Error> {
    TOOL_DIRS
        .iter()
        .map(|d| Path::new(d).join(name))
        .find(|p| p.is_file())
        .ok_or(Error::MissingTool(name))
}

impl Tree {
    /// Reads a folder as untrusted input and stores its files. Every entry
    /// is opened relative to its parent's handle without following
    /// symlinks, and its type is checked on the opened handle, so an entry
    /// swapped for a symlink during the import can never pull in a file
    /// from outside (such as `/etc/shadow`). Symlinks are recorded, never
    /// followed; hard links become separate entries (the store keeps one
    /// copy anyway); setuid, setgid and sticky bits are dropped; device
    /// files, sockets and pipes are refused without being opened.
    pub fn import_dir(store: &Store, dir: &Path) -> Result<Tree, Error> {
        let fail = |p: &Path| {
            let p = p.to_owned();
            move |e: rustix::io::Errno| Error::Io {
                context: p.display().to_string(),
                source: e.into(),
            }
        };
        let root = rustix::fs::open(
            dir,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(fail(dir))?;
        let root_mode = fstat(&root).map_err(fail(dir))?.st_mode & 0o777;
        let mut tree = Tree::new();
        tree.entries
            .insert(Vec::new(), Node::Dir { mode: root_mode });

        let mut stack: Vec<(OwnedFd, Vec<u8>)> = vec![(root, Vec::new())];
        while let Some((dir_fd, rel)) = stack.pop() {
            let shown = dir.join(OsStr::from_bytes(&rel));
            for entry in Dir::read_from(&dir_fd).map_err(fail(&shown))? {
                let entry = entry.map_err(fail(&shown))?;
                let name = entry.file_name().to_bytes();
                if name == b"." || name == b".." {
                    continue;
                }
                let name_path = Path::new(OsStr::from_bytes(name));
                let mut key = rel.clone();
                if !key.is_empty() {
                    key.push(b'/');
                }
                key.extend_from_slice(name);
                let path = dir.join(OsStr::from_bytes(&key));

                let pinned = app_objects::pin(&dir_fd, name_path)?;
                let st = fstat(&pinned).map_err(fail(&path))?;
                let mode = st.st_mode & 0o777;
                let node = match FileType::from_raw_mode(st.st_mode) {
                    FileType::Directory => {
                        let sub = openat(
                            &pinned,
                            ".",
                            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                            Mode::empty(),
                        )
                        .map_err(fail(&path))?;
                        stack.push((sub, key.clone()));
                        Node::Dir { mode }
                    }
                    FileType::Symlink => {
                        let target = readlinkat(&pinned, "", Vec::new()).map_err(fail(&path))?;
                        Node::Symlink {
                            target: target.into_bytes(),
                        }
                    }
                    FileType::RegularFile => {
                        let size = st.st_size as u64;
                        let digest = if size == 0 {
                            None
                        } else {
                            Some(store.import(app_objects::reopen_for_reading(&pinned, &path)?)?)
                        };
                        Node::File { mode, size, digest }
                    }
                    // Device files, sockets, pipes.
                    _ => return Err(Error::SpecialFile(path)),
                };
                tree.entries.insert(key, node);
            }
        }
        Ok(tree)
    }
}

/// Writes the tree's composefs image to `out`, enables fs-verity on it and
/// returns the image digest (what stores publish and mounts require).
/// Every object the tree refers to must already be in the store.
pub fn build_image(tree: &Tree, out: &Path) -> Result<Digest, Error> {
    let mkcomposefs = tool("mkcomposefs")?;
    let dir = out.parent().unwrap_or(Path::new("."));
    let mut dump = tempfile::NamedTempFile::new_in(dir).map_err(io_err(dir.display()))?;
    dump.write_all(&tree.dumpfile())
        .map_err(io_err("writing the dump file"))?;
    dump.as_file()
        .sync_all()
        .map_err(io_err("writing the dump file"))?;

    // Build beside the destination, then rename: a crash never leaves a half image.
    let partial = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o644))
        .tempfile_in(dir)
        .map_err(io_err(dir.display()))?
        .into_temp_path();
    let status = Command::new(&mkcomposefs)
        .arg("--from-file")
        // Pin the image format so the same tree always gives the same image.
        .args(["--min-version=1", "--max-version=1"])
        .arg(dump.path())
        .arg(&*partial)
        .env_clear()
        .output()
        .map_err(io_err("running mkcomposefs"))?;
    if !status.status.success() {
        return Err(Error::Tool {
            tool: "mkcomposefs",
            message: String::from_utf8_lossy(&status.stderr).trim().into(),
        });
    }
    let digest = app_objects::seal(&partial)?;
    partial.persist(out).map_err(|e| Error::Io {
        context: out.display().to_string(),
        source: e.error,
    })?;
    Ok(digest)
}

/// Mounts an image read-only at `target`, requiring that the image has
/// exactly `digest` and that every file's fs-verity digest matches.
/// A changed byte anywhere then gives a read error.
pub fn mount(
    image: &Path,
    objects_dir: &Path,
    target: &Path,
    digest: &Digest,
) -> Result<(), Error> {
    let mount_composefs = tool("mount.composefs")?;
    for (what, p) in [
        ("image", image),
        ("objects", objects_dir),
        ("target", target),
    ] {
        if p.as_os_str().as_bytes().contains(&b',') {
            return Err(Error::Tool {
                tool: "mount.composefs",
                message: format!("{what} path may not contain `,`"),
            });
        }
    }
    let mut options = std::ffi::OsString::from("ro,verity,digest=");
    options.push(digest.to_hex());
    options.push(",basedir=");
    options.push(objects_dir.as_os_str());
    let out = Command::new(&mount_composefs)
        .arg("-o")
        .arg(&options)
        .arg(image)
        .arg(target)
        .env_clear()
        .output()
        .map_err(io_err("running mount.composefs"))?;
    if !out.status.success() {
        return Err(Error::Tool {
            tool: "mount.composefs",
            message: String::from_utf8_lossy(&out.stderr).trim().into(),
        });
    }
    Ok(())
}
