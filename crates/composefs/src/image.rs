//! Building and mounting composefs images (Linux only).

use std::fs;
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use app_objects::{Digest, Store};

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
    /// Reads a folder as untrusted input and stores its files. Symlinks are
    /// recorded, never followed; hard links become separate entries (the
    /// store keeps one copy anyway); setuid, setgid and sticky bits are
    /// dropped; device files, sockets and pipes are refused.
    pub fn import_dir(store: &Store, dir: &Path) -> Result<Tree, Error> {
        let mut tree = Tree::new();
        let root_mode = fs::symlink_metadata(dir).map_err(io_err(dir.display()))?;
        if !root_mode.is_dir() {
            return Err(Error::Io {
                context: dir.display().to_string(),
                source: io::Error::new(io::ErrorKind::InvalidInput, "not a folder"),
            });
        }
        tree.entries.insert(
            Vec::new(),
            Node::Dir {
                mode: root_mode.permissions().mode() & 0o777,
            },
        );
        let mut stack = vec![(dir.to_path_buf(), Vec::new())];
        while let Some((abs, rel)) = stack.pop() {
            for entry in fs::read_dir(&abs).map_err(io_err(abs.display()))? {
                let entry = entry.map_err(io_err(abs.display()))?;
                let path = entry.path();
                let mut key = rel.clone();
                if !key.is_empty() {
                    key.push(b'/');
                }
                key.extend_from_slice(entry.file_name().as_bytes());
                let meta = fs::symlink_metadata(&path).map_err(io_err(path.display()))?;
                let mode = meta.permissions().mode() & 0o777;
                let ft = meta.file_type();
                let node = if ft.is_dir() {
                    stack.push((path.clone(), key.clone()));
                    Node::Dir { mode }
                } else if ft.is_symlink() {
                    let target = fs::read_link(&path).map_err(io_err(path.display()))?;
                    Node::Symlink {
                        target: target.as_os_str().as_bytes().to_vec(),
                    }
                } else if ft.is_file() {
                    let size = meta.len();
                    let digest = if size == 0 {
                        None
                    } else {
                        Some(store.import_file(&path)?)
                    };
                    Node::File { mode, size, digest }
                } else {
                    // Device files, sockets, pipes.
                    return Err(Error::SpecialFile(path));
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
