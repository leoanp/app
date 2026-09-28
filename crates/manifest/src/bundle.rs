//! Checks on a bundle's file tree (spec section 5, "Rules for bundles", and
//! section 6, "Validation").
//!
//! The tree is read through [`BundleFs`], so the same checks run on an
//! extracted folder, a mounted image, or an in-memory tree in tests.

use std::io;

use crate::Manifest;
use crate::report::Report;

/// Path of the manifest inside a bundle.
pub const MANIFEST_PATH: &str = "manifest.toml";
/// Path of the required icon.
pub const ICON_PATH: &str = "icons/256.png";
/// Path of the optional scalable icon.
pub const SVG_ICON_PATH: &str = "icons/scalable.svg";
/// Largest accepted `icons/scalable.svg`.
pub const MAX_SVG_BYTES: u64 = 1 << 20;
/// Most bytes read from `icons/256.png`. Not a spec limit: a 256×256 PNG is
/// far smaller; this only stops a hostile file from exhausting memory.
const MAX_PNG_READ: u64 = 16 << 20;
/// Most symlinks followed while resolving one path, as in Linux.
const MAX_SYMLINK_HOPS: usize = 40;

/// What a path in the bundle is, without following symlinks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Entry {
    File {
        executable: bool,
        size: u64,
    },
    Dir,
    Symlink {
        target: String,
    },
    /// Device files, sockets, pipes: never allowed.
    Special,
}

/// Read access to a bundle's tree. Paths are relative, `/`-separated, and
/// never contain `.` or `..`; `""` is the bundle root.
pub trait BundleFs {
    /// The entry at `path`, or `None` if nothing is there.
    fn entry(&self, path: &str) -> io::Result<Option<Entry>>;
    /// Every path in the bundle except the root, with its entry.
    fn entries(&self) -> io::Result<Vec<(String, Entry)>>;
    /// Reads a regular file, failing if it is larger than `max` bytes.
    fn read(&self, path: &str, max: u64) -> io::Result<Vec<u8>>;
}

/// Checks the whole bundle against its manifest: no special files, no
/// escaping symlinks, the required files present, the icons valid, and
/// `exec` an executable file (unless it lies inside an external file's
/// destination, which exists only after install; call [`check_exec`] then).
pub fn check(m: &Manifest, fs: &dyn BundleFs) -> Result<(), crate::Error> {
    let mut r = Report::default();
    match fs.entries() {
        Ok(entries) => {
            for (path, entry) in entries {
                match entry {
                    Entry::Special => {
                        r.invalid(path, "device files, sockets and pipes are not allowed")
                    }
                    Entry::Symlink { target } => {
                        if let Err(e) = check_symlink(fs, &path, &target) {
                            r.invalid(path, e);
                        }
                    }
                    _ => {}
                }
            }
        }
        Err(e) => r.invalid("", format!("cannot list the bundle: {e}")),
    }

    match fs.entry(MANIFEST_PATH) {
        Ok(Some(Entry::File { .. })) => {}
        _ => r.invalid(MANIFEST_PATH, "must be a regular file at the top level"),
    }
    check_icons(fs, &mut r);
    if !exec_is_external(m) {
        exec(m, fs, &mut r);
    }
    r.finish().map(|_| ())
}

/// Checks that `app.exec` resolves inside the bundle to an executable file.
pub fn check_exec(m: &Manifest, fs: &dyn BundleFs) -> Result<(), crate::Error> {
    let mut r = Report::default();
    exec(m, fs, &mut r);
    r.finish().map(|_| ())
}

fn exec(m: &Manifest, fs: &dyn BundleFs, r: &mut Report) {
    match resolve(fs, "", &m.app.exec) {
        Ok(Some((
            _,
            Entry::File {
                executable: true, ..
            },
        ))) => {}
        Ok(Some((_, Entry::File { .. }))) => r.invalid("app.exec", "is not marked executable"),
        Ok(Some(_)) => r.invalid("app.exec", "is not a regular file"),
        Ok(None) => r.invalid(
            "app.exec",
            format!("`{}` does not exist in the bundle", m.app.exec),
        ),
        Err(e) => r.invalid("app.exec", e),
    }
}

/// Whether `app.exec` lies inside a path an external file will fill.
fn exec_is_external(m: &Manifest) -> bool {
    m.external.iter().any(|e| {
        let dest = e.dest.trim_end_matches('/');
        m.app.exec == dest || m.app.exec.starts_with(&format!("{dest}/"))
    })
}

fn check_icons(fs: &dyn BundleFs, r: &mut Report) {
    match fs.entry(ICON_PATH) {
        Ok(Some(Entry::File { .. })) => match fs.read(ICON_PATH, MAX_PNG_READ) {
            Ok(bytes) => r.check(ICON_PATH, png_256(&bytes)),
            Err(e) => r.invalid(ICON_PATH, format!("cannot be read: {e}")),
        },
        _ => r.invalid(ICON_PATH, "is required and must be a regular file"),
    }
    match fs.entry(SVG_ICON_PATH) {
        Ok(None) => {}
        Ok(Some(Entry::File { size, .. })) if size <= MAX_SVG_BYTES => {}
        Ok(Some(Entry::File { .. })) => r.invalid(SVG_ICON_PATH, "is larger than 1 MiB"),
        _ => r.invalid(SVG_ICON_PATH, "must be a regular file"),
    }
}

/// A complete, valid PNG of exactly 256×256 pixels.
pub fn png_256(bytes: &[u8]) -> Result<(), String> {
    let decoder = png::Decoder::new(io::Cursor::new(bytes));
    let mut reader = decoder
        .read_info()
        .map_err(|e| format!("is not a valid PNG ({e})"))?;
    let (w, h) = (reader.info().width, reader.info().height);
    if (w, h) != (256, 256) {
        return Err(format!("must be 256×256 pixels, not {w}×{h}"));
    }
    let size = reader
        .output_buffer_size()
        .ok_or("is not a valid PNG (image too large)")?;
    let mut buf = vec![0; size];
    reader
        .next_frame(&mut buf)
        .map_err(|e| format!("is not a valid PNG ({e})"))?;
    Ok(())
}

/// A symlink at `link` pointing to `target` is allowed only if the target is
/// relative and, followed through the real tree, never leaves the bundle.
/// A target that does not exist is allowed (it can never be created: the
/// bundle is read-only), as long as the part that exists stays inside.
pub fn check_symlink(fs: &dyn BundleFs, link: &str, target: &str) -> Result<(), String> {
    if target.is_empty() {
        return Err("symlink has an empty target".into());
    }
    if target.starts_with('/') {
        return Err(format!(
            "symlink points to the absolute path `{target}`; only relative symlinks are allowed"
        ));
    }
    let parent = link.rsplit_once('/').map_or("", |(dir, _)| dir);
    resolve(fs, parent, target).map(|_| ())
}

/// Resolves `path` relative to directory `base` inside the bundle, following
/// symlinks, like the kernel would with the bundle root as `/`'s parent
/// boundary. Returns the final path and entry, `None` if some part does not
/// exist, or an error if the path leaves the bundle.
pub fn resolve(
    fs: &dyn BundleFs,
    base: &str,
    path: &str,
) -> Result<Option<(String, Entry)>, String> {
    let io_err = |e: io::Error| format!("cannot read the bundle: {e}");
    let mut dir: Vec<String> = base
        .split('/')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    // Components still to walk, in reverse so the next one is at the end.
    let mut todo: Vec<String> = path.split('/').rev().map(str::to_owned).collect();
    let mut hops = 0;
    let mut current = Entry::Dir;

    while let Some(part) = todo.pop() {
        if part.is_empty() || part == "." {
            continue;
        }
        if current != Entry::Dir {
            return Ok(None); // walking below a file: nothing is there
        }
        if part == ".." {
            if dir.pop().is_none() {
                return Err(format!("`{path}` leads outside the bundle"));
            }
            continue;
        }
        dir.push(part);
        let joined = dir.join("/");
        match fs.entry(&joined).map_err(io_err)? {
            None => return Ok(None),
            Some(Entry::Symlink { target }) => {
                hops += 1;
                if hops > MAX_SYMLINK_HOPS {
                    return Err(format!("`{path}` has too many levels of symlinks"));
                }
                if target.starts_with('/') {
                    return Err(format!(
                        "`{path}` goes through a symlink to an absolute path"
                    ));
                }
                dir.pop();
                todo.extend(target.split('/').rev().map(str::to_owned));
                current = Entry::Dir;
            }
            Some(e) => current = e,
        }
    }
    Ok(Some((dir.join("/"), current)))
}

/// An in-memory bundle, for tests and for building trees before writing them.
#[derive(Clone, Debug, Default)]
pub struct MemoryFs {
    entries: std::collections::BTreeMap<String, (Entry, Vec<u8>)>,
}

impl MemoryFs {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a file, creating its parent folders.
    pub fn file(&mut self, path: &str, contents: &[u8], executable: bool) -> &mut Self {
        self.parents(path);
        let entry = Entry::File {
            executable,
            size: contents.len() as u64,
        };
        self.entries
            .insert(path.to_owned(), (entry, contents.to_vec()));
        self
    }

    pub fn symlink(&mut self, path: &str, target: &str) -> &mut Self {
        self.parents(path);
        self.entries.insert(
            path.to_owned(),
            (
                Entry::Symlink {
                    target: target.to_owned(),
                },
                Vec::new(),
            ),
        );
        self
    }

    pub fn special(&mut self, path: &str) -> &mut Self {
        self.parents(path);
        self.entries
            .insert(path.to_owned(), (Entry::Special, Vec::new()));
        self
    }

    fn parents(&mut self, path: &str) {
        let mut dir = String::new();
        let parts: Vec<&str> = path.split('/').collect();
        for part in &parts[..parts.len().saturating_sub(1)] {
            if !dir.is_empty() {
                dir.push('/');
            }
            dir.push_str(part);
            self.entries
                .entry(dir.clone())
                .or_insert((Entry::Dir, Vec::new()));
        }
    }
}

impl BundleFs for MemoryFs {
    fn entry(&self, path: &str) -> io::Result<Option<Entry>> {
        if path.is_empty() {
            return Ok(Some(Entry::Dir));
        }
        Ok(self.entries.get(path).map(|(e, _)| e.clone()))
    }

    fn entries(&self) -> io::Result<Vec<(String, Entry)>> {
        Ok(self
            .entries
            .iter()
            .map(|(p, (e, _))| (p.clone(), e.clone()))
            .collect())
    }

    fn read(&self, path: &str, max: u64) -> io::Result<Vec<u8>> {
        match self.entries.get(path) {
            Some((Entry::File { size, .. }, _)) if *size > max => {
                Err(io::Error::new(io::ErrorKind::InvalidData, "file too large"))
            }
            Some((Entry::File { .. }, data)) => Ok(data.clone()),
            _ => Err(io::Error::new(io::ErrorKind::NotFound, "not a file")),
        }
    }
}
