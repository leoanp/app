//! An app's file tree, and its composefs dump file (composefs-dump(5)).

use std::collections::BTreeMap;

use app_objects::Digest;

/// One entry of the tree. Ownership and times are not kept: every image
/// has owner 0:0 and time 0.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Node {
    /// `mode` is the permission bits only (at most 0o777).
    Dir {
        mode: u32,
    },
    /// A regular file stored in the object store (`digest` is `None` only for empty files).
    File {
        mode: u32,
        size: u64,
        digest: Option<Digest>,
    },
    Symlink {
        target: Vec<u8>,
    },
}

/// A complete tree, keyed by path relative to the root (`b""` is the root).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Tree {
    pub entries: BTreeMap<Vec<u8>, Node>,
}

impl Tree {
    /// An empty tree with a root folder (mode 0755).
    pub fn new() -> Tree {
        let mut t = Tree::default();
        t.entries.insert(Vec::new(), Node::Dir { mode: 0o755 });
        t
    }

    /// Every object digest the tree refers to.
    pub fn digests(&self) -> impl Iterator<Item = &Digest> {
        self.entries.values().filter_map(|n| match n {
            Node::File { digest, .. } => digest.as_ref(),
            _ => None,
        })
    }

    /// The composefs dump file describing this tree. Paths sort bytewise,
    /// so every folder comes before its contents.
    pub fn dumpfile(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (path, node) in &self.entries {
            let mut full = b"/".to_vec();
            full.extend_from_slice(path);
            let (size, mode, payload, digest) = match node {
                Node::Dir { mode } => {
                    (0, 0o040000 | (mode & 0o777), "-".to_owned(), "-".to_owned())
                }
                Node::File { mode, size, digest } => match digest {
                    Some(d) => (
                        *size,
                        0o100000 | (mode & 0o777),
                        d.object_path(),
                        d.to_hex(),
                    ),
                    None => (0, 0o100000 | (mode & 0o777), "-".to_owned(), "-".to_owned()),
                },
                Node::Symlink { target } => (
                    target.len() as u64,
                    0o120777,
                    escape(target),
                    "-".to_owned(),
                ),
            };
            // PATH SIZE MODE NLINK UID GID RDEV MTIME PAYLOAD CONTENT DIGEST
            let line = format!(
                "{} {size} {mode:o} 1 0 0 0 0.0 {payload} - {digest}\n",
                escape(&full)
            );
            out.extend_from_slice(line.as_bytes());
        }
        out
    }
}

/// Escapes a field for the dump file: safe characters as they are, anything
/// else as `\xHH`. A field that is exactly `-` (meaning "none") is escaped too.
pub(crate) fn escape(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len());
    for &b in bytes {
        if b.is_ascii_alphanumeric() || b"/._-+,@:~".contains(&b) {
            s.push(b as char);
        } else {
            s.push_str(&format!("\\x{b:02x}"));
        }
    }
    if s == "-" { "\\x2d".to_owned() } else { s }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> Digest {
        app_objects::digest::compute(&[byte][..]).unwrap()
    }

    #[test]
    fn dumpfile_lines() {
        let mut t = Tree::new();
        let d = digest(1);
        t.entries.insert(b"bin".to_vec(), Node::Dir { mode: 0o755 });
        t.entries.insert(
            b"bin/app".to_vec(),
            Node::File {
                mode: 0o755,
                size: 1,
                digest: Some(d),
            },
        );
        t.entries.insert(
            b"empty".to_vec(),
            Node::File {
                mode: 0o644,
                size: 0,
                digest: None,
            },
        );
        t.entries.insert(
            b"link".to_vec(),
            Node::Symlink {
                target: b"bin/app".to_vec(),
            },
        );
        let text = String::from_utf8(t.dumpfile()).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "/ 0 40755 1 0 0 0 0.0 - - -");
        assert_eq!(lines[1], "/bin 0 40755 1 0 0 0 0.0 - - -");
        assert_eq!(
            lines[2],
            format!(
                "/bin/app 1 100755 1 0 0 0 0.0 {} - {}",
                d.object_path(),
                d.to_hex()
            )
        );
        assert_eq!(lines[3], "/empty 0 100644 1 0 0 0 0.0 - - -");
        assert_eq!(lines[4], "/link 7 120777 1 0 0 0 0.0 bin/app - -");
    }

    #[test]
    fn modes_never_carry_setuid() {
        let mut t = Tree::new();
        t.entries.insert(
            b"x".to_vec(),
            Node::File {
                mode: 0o4755,
                size: 0,
                digest: None,
            },
        );
        t.entries.insert(b"d".to_vec(), Node::Dir { mode: 0o3777 });
        let text = String::from_utf8(t.dumpfile()).unwrap();
        assert!(text.contains("/x 0 100755 "), "{text}");
        assert!(text.contains("/d 0 40777 "), "{text}");
    }

    #[test]
    fn escaping() {
        assert_eq!(escape(b"sp ace/f=1"), "sp\\x20ace/f\\x3d1");
        assert_eq!(escape(b"-"), "\\x2d");
        assert_eq!(escape(b"a-b"), "a-b");
        assert_eq!(escape(b"back\\slash\nnl"), "back\\x5cslash\\x0anl");
        assert_eq!(escape("é".as_bytes()), "\\xc3\\xa9");
    }

    #[test]
    fn folders_come_before_contents() {
        let mut t = Tree::new();
        for p in ["a/x", "a b", "a", "a/x/y", "a-"] {
            t.entries
                .insert(p.as_bytes().to_vec(), Node::Dir { mode: 0o755 });
        }
        let order: Vec<&[u8]> = t.entries.keys().map(Vec::as_slice).collect();
        let pos = |p: &str| order.iter().position(|k| *k == p.as_bytes()).unwrap();
        assert!(pos("a") < pos("a/x") && pos("a/x") < pos("a/x/y"));
    }
}
