//! fs-verity file digests (SHA-256, 4096-byte blocks, no salt): the name of
//! every stored object, and what the kernel checks on every read.
//!
//! The digest is SHA-256 over a 256-byte descriptor holding the file size
//! and the root of a Merkle tree over the file's 4096-byte blocks, exactly
//! as the kernel and `fsverity digest` compute it.

use std::fmt;
use std::io::{self, Read};
use std::str::FromStr;

use sha2::{Digest as _, Sha256};

pub const BLOCK_SIZE: usize = 4096;
const HASH_SIZE: usize = 32;
const HASHES_PER_BLOCK: usize = BLOCK_SIZE / HASH_SIZE;

/// An fs-verity SHA-256 digest.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    /// Lowercase hexadecimal, 64 characters.
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The object's path inside the store: `ab/cdef…` (composefs layout).
    pub fn object_path(&self) -> String {
        let hex = self.to_hex();
        format!("{}/{}", &hex[..2], &hex[2..])
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest({})", self.to_hex())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("`{0}` is not a digest (expected 64 lowercase hexadecimal characters)")]
pub struct DigestParseError(String);

impl FromStr for Digest {
    type Err = DigestParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || DigestParseError(s.to_owned());
        let valid = s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !valid {
            return Err(err());
        }
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| err())?;
        }
        Ok(Digest(out))
    }
}

/// Computes the fs-verity digest of everything `reader` yields.
pub fn compute(mut reader: impl Read) -> io::Result<Digest> {
    // levels[0] collects data-block hashes; levels[n] hashes of full level-(n-1) blocks.
    let mut levels: Vec<Vec<u8>> = vec![Vec::new()];
    let mut size: u64 = 0;
    let mut block = vec![0u8; BLOCK_SIZE];
    loop {
        let n = read_full(&mut reader, &mut block)?;
        if n == 0 {
            break;
        }
        size += n as u64;
        block[n..].fill(0);
        push_hash(&mut levels, 0, Sha256::digest(&block).into());
        if n < BLOCK_SIZE {
            break;
        }
    }
    let root = root_hash(levels, size);
    Ok(Digest(descriptor_digest(size, &root)))
}

/// Reads until `buf` is full or the input ends.
fn read_full(r: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

/// Adds a hash to `level`; when that level fills a block, hashes the block into the next level.
fn push_hash(levels: &mut Vec<Vec<u8>>, level: usize, hash: [u8; HASH_SIZE]) {
    levels[level].extend_from_slice(&hash);
    if levels[level].len() == BLOCK_SIZE {
        let full = std::mem::take(&mut levels[level]);
        if levels.len() == level + 1 {
            levels.push(Vec::new());
        }
        push_hash(levels, level + 1, Sha256::digest(&full).into());
    }
}

/// Finishes the tree: pads partial blocks upward until one hash remains.
fn root_hash(mut levels: Vec<Vec<u8>>, size: u64) -> [u8; HASH_SIZE] {
    if size == 0 {
        return [0; HASH_SIZE]; // an empty file has an all-zero root
    }
    let data_blocks = size.div_ceil(BLOCK_SIZE as u64);
    if data_blocks == 1 {
        // One data block: the root is that block's hash.
        let mut root = [0; HASH_SIZE];
        root.copy_from_slice(&levels[0][..HASH_SIZE]);
        return root;
    }
    // Number of levels above the data: until one block of hashes covers everything.
    let mut blocks = data_blocks;
    let mut depth = 0;
    while blocks > 1 {
        blocks = blocks.div_ceil(HASHES_PER_BLOCK as u64);
        depth += 1;
    }
    // Flush each level below the top: pad its partial block and hash it
    // upward (which may in turn fill the level above).
    for level in 0..depth - 1 {
        if !levels[level].is_empty() {
            let mut pending = std::mem::take(&mut levels[level]);
            pending.resize(BLOCK_SIZE, 0);
            push_hash(&mut levels, level + 1, Sha256::digest(&pending).into());
        }
    }
    let top = &levels[depth - 1];
    if top.is_empty() {
        // The top block filled exactly and was already hashed one level up.
        let mut root = [0; HASH_SIZE];
        root.copy_from_slice(&levels[depth][..HASH_SIZE]);
        return root;
    }
    let mut top = top.clone();
    top.resize(BLOCK_SIZE, 0);
    Sha256::digest(&top).into()
}

/// SHA-256 of `struct fsverity_descriptor` (version 1, SHA-256, 4 KiB blocks, no salt).
fn descriptor_digest(size: u64, root: &[u8; HASH_SIZE]) -> [u8; 32] {
    let mut d = [0u8; 256];
    d[0] = 1; // version
    d[1] = 1; // FS_VERITY_HASH_ALG_SHA256
    d[2] = 12; // log2(block size)
    d[3] = 0; // salt size
    // d[4..8]: reserved
    d[8..16].copy_from_slice(&size.to_le_bytes());
    d[16..16 + HASH_SIZE].copy_from_slice(root); // root hash, padded to 64 bytes
    // d[80..112]: salt; d[112..256]: reserved
    Sha256::digest(d).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(len: usize, modulo: usize) -> Vec<u8> {
        (0..len).map(|i| (i % modulo) as u8).collect()
    }

    fn hex(data: &[u8]) -> String {
        compute(data).unwrap().to_hex()
    }

    /// Reference values from `fsverity digest --compact` (fsverity-utils 1.6).
    #[test]
    fn matches_fsverity_utils() {
        let cases: [(Vec<u8>, &str); 7] = [
            (
                vec![],
                "3d248ca542a24fc62d1c43b916eae5016878e2533c88238480b26128a1f1af95",
            ),
            (
                b"a".to_vec(),
                "bce75948b9e7510293f8f2720412af9697c1479281323f3f220623fb8e94b557",
            ),
            (
                vec![b'b'; 4096],
                "3b824cd4c7037f30d8d7120b386494ab101f0f896f201eca33bc67cd98132d1c",
            ),
            (
                vec![b'c'; 4097],
                "dc5521273b09afd1713da5940d1482e729f7fa1edd60ea9e3101bb9ec01eed13",
            ),
            (
                pattern(128 * 4096, 251),
                "d82861203d50ae9b60948504a704f35f5118bd229aeb1a22d6dae47b1767c4c4",
            ),
            (
                pattern(128 * 4096 + 1, 251),
                "4dc6905041c9c4ee73e13b53f63f5d289c46da359b664a965ead7f8cc4d799d4",
            ),
            (
                pattern(128 * 128 * 4096 + 5, 253),
                "3d0a283043a5d5dae31609f008d98f15fe8abbfb2b1237f52fc746b1d6a61c08",
            ),
        ];
        for (data, want) in cases {
            assert_eq!(hex(&data), want, "size {}", data.len());
        }
    }

    #[test]
    fn reads_in_small_pieces() {
        // A reader returning 7 bytes at a time must give the same digest.
        struct Trickle<'a>(&'a [u8]);
        impl Read for Trickle<'_> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                let n = buf.len().min(7).min(self.0.len());
                buf[..n].copy_from_slice(&self.0[..n]);
                self.0 = &self.0[n..];
                Ok(n)
            }
        }
        let data = pattern(3 * 4096 + 100, 13);
        assert_eq!(
            compute(Trickle(&data)).unwrap(),
            compute(&data[..]).unwrap()
        );
    }

    #[test]
    fn hex_round_trip() {
        let d = compute(&b"x"[..]).unwrap();
        assert_eq!(d.to_hex().parse::<Digest>().unwrap(), d);
        assert_eq!(d.object_path().len(), 65);
        assert_eq!(&d.object_path()[2..3], "/");
        for bad in ["", "AB", &"A".repeat(64), &"g".repeat(64), &"a".repeat(63)] {
            assert!(bad.parse::<Digest>().is_err(), "{bad}");
        }
    }
}
