//! Versions used in `[requires]` and in a platform's `[provides]`.
//!
//! A version is 1–4 dot-separated whole numbers without leading zeros
//! (`"2.39"`, `"3.4.30"`). Versions compare part by part; missing parts count
//! as 0, so `2.39` equals `2.39.0`.

use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Most parts a version may have.
pub const MAX_PARTS: usize = 4;

/// A parsed version. Equality and ordering ignore trailing zero parts.
#[derive(Clone, Debug)]
pub struct Version {
    parts: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("`{0}` is not a version (expected 1 to 4 dot-separated whole numbers, such as \"2.39\")")]
pub struct VersionError(String);

impl Version {
    /// The numeric parts, as written.
    pub fn parts(&self) -> &[u32] {
        &self.parts
    }

    fn part(&self, i: usize) -> u32 {
        self.parts.get(i).copied().unwrap_or(0)
    }
}

impl FromStr for Version {
    type Err = VersionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || VersionError(s.to_owned());
        let parts = s
            .split('.')
            .map(|p| {
                let digits_only = !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit());
                let leading_zero = p.len() > 1 && p.starts_with('0');
                if !digits_only || leading_zero {
                    return Err(err());
                }
                p.parse::<u32>().map_err(|_| err())
            })
            .collect::<Result<Vec<_>, _>>()?;
        if parts.len() > MAX_PARTS {
            return Err(err());
        }
        Ok(Version { parts })
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s: Vec<String> = self.parts.iter().map(u32::to_string).collect();
        f.write_str(&s.join("."))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        (0..MAX_PARTS)
            .map(|i| self.part(i).cmp(&other.part(i)))
            .find(|o| o.is_ne())
            .unwrap_or(Ordering::Equal)
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other).is_eq()
    }
}

impl Eq for Version {}

impl Serialize for Version {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Version {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        s.parse().unwrap()
    }

    #[test]
    fn parses() {
        assert_eq!(v("2.39").parts(), &[2, 39]);
        assert_eq!(v("3.4.30").parts(), &[3, 4, 30]);
        assert_eq!(v("0").parts(), &[0]);
        assert_eq!(v("1.2.3.4").to_string(), "1.2.3.4");
    }

    #[test]
    fn rejects() {
        for bad in [
            "",
            "2.",
            ".2",
            "2..3",
            "02.1",
            "2.39a",
            "v2",
            "1.2.3.4.5",
            "-1",
            "2 .3",
            "99999999999",
        ] {
            assert!(bad.parse::<Version>().is_err(), "{bad:?} should be refused");
        }
    }

    #[test]
    fn compares_numerically() {
        assert!(v("2.39") > v("2.9"));
        assert!(v("3.4.30") < v("3.4.31"));
        assert!(v("1.3") > v("1.2.9"));
        assert_eq!(v("2.39"), v("2.39.0"));
        assert_eq!(v("2.39").cmp(&v("2.39.0.0")), Ordering::Equal);
    }
}
