//! The platform foundation (spec section 4).
//!
//! Loads a foundation list (the spec's `spec/foundation.toml`, or a
//! platform's generated `/usr/share/app/foundation.toml`), classifies a
//! library as foundation or bundled, checks a platform's list against the
//! spec's, and checks an app's `[requires]` against a platform's `[provides]`.
//! Pure Rust, no system access.

use std::collections::{BTreeMap, BTreeSet};

use app_manifest::{REQUIRES_KEYS, Requires, Version};
use serde::Deserialize;

/// The spec's foundation list for format version 1, built into the binary.
pub const SPEC_FOUNDATION_TOML: &str = include_str!("../../../spec/foundation.toml");

/// The only format version this crate understands.
pub const FORMAT: i64 = 1;

/// `[provides]` keys every platform must fill in: its C and C++ runtimes
/// always exist. Graphics and video versions may be absent on hardware
/// without them; apps requiring them then do not run there.
pub const REQUIRED_PROVIDES: &[&str] = &["glibc", "libstdcxx"];

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("foundation list is not valid TOML: {0}")]
    Toml(String),
    #[error("foundation list: {0}")]
    Invalid(String),
}

/// A foundation list.
#[derive(Clone, Debug, Deserialize)]
pub struct Foundation {
    pub format: i64,
    #[serde(rename = "component")]
    pub components: Vec<Component>,
    /// Versions a platform provides, keyed like `[requires]`. Empty in the spec's list.
    #[serde(default)]
    pub provides: BTreeMap<String, Version>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct Component {
    pub id: String,
    pub summary: String,
    /// Manifest `requires.*` keys this component answers.
    #[serde(default)]
    pub requires: Vec<String>,
    /// ELF symbol version prefix used to detect requirements, such as `GLIBC_`.
    pub symbol_prefix: Option<String>,
    /// Libraries every platform installs and bundles must not contain.
    pub sonames: Vec<String>,
    /// Driver-internal file name patterns (`*` wildcard) bundles must not
    /// contain, though platforms need not install them all.
    #[serde(default)]
    pub never_bundle: Vec<String>,
}

/// What a library file is, with respect to the foundation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class<'a> {
    /// A foundation library: the platform provides it, the bundle must not.
    Foundation(&'a Component),
    /// A driver-internal library: the bundle must not contain it.
    DriverInternal(&'a Component),
    /// Everything else: the bundle must carry it.
    Bundle,
}

impl Class<'_> {
    /// Whether a bundle may contain this library.
    pub fn may_bundle(&self) -> bool {
        matches!(self, Class::Bundle)
    }
}

/// A requirement the platform does not meet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unmet {
    pub key: &'static str,
    pub needed: Version,
    /// What the platform provides, or `None` if it provides none at all.
    pub provided: Option<Version>,
}

impl Foundation {
    /// The spec's list, built into the binary.
    pub fn spec() -> Result<Foundation, Error> {
        Foundation::parse(SPEC_FOUNDATION_TOML)
    }

    /// Parses and checks a foundation list.
    pub fn parse(text: &str) -> Result<Foundation, Error> {
        let f: Foundation = toml::from_str(text).map_err(|e| Error::Toml(e.to_string()))?;
        f.check_shape()?;
        Ok(f)
    }

    fn check_shape(&self) -> Result<(), Error> {
        let invalid = |m: String| Err(Error::Invalid(m));
        if self.format != FORMAT {
            return invalid(format!(
                "format {} is not supported (expected {FORMAT})",
                self.format
            ));
        }
        let mut ids = BTreeSet::new();
        let mut sonames = BTreeSet::new();
        for c in &self.components {
            if !ids.insert(c.id.as_str()) {
                return invalid(format!("component `{}` is listed twice", c.id));
            }
            for s in &c.sonames {
                if s.is_empty() || s.contains('/') || s.contains('*') {
                    return invalid(format!("`{s}` in `{}` is not a library file name", c.id));
                }
                if !sonames.insert(s.as_str()) {
                    return invalid(format!("`{s}` is listed twice"));
                }
            }
            for p in &c.never_bundle {
                if p.is_empty() || p.contains('/') || p == "*" {
                    return invalid(format!(
                        "`{p}` in `{}` is not a usable file name pattern",
                        c.id
                    ));
                }
            }
            for k in &c.requires {
                if !REQUIRES_KEYS.contains(&k.as_str()) {
                    return invalid(format!(
                        "component `{}` answers unknown requirement `{k}`",
                        c.id
                    ));
                }
            }
        }
        for k in self.provides.keys() {
            if !REQUIRES_KEYS.contains(&k.as_str()) {
                return invalid(format!("[provides] has unknown key `{k}`"));
            }
        }
        Ok(())
    }

    /// Classifies a library by its soname (`libstdc++.so.6`) or file name.
    /// A file name matches a soname exactly or as its fuller-versioned file
    /// (`libstdc++.so.6.0.33`). The packager should prefer the ELF
    /// `DT_SONAME`; the file name is the fallback.
    pub fn classify(&self, name: &str) -> Class<'_> {
        let is_soname_file = |soname: &String| {
            name.strip_prefix(soname.as_str())
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('.'))
        };
        if let Some(c) = self
            .components
            .iter()
            .find(|c| c.sonames.iter().any(is_soname_file))
        {
            return Class::Foundation(c);
        }
        if let Some(c) = self
            .components
            .iter()
            .find(|c| c.never_bundle.iter().any(|p| glob(p, name)))
        {
            return Class::DriverInternal(c);
        }
        Class::Bundle
    }

    /// The component answering a `requires` key.
    pub fn component_for(&self, key: &str) -> Option<&Component> {
        self.components
            .iter()
            .find(|c| c.requires.iter().any(|k| k == key))
    }

    /// Checks a platform's list against this (the spec's) list: every
    /// component and soname present in the same component (a platform may
    /// add, never drop), and the required `[provides]` versions set.
    /// Returns every problem found.
    pub fn check_platform(&self, platform: &Foundation) -> Result<(), Vec<String>> {
        let mut problems = Vec::new();
        for spec_c in &self.components {
            let Some(plat_c) = platform.components.iter().find(|c| c.id == spec_c.id) else {
                problems.push(format!("component `{}` is missing", spec_c.id));
                continue;
            };
            for s in spec_c
                .sonames
                .iter()
                .filter(|s| !plat_c.sonames.contains(s))
            {
                problems.push(format!("`{s}` is missing from component `{}`", spec_c.id));
            }
        }
        for k in REQUIRED_PROVIDES
            .iter()
            .filter(|k| !platform.provides.contains_key(**k))
        {
            problems.push(format!("[provides] must set `{k}`"));
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(problems)
        }
    }

    /// Checks an app's requirements against this platform's `[provides]`.
    /// An empty result means the app may run.
    pub fn check_requires(&self, requires: &Requires) -> Vec<Unmet> {
        requires
            .entries()
            .into_iter()
            .filter_map(|(key, needed)| {
                let provided = self.provides.get(key);
                match provided {
                    Some(p) if p >= needed => None,
                    _ => Some(Unmet {
                        key,
                        needed: needed.clone(),
                        provided: provided.cloned(),
                    }),
                }
            })
            .collect()
    }
}

/// Matches `name` against `pattern`, where `*` matches any run of characters.
fn glob(pattern: &str, name: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    let (first, rest) = parts.split_first().unwrap_or((&"", &[]));
    let Some(mut remaining) = name.strip_prefix(first) else {
        return false;
    };
    let Some((last, middle)) = rest.split_last() else {
        return remaining.is_empty(); // no `*`: exact match
    };
    for part in middle {
        match remaining.find(part) {
            Some(i) => remaining = &remaining[i + part.len()..],
            None => return false,
        }
    }
    remaining.len() >= last.len() && remaining.ends_with(last)
}

#[cfg(test)]
mod tests;
