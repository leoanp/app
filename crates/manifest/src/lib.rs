//! Parse, write and validate `manifest.toml` (spec section 6).
//!
//! Shared by the runtime and the packager. Pure Rust, no system access:
//! checks that need the bundle's files go through the [`bundle::BundleFs`]
//! trait, which callers implement.
//!
//! ```
//! let text = r#"
//! format = 1
//! [app]
//! id = "org.example.Hello"
//! name = "Hello"
//! version = "1.0"
//! build = 1
//! arch = "x86_64"
//! exec = "bin/hello"
//! license = "MIT"
//! source = "https://example.org/hello"
//! [requires]
//! glibc = "2.39"
//! [ui]
//! inputs = ["pointer", "keyboard"]
//! "#;
//! let parsed = app_manifest::parse(text).unwrap();
//! assert_eq!(parsed.manifest.app.id, "org.example.Hello");
//! ```

pub mod bundle;
pub mod categories;
pub mod env;
mod model;
mod report;
pub mod syntax;
mod validate;
mod version;

pub use model::*;
pub use report::{Error, Problem, ProblemKind, Warning};
pub use validate::{MAX_LIST_ENTRIES, MAX_STRING_BYTES};
pub use version::{Version, VersionError};

use report::Report;

/// Largest accepted `manifest.toml`, in bytes.
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;

/// A manifest that passed validation, with anything `app check` should mention.
#[derive(Clone, Debug)]
pub struct Parsed {
    pub manifest: Manifest,
    pub warnings: Vec<Warning>,
}

/// Parses and validates the text of a `manifest.toml`.
pub fn parse(text: &str) -> Result<Parsed, Error> {
    let mut r = Report::default();
    if text.len() > MAX_MANIFEST_BYTES {
        r.invalid(
            "",
            format!(
                "manifest.toml is larger than {} KiB",
                MAX_MANIFEST_BYTES / 1024
            ),
        );
        return fail(r);
    }
    let table: toml::Table = match text.parse() {
        Ok(t) => t,
        Err(e) => {
            r.invalid(
                "",
                format!(
                    "manifest.toml is not valid TOML: {}",
                    capped(&e.to_string())
                ),
            );
            return fail(r);
        }
    };

    // Before anything else: a newer format may change any other rule.
    match table.get("format") {
        None => r.invalid("format", "is required"),
        Some(toml::Value::Integer(n)) if *n == FORMAT => {}
        Some(toml::Value::Integer(n)) => r.newer_system(
            "format",
            format!("uses format {n}; this system supports format {FORMAT}"),
        ),
        Some(_) => r.invalid("format", "must be a whole number"),
    }
    if let Some(toml::Value::Table(req)) = table.get("requires") {
        for key in req.keys().filter(|k| !REQUIRES_KEYS.contains(&k.as_str())) {
            r.newer_system(
                format!("requires.{key}"),
                "is a requirement this system cannot check",
            );
        }
    }
    raw_limits(&mut Vec::new(), &toml::Value::Table(table), &mut r);
    if !r.problems.is_empty() {
        return fail(r);
    }

    let mut ignored = Vec::new();
    let manifest: Manifest = match toml::Deserializer::parse(text)
        .and_then(|de| serde_ignored::deserialize(de, |path| ignored.push(path.to_string())))
    {
        Ok(m) => m,
        Err(e) => {
            r.invalid("", capped(e.to_string().trim_end()));
            return fail(r);
        }
    };
    for path in ignored {
        if path.starts_with("permissions.") {
            r.warn(path, "unknown permission; ignored and never granted");
        } else {
            r.warn(path, "unknown field; ignored");
        }
    }

    validate::manifest(&manifest, &mut r);
    let warnings = r.finish()?;
    Ok(Parsed { manifest, warnings })
}

impl Manifest {
    /// Checks every field rule. [`parse`] already does this; use it for
    /// manifests built in code, such as by the packager.
    pub fn validate(&self) -> Result<Vec<Warning>, Error> {
        let mut r = Report::default();
        validate::manifest(self, &mut r);
        r.finish()
    }

    /// Validates, then writes the manifest as TOML.
    pub fn to_toml(&self) -> Result<String, Error> {
        self.validate()?;
        let text = toml::to_string(self).map_err(|e| Error {
            problems: vec![Problem {
                kind: ProblemKind::Invalid,
                field: String::new(),
                message: e.to_string(),
            }],
        })?;
        if text.len() > MAX_MANIFEST_BYTES {
            let mut r = Report::default();
            r.invalid(
                "",
                format!(
                    "manifest.toml would be larger than {} KiB",
                    MAX_MANIFEST_BYTES / 1024
                ),
            );
            return fail(r);
        }
        Ok(text)
    }
}

/// Parser errors quote the offending line, which may be 64 KiB long.
fn capped(message: &str) -> String {
    const MAX: usize = 800;
    match message.char_indices().nth(MAX) {
        Some((i, _)) => format!("{}…", &message[..i]),
        None => message.to_owned(),
    }
}

fn fail<T>(r: Report) -> Result<T, Error> {
    Err(Error {
        problems: r.problems,
    })
}

/// Limits that apply to every value, known or not: no NUL characters, and
/// the default string and list limits unless a field states others.
fn raw_limits(path: &mut Vec<String>, v: &toml::Value, r: &mut Report) {
    let (max_string, max_list) = match path.join(".").as_str() {
        "app.args" => (0, 256),
        "app.args.[]" | "app.exec" | "external.[].dest" => (syntax::MAX_PATH_BYTES, 0),
        "integration.mime_types" => (0, 256),
        _ => (MAX_STRING_BYTES, MAX_LIST_ENTRIES),
    };
    let field = path.join(".").replace(".[]", "[]");
    match v {
        toml::Value::String(s) => {
            if s.contains('\0') {
                r.invalid(field.clone(), "contains a NUL character");
            } else if s.len() > max_string {
                r.invalid(field.clone(), format!("is longer than {max_string} bytes"));
            }
        }
        toml::Value::Array(items) => {
            if items.len() > max_list {
                r.invalid(field.clone(), format!("has more than {max_list} entries"));
            }
            path.push("[]".into());
            items.iter().for_each(|item| raw_limits(path, item, r));
            path.pop();
        }
        toml::Value::Table(t) => {
            for (key, item) in t {
                if key.contains('\0') || key.len() > MAX_STRING_BYTES {
                    r.invalid(
                        field.clone(),
                        "has a key with a NUL character or longer than 1024 bytes",
                    );
                    continue;
                }
                path.push(key.clone());
                raw_limits(path, item, r);
                path.pop();
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests;
