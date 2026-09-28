//! Field rules for a manifest (spec section 6, "Validation").

use crate::model::{COMPAT_PREFIX, FORMAT, Grant, Manifest, REASON_KEYS};
use crate::report::Report;
use crate::{categories, env, syntax};

/// Default limits when the spec states no other.
pub const MAX_STRING_BYTES: usize = 1024;
pub const MAX_LIST_ENTRIES: usize = 64;

pub const MAX_ARGS: usize = 256;
pub const MAX_ARG_BYTES: usize = 4096;
pub const MAX_MIME_TYPES: usize = 256;
pub const MAX_REASON_CHARS: usize = 500;
pub const MAX_MIN_WIDTH: i64 = 16384;
pub const MAX_EXTERNAL_SIZE: u64 = 64 << 30;

/// D-Bus names the app bus already provides, which `permissions.services` may not ask for.
const APP_BUS_NAMES: &[&str] = &["org.freedesktop.DBus"];
const APP_BUS_PREFIXES: &[&str] = &["org.freedesktop.portal.", "org.freedesktop.impl.portal."];

pub(crate) fn manifest(m: &Manifest, r: &mut Report) {
    if m.format != FORMAT {
        r.newer_system(
            "format",
            format!(
                "uses format {}; this system supports format {FORMAT}",
                m.format
            ),
        );
        return;
    }
    app(m, r);
    permissions(m, r);
    reasons(m, r);
    ui(m, r);
    integration(m, r);
    compat(m, r);
    external(m, r);
}

fn app(m: &Manifest, r: &mut Report) {
    let a = &m.app;
    r.check("app.id", syntax::app_id(&a.id));
    r.check("app.name", syntax::display_text(&a.name, 1, 64));
    r.check("app.version", syntax::display_text(&a.version, 1, 64));
    if a.build < 1 {
        r.invalid("app.build", "must be 1 or more");
    }
    r.check("app.exec", syntax::relative_path(&a.exec, false));

    list_len(r, "app.args", a.args.len(), MAX_ARGS);
    for (i, arg) in a.args.iter().enumerate() {
        if arg.len() > MAX_ARG_BYTES {
            r.invalid(
                format!("app.args[{i}]"),
                format!("is longer than {MAX_ARG_BYTES} bytes"),
            );
        }
    }
    if let Some(s) = &a.summary {
        r.check("app.summary", syntax::display_text(s, 1, 200));
    }

    string_len(r, "app.license", &a.license);
    match license_is_proprietary(&a.license) {
        Err(e) => r.invalid("app.license", e),
        Ok(false) if a.source.is_none() => r.invalid(
            "app.source",
            "is required for open-source apps (license is not a `LicenseRef-...`)",
        ),
        Ok(_) => {}
    }
    for (field, url) in [("app.source", &a.source), ("app.homepage", &a.homepage)] {
        if let Some(u) = url {
            string_len(r, field, u);
            r.check(field, syntax::web_url(u, &["https", "http"]));
        }
    }

    list_len(r, "app.categories", a.categories.len(), MAX_LIST_ENTRIES);
    for c in &a.categories {
        if !categories::is_known(c) {
            r.warn(
                "app.categories",
                format!("unknown Freedesktop category `{c}` is ignored"),
            );
        }
    }
}

/// Parses an SPDX expression. `Ok(true)` if every license in it is a custom
/// `LicenseRef-...`, which marks a proprietary app.
fn license_is_proprietary(expr: &str) -> Result<bool, String> {
    // Strict SPDX, except deprecated identifiers (such as `GPL-3.0`) stay
    // valid: they are still SPDX identifiers, and many Flathub apps use them.
    let mode = spdx::ParseMode {
        allow_deprecated: true,
        ..spdx::ParseMode::STRICT
    };
    let parsed = spdx::Expression::parse_mode(expr, mode)
        .map_err(|e| format!("is not a valid SPDX expression ({e})"))?;
    Ok(parsed
        .requirements()
        .all(|r| matches!(r.req.license, spdx::LicenseItem::Other(_))))
}

fn permissions(m: &Manifest, r: &mut Report) {
    let p = &m.permissions;
    for (folder, grant) in &p.folders {
        let name = serde_name(folder);
        grant_reason(r, &format!("permissions.folders.{name}"), grant);
    }
    if let Some(g) = &p.removable {
        grant_reason(r, "permissions.removable", g);
    }
    list_len(
        r,
        "permissions.services",
        p.services.len(),
        MAX_LIST_ENTRIES,
    );
    for s in &p.services {
        let field = "permissions.services";
        if let Err(e) = syntax::dbus_name(s) {
            r.invalid(field, format!("`{s}` {e}"));
        } else if APP_BUS_NAMES.contains(&s.as_str())
            || APP_BUS_PREFIXES.iter().any(|p| s.starts_with(p))
        {
            r.invalid(
                field,
                format!("`{s}` is already provided on the app bus and cannot be requested"),
            );
        }
    }
}

fn grant_reason(r: &mut Report, field: &str, g: &Grant) {
    if let Some(reason) = &g.reason {
        r.check(
            format!("{field}.reason"),
            syntax::display_text(reason, 1, MAX_REASON_CHARS),
        );
    }
}

fn reasons(m: &Manifest, r: &mut Report) {
    for (key, text) in &m.reasons {
        let field = format!("reasons.{key}");
        if REASON_KEYS.contains(&key.as_str()) {
            r.check(field, syntax::display_text(text, 1, MAX_REASON_CHARS));
        } else {
            r.warn(field, "not a known permission; ignored");
        }
    }
}

fn ui(m: &Manifest, r: &mut Report) {
    list_len(r, "ui.inputs", m.ui.inputs.len(), MAX_LIST_ENTRIES);
    for i in &m.ui.inputs {
        if crate::Input::from_name(i).is_none() {
            r.warn(
                "ui.inputs",
                format!("unknown input method `{i}` is ignored"),
            );
        }
    }
    if m.inputs().is_empty() {
        r.invalid(
            "ui.inputs",
            "must list at least one of gamepad, touch, pointer, keyboard, remote",
        );
    }
    if let Some(w) = m.ui.min_width
        && !(1..=MAX_MIN_WIDTH).contains(&w)
    {
        r.invalid(
            "ui.min_width",
            format!("must be between 1 and {MAX_MIN_WIDTH}"),
        );
    }
}

fn integration(m: &Manifest, r: &mut Report) {
    let i = &m.integration;
    list_len(
        r,
        "integration.mime_types",
        i.mime_types.len(),
        MAX_MIME_TYPES,
    );
    for t in &i.mime_types {
        r.check(
            "integration.mime_types",
            syntax::mime_type(t).map_err(|e| format!("`{t}` {e}")),
        );
    }
    list_len(
        r,
        "integration.url_schemes",
        i.url_schemes.len(),
        MAX_LIST_ENTRIES,
    );
    for s in &i.url_schemes {
        r.check(
            "integration.url_schemes",
            syntax::url_scheme(s).map_err(|e| format!("`{s}` {e}")),
        );
    }
}

fn compat(m: &Manifest, r: &mut Report) {
    let c = &m.compat;
    if let Some(p) = &c.prefix
        && p != COMPAT_PREFIX
    {
        r.invalid("compat.prefix", format!("may only be `{COMPAT_PREFIX}`"));
    }
    list_len(r, "compat.env", c.env.len(), MAX_LIST_ENTRIES);
    for (name, value) in &c.env {
        let field = format!("compat.env.{name}");
        if !env::is_valid_name(name) {
            r.invalid(field, "is not a valid variable name");
        } else if env::is_reserved(name) {
            r.invalid(field, "is set by the launcher and cannot be changed");
        } else {
            string_len(r, &field, value);
        }
    }
}

fn external(m: &Manifest, r: &mut Report) {
    list_len(r, "external", m.external.len(), MAX_LIST_ENTRIES);
    for (i, e) in m.external.iter().enumerate() {
        let f = |name: &str| format!("external[{i}].{name}");
        string_len(r, &f("url"), &e.url);
        r.check(f("url"), syntax::web_url(&e.url, &["https"]));
        r.check(f("sha256"), syntax::sha256_hex(&e.sha256));
        if !(1..=MAX_EXTERNAL_SIZE).contains(&e.size) {
            r.invalid(f("size"), "must be between 1 byte and 64 GiB");
        }
        r.check(f("dest"), syntax::relative_path(&e.dest, true));
    }
}

fn string_len(r: &mut Report, field: &str, s: &str) {
    if s.len() > MAX_STRING_BYTES {
        r.invalid(field, format!("is longer than {MAX_STRING_BYTES} bytes"));
    }
}

fn list_len(r: &mut Report, field: &str, len: usize, max: usize) {
    if len > max {
        r.invalid(field, format!("has more than {max} entries"));
    }
}

/// The name a unit enum variant has in TOML.
fn serde_name<T: serde::Serialize>(v: &T) -> String {
    toml::Value::try_from(v)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}
