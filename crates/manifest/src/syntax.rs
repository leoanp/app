//! Syntax checks for individual manifest values (spec section 6, "Validation").
//!
//! Each function returns `Err` with a short, user-readable reason.

/// Longest path accepted in `exec` and `external.dest`, in bytes.
pub const MAX_PATH_BYTES: usize = 4096;

/// `app.id`: Flatpak's application ID rules, so converted apps keep their IDs.
/// At least 3 dot-separated parts of `[A-Za-z0-9_-]`, `-` only in the last
/// part, no part empty or starting with a digit, at most 255 bytes.
pub fn app_id(id: &str) -> Result<(), String> {
    if id.len() > 255 {
        return Err("is longer than 255 bytes".into());
    }
    let parts: Vec<&str> = id.split('.').collect();
    if parts.len() < 3 {
        return Err("needs at least 3 dot-separated parts, such as org.example.App".into());
    }
    let last = parts.len() - 1;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            return Err("has an empty part".into());
        }
        if part.starts_with(|c: char| c.is_ascii_digit()) {
            return Err(format!("part `{part}` starts with a digit"));
        }
        for c in part.chars() {
            let ok = c.is_ascii_alphanumeric() || c == '_' || (c == '-' && i == last);
            if !ok {
                return Err(if c == '-' {
                    "may only use `-` in its last part".into()
                } else {
                    format!("contains `{c}`; only letters, digits, `_` and `-` are allowed")
                });
            }
        }
    }
    Ok(())
}

/// A D-Bus well-known bus name: at most 255 bytes, at least 2 dot-separated
/// parts of `[A-Za-z0-9_-]`, none empty or starting with a digit.
pub fn dbus_name(name: &str) -> Result<(), String> {
    if name.len() > 255 {
        return Err("is longer than 255 bytes".into());
    }
    let parts: Vec<&str> = name.split('.').collect();
    if parts.len() < 2 {
        return Err("needs at least 2 dot-separated parts".into());
    }
    for part in parts {
        if part.is_empty() {
            return Err("has an empty part".into());
        }
        if part.starts_with(|c: char| c.is_ascii_digit()) {
            return Err(format!("part `{part}` starts with a digit"));
        }
        if let Some(c) = part
            .chars()
            .find(|c| !(c.is_ascii_alphanumeric() || *c == '_' || *c == '-'))
        {
            return Err(format!(
                "contains `{c}`; wildcards and other symbols are not allowed"
            ));
        }
    }
    Ok(())
}

/// A relative path inside the bundle: `/`-separated, at most
/// [`MAX_PATH_BYTES`], no empty, `.` or `..` parts, not absolute.
/// With `dir_allowed`, one trailing `/` is accepted.
pub fn relative_path(path: &str, dir_allowed: bool) -> Result<(), String> {
    if path.is_empty() {
        return Err("is empty".into());
    }
    if path.len() > MAX_PATH_BYTES {
        return Err(format!("is longer than {MAX_PATH_BYTES} bytes"));
    }
    if path.starts_with('/') {
        return Err("must be relative to the bundle, not start with `/`".into());
    }
    let body = match path.strip_suffix('/') {
        Some(b) if dir_allowed => b,
        Some(_) => return Err("must name a file, not end with `/`".into()),
        None => path,
    };
    for part in body.split('/') {
        match part {
            "" => return Err("contains an empty part (`//`)".into()),
            "." | ".." => return Err(format!("contains `{part}`")),
            _ => {}
        }
    }
    Ok(())
}

/// A MIME type `type/subtype`, both RFC 6838 restricted names.
pub fn mime_type(m: &str) -> Result<(), String> {
    let restricted = |s: &str| {
        let mut chars = s.chars();
        s.len() <= 127
            && matches!(chars.next(), Some(c) if c.is_ascii_alphanumeric())
            && chars.all(|c| c.is_ascii_alphanumeric() || "!#$&^_.+-".contains(c))
    };
    match m.split_once('/') {
        Some((t, s)) if restricted(t) && restricted(s) => Ok(()),
        _ => Err("is not a MIME type such as `image/png`".into()),
    }
}

/// A URL scheme (RFC 3986), lowercase, and not `file`.
pub fn url_scheme(s: &str) -> Result<(), String> {
    let mut chars = s.chars();
    let ok = matches!(chars.next(), Some(c) if c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "+-.".contains(c));
    if !ok {
        return Err("is not a lowercase URL scheme such as `mailto`".into());
    }
    if s == "file" {
        return Err("`file` links cannot be claimed by an app".into());
    }
    Ok(())
}

/// Exactly 64 lowercase hexadecimal characters.
pub fn sha256_hex(s: &str) -> Result<(), String> {
    if s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        Err("must be exactly 64 lowercase hexadecimal characters".into())
    }
}

/// A web URL with one of `schemes` and a host.
pub fn web_url(s: &str, schemes: &[&str]) -> Result<(), String> {
    let url = url::Url::parse(s).map_err(|e| format!("is not a valid URL ({e})"))?;
    if !schemes.contains(&url.scheme()) {
        let list: Vec<String> = schemes.iter().map(|s| format!("{s}://")).collect();
        return Err(format!("must start with {}", list.join(" or ")));
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err("has no host".into());
    }
    Ok(())
}

/// A display string: `min..=max` characters and no control characters.
pub fn display_text(s: &str, min: usize, max: usize) -> Result<(), String> {
    let n = s.chars().count();
    if n < min {
        return Err("is empty".into());
    }
    if n > max {
        return Err(format!("is longer than {max} characters"));
    }
    if s.chars().any(char::is_control) {
        return Err("contains control characters such as newlines".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_ids() {
        for ok in [
            "org.libretro.RetroArch",
            "com.example.my-app",
            "io.github.user_name.App2",
        ] {
            assert!(app_id(ok).is_ok(), "{ok}");
        }
        for bad in [
            "org.example",
            "org..example.App",
            "org.example.App.",
            "org.2example.App",
            "org.my-example.App",
            "org.example.App!",
            "org.example.Äpp",
            "",
        ] {
            assert!(app_id(bad).is_err(), "{bad}");
        }
        assert!(app_id(&format!("org.example.{}", "a".repeat(250))).is_err());
    }

    #[test]
    fn dbus_names() {
        assert!(dbus_name("org.kde.kdeconnect").is_ok());
        assert!(dbus_name("org.example.Service-1").is_ok());
        for bad in ["org", "org.*", "org.kde.*", ":1.42", "org..kde", "org.1kde"] {
            assert!(dbus_name(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn paths() {
        assert!(relative_path("bin/app", false).is_ok());
        assert!(relative_path("vendor/", true).is_ok());
        assert!(relative_path("vendor/sub", true).is_ok());
        for bad in [
            "",
            "/bin/app",
            "bin//app",
            "./bin",
            "bin/../../etc",
            "..",
            "bin/.",
        ] {
            assert!(relative_path(bad, true).is_err(), "{bad}");
        }
        assert!(relative_path("bin/", false).is_err());
        assert!(relative_path("vendor//", true).is_err());
        assert!(relative_path(&"a/".repeat(2049), true).is_err());
    }

    #[test]
    fn mime_and_schemes() {
        assert!(mime_type("image/png").is_ok());
        assert!(mime_type("application/x-nes-rom").is_ok());
        assert!(mime_type("application/vnd.ms-excel").is_ok());
        for bad in [
            "image",
            "image/",
            "/png",
            "image/png/x",
            "image/p ng",
            "*/*",
        ] {
            assert!(mime_type(bad).is_err(), "{bad}");
        }
        assert!(url_scheme("mailto").is_ok());
        assert!(url_scheme("web+app").is_ok());
        for bad in ["file", "Mailto", "1abc", "", "a b", "a:"] {
            assert!(url_scheme(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn hashes_and_urls() {
        assert!(sha256_hex(&"a".repeat(64)).is_ok());
        assert!(sha256_hex(&"A".repeat(64)).is_err());
        assert!(sha256_hex(&"a".repeat(63)).is_err());
        assert!(sha256_hex(&"g".repeat(64)).is_err());
        assert!(web_url("https://example.org/x", &["https"]).is_ok());
        assert!(web_url("http://example.org/x", &["https"]).is_err());
        assert!(web_url("http://example.org", &["https", "http"]).is_ok());
        assert!(web_url("file:///etc/passwd", &["https", "http"]).is_err());
        assert!(web_url("not a url", &["https"]).is_err());
    }

    #[test]
    fn text() {
        assert!(display_text("RetroArch", 1, 64).is_ok());
        assert!(display_text("", 1, 64).is_err());
        assert!(display_text("a\nb", 1, 64).is_err());
        assert!(display_text(&"é".repeat(64), 1, 64).is_ok());
        assert!(display_text(&"é".repeat(65), 1, 64).is_err());
    }
}
