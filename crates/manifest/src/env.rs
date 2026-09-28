//! Environment variables owned by the launcher.
//!
//! This is the one authoritative list: the launcher sets (or deliberately
//! clears) these, and the manifest validator refuses them in `compat.env`.
//! Both sides use these constants, so they cannot drift apart.

/// Any variable whose name starts with one of these is reserved.
pub const RESERVED_PREFIXES: &[&str] =
    &["LD_", "XDG_", "DBUS_", "WAYLAND_", "PIPEWIRE_", "AT_SPI_"];

/// Exact variable names reserved for the launcher.
pub const RESERVED_NAMES: &[&str] = &[
    // Identity and folders (spec section 9)
    "HOME",
    "TMPDIR",
    "PATH",
    "USER",
    "LOGNAME",
    "SHELL",
    // Toolkit and portal settings (spec section 10, launch step 5)
    "GDK_BACKEND",
    "QT_QPA_PLATFORM",
    "SDL_VIDEODRIVER",
    "GTK_USE_PORTAL",
    "QT_QPA_PLATFORMTHEME",
    "SECRET_BACKEND",
    // Connections the launcher hands in, or keeps out
    "SSH_AUTH_SOCK",
    "DISPLAY",
    "NOTIFY_SOCKET",
    "LISTEN_FDS",
];

/// Whether `name` is reserved for the launcher.
pub fn is_reserved(name: &str) -> bool {
    RESERVED_NAMES.contains(&name) || RESERVED_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// Whether `name` is a well-formed environment variable name: `[A-Za-z_][A-Za-z0-9_]*`.
pub fn is_valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved() {
        assert!(is_reserved("HOME"));
        assert!(is_reserved("LD_PRELOAD"));
        assert!(is_reserved("XDG_DATA_HOME"));
        assert!(is_reserved("GDK_BACKEND"));
        assert!(!is_reserved("MY_SETTING"));
        assert!(!is_reserved("HOMEPAGE"));
    }

    #[test]
    fn names() {
        assert!(is_valid_name("_X1"));
        assert!(is_valid_name("MOZ_ENABLE_WAYLAND"));
        assert!(!is_valid_name(""));
        assert!(!is_valid_name("1X"));
        assert!(!is_valid_name("A-B"));
        assert!(!is_valid_name("A=B"));
    }
}
