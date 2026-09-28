//! The manifest's data model (spec section 6, "Field reference").
//!
//! These types only describe shape. Rules that go beyond shape (lengths,
//! syntax, required-unless) live in `validate`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::version::Version;

/// The only format version this crate understands.
pub const FORMAT: i64 = 1;

/// A parsed `manifest.toml`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    pub format: i64,
    pub app: App,
    pub requires: Requires,
    #[serde(default, skip_serializing_if = "Permissions::is_empty")]
    pub permissions: Permissions,
    /// Prompt text keyed by permission name, such as `reasons.camera`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub reasons: BTreeMap<String, String>,
    pub ui: Ui,
    #[serde(default, skip_serializing_if = "Integration::is_empty")]
    pub integration: Integration,
    #[serde(default, skip_serializing_if = "Compat::is_empty")]
    pub compat: Compat,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub external: Vec<External>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct App {
    pub id: String,
    pub name: String,
    pub version: String,
    pub build: i64,
    pub arch: Arch,
    pub exec: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    pub license: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub homepage: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub categories: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Arch {
    #[serde(rename = "x86_64")]
    X86_64,
    #[serde(rename = "aarch64")]
    Aarch64,
}

impl Arch {
    pub fn as_str(self) -> &'static str {
        match self {
            Arch::X86_64 => "x86_64",
            Arch::Aarch64 => "aarch64",
        }
    }
}

/// Foundation versions the app needs. Unknown keys are refused: a platform
/// that cannot check a requirement must not install the app.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Requires {
    pub glibc: Version,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub libstdcxx: Option<Version>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vulkan: Option<Version>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gles: Option<Version>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gl: Option<Version>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub libva: Option<Version>,
}

/// Every key allowed in `[requires]`.
pub const REQUIRES_KEYS: &[&str] = &["glibc", "libstdcxx", "vulkan", "gles", "gl", "libva"];

impl Requires {
    /// The requirements that are set, as `(key, version)` pairs.
    pub fn entries(&self) -> Vec<(&'static str, &Version)> {
        let optional = [
            ("libstdcxx", &self.libstdcxx),
            ("vulkan", &self.vulkan),
            ("gles", &self.gles),
            ("gl", &self.gl),
            ("libva", &self.libva),
        ];
        std::iter::once(("glibc", &self.glibc))
            .chain(
                optional
                    .into_iter()
                    .filter_map(|(k, v)| v.as_ref().map(|v| (k, v))),
            )
            .collect()
    }
}

/// Install-time permissions (spec sections 6 and 8).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Permissions {
    #[serde(default, skip_serializing_if = "is_false")]
    pub network: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub audio: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub gamepad: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub background: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub printing: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub ssh_agent: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removable: Option<Grant>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub folders: BTreeMap<Folder, Grant>,
}

impl Permissions {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// The shared folders of format version 1 (spec section 8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Folder {
    Documents,
    Downloads,
    Music,
    Pictures,
    Videos,
    Roms,
}

/// Access to a shared folder or removable drives.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    pub access: Access,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Access {
    Read,
    ReadWrite,
}

/// Permission names accepted as keys of `[reasons]`: the install-time
/// permissions plus those asked for at run time through the portal.
pub const REASON_KEYS: &[&str] = &[
    "network",
    "audio",
    "gamepad",
    "removable",
    "background",
    "printing",
    "ssh_agent",
    "services",
    "camera",
    "microphone",
    "location",
    "notifications",
    "screen_sharing",
    "global_shortcuts",
    "usb",
    "autostart",
];

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Ui {
    /// Kept as written; entries this format does not know are ignored.
    /// See [`Manifest::inputs`].
    pub inputs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_width: Option<i64>,
}

/// Input methods of format version 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Input {
    Gamepad,
    Touch,
    Pointer,
    Keyboard,
    Remote,
}

impl Input {
    pub const ALL: [Input; 5] = [
        Input::Gamepad,
        Input::Touch,
        Input::Pointer,
        Input::Keyboard,
        Input::Remote,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Input::Gamepad => "gamepad",
            Input::Touch => "touch",
            Input::Pointer => "pointer",
            Input::Keyboard => "keyboard",
            Input::Remote => "remote",
        }
    }

    pub fn from_name(s: &str) -> Option<Input> {
        Input::ALL.into_iter().find(|i| i.as_str() == s)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Integration {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mime_types: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub url_schemes: Vec<String>,
}

impl Integration {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Compat {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
}

impl Compat {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// The only value `compat.prefix` may take.
pub const COMPAT_PREFIX: &str = "/app";

/// A file downloaded by the device from its publisher (spec section 5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct External {
    pub url: String,
    pub sha256: String,
    pub size: u64,
    pub dest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unpack: Option<Unpack>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Unpack {
    Tar,
    Zip,
    Deb,
}

impl Manifest {
    /// The input methods this format knows, in the order written.
    pub fn inputs(&self) -> Vec<Input> {
        self.ui
            .inputs
            .iter()
            .filter_map(|s| Input::from_name(s))
            .collect()
    }
}

fn is_false(b: &bool) -> bool {
    !*b
}
