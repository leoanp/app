use super::*;
use crate::bundle::{self, MemoryFs};

/// The example from spec section 6.
const SPEC_EXAMPLE: &str = r#"
format = 1

[app]
id = "org.libretro.RetroArch"
name = "RetroArch"
version = "1.19.1"
build = 42
arch = "aarch64"
exec = "bin/retroarch"
summary = "Frontend for emulators and game engines"
license = "GPL-3.0-or-later"
source = "https://github.com/libretro/RetroArch"
categories = ["Game", "Emulator"]

[requires]
glibc = "2.39"

[permissions]
network = true
audio = true
gamepad = true

[permissions.folders]
roms = { access = "read", reason = "To find and load your games" }

[ui]
inputs = ["gamepad", "touch", "pointer"]
"#;

/// Replaces `from` with `to` in the spec example (panics if absent).
fn edit(from: &str, to: &str) -> String {
    assert!(
        SPEC_EXAMPLE.contains(from),
        "test bug: {from:?} not in example"
    );
    SPEC_EXAMPLE.replacen(from, to, 1)
}

fn refused(text: &str) -> Error {
    match parse(text) {
        Ok(p) => panic!("should be refused, parsed: {:?}", p.manifest),
        Err(e) => e,
    }
}

fn refused_on(text: &str, field: &str) -> Error {
    let e = refused(text);
    assert!(
        e.problems.iter().any(|p| p.field == field),
        "expected a problem on {field:?}, got:\n{e}"
    );
    e
}

fn warnings(text: &str) -> Vec<Warning> {
    match parse(text) {
        Ok(p) => p.warnings,
        Err(e) => panic!("should parse, got:\n{e}"),
    }
}

#[test]
fn spec_example_parses() {
    let p = parse(SPEC_EXAMPLE).unwrap();
    let m = &p.manifest;
    assert!(p.warnings.is_empty(), "{:?}", p.warnings);
    assert_eq!(m.app.id, "org.libretro.RetroArch");
    assert_eq!(m.app.build, 42);
    assert_eq!(m.app.arch, Arch::Aarch64);
    assert_eq!(m.requires.glibc, "2.39".parse().unwrap());
    assert!(m.permissions.network && m.permissions.audio && m.permissions.gamepad);
    assert!(!m.permissions.background);
    let roms = &m.permissions.folders[&Folder::Roms];
    assert_eq!(roms.access, Access::Read);
    assert_eq!(
        m.inputs(),
        vec![Input::Gamepad, Input::Touch, Input::Pointer]
    );
}

#[test]
fn round_trips_through_toml() {
    let mut m = parse(SPEC_EXAMPLE).unwrap().manifest;
    m.requires.gl = Some("3.3".parse().unwrap());
    m.permissions.removable = Some(Grant {
        access: Access::ReadWrite,
        reason: None,
    });
    m.permissions.services = vec!["org.kde.kdeconnect".into()];
    m.compat.prefix = Some("/app".into());
    m.compat.env.insert("MOZ_ENABLE_WAYLAND".into(), "1".into());
    m.reasons.insert("camera".into(), "To scan QR codes".into());
    m.external.push(External {
        url: "https://vendor.example/app.tar.gz".into(),
        sha256: "ab".repeat(32),
        size: 1000,
        dest: "vendor/".into(),
        unpack: Some(Unpack::Tar),
    });
    let text = m.to_toml().unwrap();
    let again = parse(&text).unwrap();
    assert_eq!(again.manifest, m, "\n{text}");
    assert!(again.warnings.is_empty());
}

#[test]
fn to_toml_refuses_invalid_manifest() {
    let mut m = parse(SPEC_EXAMPLE).unwrap().manifest;
    m.app.id = "bad".into();
    assert!(m.to_toml().is_err());
}

// ---- format and requires: fail closed as "needs a newer system" ----

#[test]
fn format() {
    let e = refused(&edit("format = 1", "format = 2"));
    assert!(e.needs_newer_system());
    let e = refused_on(&edit("format = 1", ""), "format");
    assert!(!e.needs_newer_system());
    refused_on(&edit("format = 1", "format = \"1\""), "format");
}

#[test]
fn unknown_requires_key_needs_newer_system() {
    let e = refused_on(
        &edit("glibc = \"2.39\"", "glibc = \"2.39\"\nopencl = \"3.0\""),
        "requires.opencl",
    );
    assert!(e.needs_newer_system());
}

#[test]
fn requires_versions() {
    refused(&edit("glibc = \"2.39\"", "glibc = \"2.39a\""));
    refused(&edit("glibc = \"2.39\"", "glibc = 2.39"));
    refused(&edit("glibc = \"2.39\"", "libstdcxx = \"3.4.30\""));
    let m = parse(&edit(
        "glibc = \"2.39\"",
        "glibc = \"2.39\"\ngl = \"3.3\"\ngles = \"3.2\"",
    ))
    .unwrap()
    .manifest;
    let keys: Vec<_> = m.requires.entries().into_iter().map(|(k, _)| k).collect();
    assert_eq!(keys, ["glibc", "gles", "gl"]);
}

// ---- unknown keys vs unknown values ----

#[test]
fn unknown_fields_are_ignored_with_warning() {
    let w = warnings(&edit("[ui]", "[ui]\nfancy = true"));
    assert!(w.iter().any(|w| w.field == "ui.fancy"), "{w:?}");
    let w = warnings(&format!("{SPEC_EXAMPLE}\n[future]\nthing = 1\n"));
    assert!(w.iter().any(|w| w.field == "future"), "{w:?}");
}

#[test]
fn unknown_permission_is_ignored_and_never_granted() {
    let w = warnings(&edit("gamepad = true", "gamepad = true\nbluetooth = true"));
    let w = w
        .iter()
        .find(|w| w.field == "permissions.bluetooth")
        .unwrap();
    assert!(w.message.contains("never granted"));
}

#[test]
fn unknown_values_are_refused() {
    refused(&edit("roms = {", "home = {"));
    refused(&edit("access = \"read\"", "access = \"write\""));
    refused(&edit("arch = \"aarch64\"", "arch = \"riscv64\""));
    refused(&edit("network = true", "network = \"yes\""));
    refused(&format!(
        "{SPEC_EXAMPLE}\n[[external]]\nurl = \"https://x.example/a\"\nsha256 = \"{}\"\nsize = 1\ndest = \"v/\"\nunpack = \"rar\"\n",
        "a".repeat(64)
    ));
}

#[test]
fn missing_required_fields() {
    for field in ["id", "name", "version", "build", "arch", "exec", "license"] {
        let text: String = SPEC_EXAMPLE
            .lines()
            .filter(|l| !l.starts_with(&format!("{field} =")))
            .collect::<Vec<_>>()
            .join("\n");
        refused(&text);
    }
    refused(&edit("glibc = \"2.39\"", ""));
    refused(&edit("inputs = [\"gamepad\", \"touch\", \"pointer\"]", ""));
}

// ---- app fields ----

#[test]
fn app_id_rules() {
    refused_on(
        &edit("org.libretro.RetroArch", "libretro.RetroArch"),
        "app.id",
    );
    refused_on(
        &edit("org.libretro.RetroArch", "org.lib-retro.RetroArch"),
        "app.id",
    );
    assert!(parse(&edit("org.libretro.RetroArch", "org.libretro.Retro-Arch")).is_ok());
}

#[test]
fn app_text_and_numbers() {
    refused_on(&edit("name = \"RetroArch\"", "name = \"\""), "app.name");
    refused_on(
        &edit("name = \"RetroArch\"", "name = \"Retro\\nArch\""),
        "app.name",
    );
    refused_on(
        &edit(
            "name = \"RetroArch\"",
            &format!("name = \"{}\"", "x".repeat(65)),
        ),
        "app.name",
    );
    refused_on(&edit("build = 42", "build = 0"), "app.build");
    refused_on(&edit("build = 42", "build = -1"), "app.build");
    refused_on(&edit("bin/retroarch", "/usr/bin/retroarch"), "app.exec");
    refused_on(&edit("bin/retroarch", "bin/../../retroarch"), "app.exec");
    refused_on(
        &edit("Frontend for emulators and game engines", &"x".repeat(201)),
        "app.summary",
    );
}

#[test]
fn license_and_source() {
    refused_on(&edit("GPL-3.0-or-later", "Not A License"), "app.license");
    // Deprecated identifiers are still valid SPDX.
    assert!(parse(&edit("GPL-3.0-or-later", "GPL-3.0")).is_ok());
    assert!(parse(&edit("GPL-3.0-or-later", "MIT OR Apache-2.0")).is_ok());

    let no_source = edit("source = \"https://github.com/libretro/RetroArch\"", "");
    refused_on(&no_source, "app.source");
    let proprietary = no_source.replace("GPL-3.0-or-later", "LicenseRef-proprietary");
    assert!(parse(&proprietary).is_ok());
    // Partly open source still needs the source.
    refused_on(
        &no_source.replace("GPL-3.0-or-later", "LicenseRef-proprietary AND MIT"),
        "app.source",
    );

    refused_on(
        &edit("https://github.com", "ftp://github.com"),
        "app.source",
    );
    refused_on(
        &edit(
            "categories",
            "homepage = \"javascript:alert(1)\"\ncategories",
        ),
        "app.homepage",
    );
}

#[test]
fn categories() {
    let w = warnings(&edit("\"Game\", \"Emulator\"", "\"Game\", \"Gaming\""));
    assert!(w.iter().any(|w| w.message.contains("Gaming")), "{w:?}");
    let many = vec!["\"Game\""; 65].join(", ");
    refused_on(&edit("\"Game\", \"Emulator\"", &many), "app.categories");
}

// ---- permissions ----

#[test]
fn services() {
    let with = |s: &str| {
        edit(
            "gamepad = true",
            &format!("gamepad = true\nservices = [\"{s}\"]"),
        )
    };
    assert!(parse(&with("org.kde.kdeconnect")).is_ok());
    refused_on(&with("org.kde.*"), "permissions.services");
    refused_on(&with("org.freedesktop.DBus"), "permissions.services");
    refused_on(
        &with("org.freedesktop.portal.Desktop"),
        "permissions.services",
    );
    refused_on(
        &with("org.freedesktop.impl.portal.Secret"),
        "permissions.services",
    );
}

#[test]
fn boolean_permissions_and_removable() {
    let text = edit(
        "gamepad = true",
        "gamepad = true\nbackground = true\nprinting = true\nssh_agent = true\nremovable = { access = \"read-write\" }",
    );
    let p = parse(&text).unwrap().manifest.permissions;
    assert!(p.background && p.printing && p.ssh_agent);
    assert_eq!(p.removable.unwrap().access, Access::ReadWrite);
    refused(&edit("gamepad = true", "gamepad = true\nprinting = 1"));
    refused(&edit(
        "gamepad = true",
        "gamepad = true\nremovable = { access = \"all\" }",
    ));
}

#[test]
fn reasons() {
    let long = "x".repeat(501);
    refused_on(
        &edit("To find and load your games", &long),
        "permissions.folders.roms.reason",
    );
    let text =
        format!("{SPEC_EXAMPLE}\n[reasons]\ncamera = \"To scan codes\"\nteleport = \"why not\"\n");
    let w = warnings(&text);
    assert!(w.iter().any(|w| w.field == "reasons.teleport"), "{w:?}");
    refused_on(
        &format!("{SPEC_EXAMPLE}\n[reasons]\ncamera = \"{long}\"\n"),
        "reasons.camera",
    );
}

// ---- ui, integration, compat ----

#[test]
fn inputs() {
    let w = warnings(&edit("\"gamepad\", \"touch\"", "\"gamepad\", \"voice\""));
    assert!(w.iter().any(|w| w.field == "ui.inputs"));
    refused_on(
        &edit("[\"gamepad\", \"touch\", \"pointer\"]", "[\"voice\"]"),
        "ui.inputs",
    );
    refused_on(
        &edit("[\"gamepad\", \"touch\", \"pointer\"]", "[]"),
        "ui.inputs",
    );
    refused_on(&edit("[ui]", "[ui]\nmin_width = 0"), "ui.min_width");
    refused_on(&edit("[ui]", "[ui]\nmin_width = 16385"), "ui.min_width");
}

#[test]
fn integration() {
    let with = |k: &str, v: &str| format!("{SPEC_EXAMPLE}\n[integration]\n{k} = [\"{v}\"]\n");
    assert!(parse(&with("mime_types", "application/x-nes-rom")).is_ok());
    refused_on(&with("mime_types", "nes"), "integration.mime_types");
    assert!(parse(&with("url_schemes", "mailto")).is_ok());
    refused_on(&with("url_schemes", "file"), "integration.url_schemes");
    refused_on(&with("url_schemes", "HTTP"), "integration.url_schemes");
}

#[test]
fn compat() {
    let with = |body: &str| format!("{SPEC_EXAMPLE}\n[compat]\n{body}\n");
    assert!(
        parse(&with(
            "prefix = \"/app\"\nenv = { SDL_AUDIODRIVER = \"pipewire\" }"
        ))
        .is_ok()
    );
    refused_on(&with("prefix = \"/opt/app\""), "compat.prefix");
    for reserved in [
        "LD_PRELOAD",
        "HOME",
        "XDG_RUNTIME_DIR",
        "GDK_BACKEND",
        "SSH_AUTH_SOCK",
        "LISTEN_FDS",
    ] {
        refused_on(
            &with(&format!("env = {{ {reserved} = \"x\" }}")),
            &format!("compat.env.{reserved}"),
        );
    }
    refused_on(&with("env = { \"A-B\" = \"x\" }"), "compat.env.A-B");
}

#[test]
fn external_files() {
    let ext = |url: &str, sha: &str, size: &str, dest: &str| {
        format!(
            "{SPEC_EXAMPLE}\n[[external]]\nurl = \"{url}\"\nsha256 = \"{sha}\"\nsize = {size}\ndest = \"{dest}\"\n"
        )
    };
    let sha = "a".repeat(64);
    assert!(parse(&ext("https://vendor.example/a.tgz", &sha, "100", "vendor/")).is_ok());
    refused_on(
        &ext("http://vendor.example/a.tgz", &sha, "100", "vendor/"),
        "external[0].url",
    );
    refused_on(
        &ext(
            "https://vendor.example/a.tgz",
            &sha.to_uppercase(),
            "100",
            "vendor/",
        ),
        "external[0].sha256",
    );
    refused_on(
        &ext("https://vendor.example/a.tgz", &sha, "0", "vendor/"),
        "external[0].size",
    );
    refused_on(
        &ext(
            "https://vendor.example/a.tgz",
            &sha,
            "68719476737",
            "vendor/",
        ),
        "external[0].size",
    );
    refused_on(
        &ext("https://vendor.example/a.tgz", &sha, "100", "../vendor/"),
        "external[0].dest",
    );
    refused(&ext("https://vendor.example/a.tgz", &sha, "-1", "vendor/"));
}

// ---- limits ----

#[test]
fn limits() {
    refused_on(
        &edit("name = \"RetroArch\"", "name = \"Retro\\u0000Arch\""),
        "app.name",
    );
    refused(&format!(
        "{SPEC_EXAMPLE}\n# {}\n",
        "x".repeat(MAX_MANIFEST_BYTES)
    ));
    refused_on(
        &edit("[ui]", &format!("[ui]\nextra = \"{}\"", "x".repeat(1025))),
        "ui.extra",
    );
    let big_list = vec!["1"; 65].join(",");
    refused_on(
        &edit("[ui]", &format!("[ui]\nextra = [{big_list}]")),
        "ui.extra",
    );
    // Arguments have their own, larger limits.
    let with_args = |args: String| {
        edit(
            "exec = \"bin/retroarch\"",
            &format!("exec = \"bin/retroarch\"\nargs = [{args}]"),
        )
    };
    assert!(
        parse(&with_args(
            vec![format!("\"{}\"", "a".repeat(4000)); 3].join(",")
        ))
        .is_ok()
    );
    assert!(parse(&with_args(vec!["\"-v\""; 256].join(","))).is_ok());
    refused_on(&with_args(vec!["\"-v\""; 257].join(",")), "app.args");
}

#[test]
fn not_toml() {
    refused("format = 1\n[app\n");
}

// ---- bundle tree ----

fn png(w: u32, h: u32) -> Vec<u8> {
    let mut out = Vec::new();
    let mut enc = png::Encoder::new(&mut out, w, h);
    enc.set_color(png::ColorType::Rgba);
    let mut writer = enc.write_header().unwrap();
    writer
        .write_image_data(&vec![0; (w * h * 4) as usize])
        .unwrap();
    writer.finish().unwrap();
    out
}

fn good_bundle() -> MemoryFs {
    let mut fs = MemoryFs::new();
    fs.file("manifest.toml", SPEC_EXAMPLE.as_bytes(), false)
        .file("bin/retroarch", b"\x7fELF", true)
        .file("lib/libfoo.so.1", b"\x7fELF", false)
        .file("icons/256.png", &png(256, 256), false);
    fs
}

fn example() -> Manifest {
    parse(SPEC_EXAMPLE).unwrap().manifest
}

fn bundle_refused_on(fs: &MemoryFs, m: &Manifest, field: &str) {
    let e = bundle::check(m, fs).expect_err("bundle should be refused");
    assert!(
        e.problems.iter().any(|p| p.field == field),
        "expected a problem on {field:?}, got:\n{e}"
    );
}

#[test]
fn good_bundle_passes() {
    bundle::check(&example(), &good_bundle()).unwrap();
}

#[test]
fn icons() {
    let mut fs = good_bundle();
    fs.file("icons/256.png", &png(128, 128), false);
    bundle_refused_on(&fs, &example(), "icons/256.png");
    fs.file("icons/256.png", b"not a png", false);
    bundle_refused_on(&fs, &example(), "icons/256.png");
    let mut truncated = png(256, 256);
    truncated.truncate(truncated.len() - 20);
    fs.file("icons/256.png", &truncated, false);
    bundle_refused_on(&fs, &example(), "icons/256.png");

    let mut fs = good_bundle();
    fs.file("icons/scalable.svg", &vec![b' '; 1 << 20], false);
    bundle::check(&example(), &fs).unwrap();
    fs.file("icons/scalable.svg", &vec![b' '; (1 << 20) + 1], false);
    bundle_refused_on(&fs, &example(), "icons/scalable.svg");

    let mut fs = MemoryFs::new();
    fs.file("manifest.toml", b"", false)
        .file("bin/retroarch", b"", true);
    bundle_refused_on(&fs, &example(), "icons/256.png");
}

#[test]
fn exec_must_be_an_executable_file() {
    let mut fs = good_bundle();
    fs.file("bin/retroarch", b"", false);
    bundle_refused_on(&fs, &example(), "app.exec");

    let mut m = example();
    m.app.exec = "bin/missing".into();
    bundle_refused_on(&good_bundle(), &m, "app.exec");

    m.app.exec = "bin".into();
    bundle_refused_on(&good_bundle(), &m, "app.exec");

    // Through a symlink inside the bundle is fine.
    let mut fs = good_bundle();
    fs.file("libexec/real", b"", true)
        .symlink("bin/app", "../libexec/real");
    m.app.exec = "bin/app".into();
    bundle::check(&m, &fs).unwrap();
}

#[test]
fn exec_inside_external_dest_is_checked_after_download() {
    let mut m = example();
    m.app.exec = "vendor/bin/app".into();
    m.external.push(External {
        url: "https://vendor.example/a.tgz".into(),
        sha256: "a".repeat(64),
        size: 1,
        dest: "vendor/".into(),
        unpack: Some(Unpack::Tar),
    });
    bundle::check(&m, &good_bundle()).unwrap();
    assert!(bundle::check_exec(&m, &good_bundle()).is_err());
    let mut fs = good_bundle();
    fs.file("vendor/bin/app", b"", true);
    bundle::check_exec(&m, &fs).unwrap();
}

#[test]
fn symlinks_must_stay_inside() {
    let cases = [
        ("lib/abs", "/usr/lib/libfoo.so"),
        ("lib/up", "../../etc/shadow"),
        ("up", ".."),
    ];
    for (link, target) in cases {
        let mut fs = good_bundle();
        fs.symlink(link, target);
        bundle_refused_on(&fs, &example(), link);
    }

    // Lexically `self/..` is the root, but `self` points to `.` at the root,
    // so the kernel would climb out: resolution must follow the real tree.
    let mut fs = good_bundle();
    fs.symlink("self", ".")
        .symlink("lib/sneaky", "../self/../..");
    bundle_refused_on(&fs, &example(), "lib/sneaky");

    let mut fs = good_bundle();
    fs.symlink("a", "b").symlink("b", "a");
    bundle_refused_on(&fs, &example(), "a");

    // Fine: relative, inside, possibly dangling.
    let mut fs = good_bundle();
    fs.symlink("lib/libfoo.so", "libfoo.so.1")
        .symlink("share/doc", "../missing/doc");
    bundle::check(&example(), &fs).unwrap();
}

#[test]
fn special_files_refused() {
    let mut fs = good_bundle();
    fs.special("dev/null");
    bundle_refused_on(&fs, &example(), "dev/null");
}
