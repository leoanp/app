use super::*;

fn spec() -> Foundation {
    Foundation::spec().unwrap()
}

fn v(s: &str) -> Version {
    s.parse().unwrap()
}

/// A platform list: the spec's list plus `extra`.
fn platform(extra: &str) -> Foundation {
    Foundation::parse(&format!("{SPEC_FOUNDATION_TOML}\n{extra}")).unwrap()
}

fn requires(extra: &str) -> Requires {
    let text = format!(
        "format = 1\n[app]\nid = \"org.example.A\"\nname = \"A\"\nversion = \"1\"\nbuild = 1\n\
         arch = \"x86_64\"\nexec = \"bin/a\"\nlicense = \"MIT\"\nsource = \"https://example.org\"\n\
         [requires]\nglibc = \"2.39\"\n{extra}\n[ui]\ninputs = [\"pointer\"]\n"
    );
    app_manifest::parse(&text).unwrap().manifest.requires
}

#[test]
fn spec_list_loads() {
    let f = spec();
    let ids: Vec<_> = f.components.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "glibc",
            "cxx-runtime",
            "vulkan",
            "libglvnd",
            "mesa",
            "x11-driver-libs",
            "driver-deps",
            "libva",
            "wayland",
            "audio"
        ]
    );
    assert!(f.provides.is_empty());
}

#[test]
fn every_requires_key_has_a_component() {
    let f = spec();
    for key in REQUIRES_KEYS {
        assert!(
            f.component_for(key).is_some(),
            "no component answers `{key}`"
        );
    }
    assert_eq!(f.component_for("gl").unwrap().id, "libglvnd");
    assert_eq!(
        f.component_for("glibc").unwrap().symbol_prefix.as_deref(),
        Some("GLIBC_")
    );
    assert_eq!(
        f.component_for("libstdcxx")
            .unwrap()
            .symbol_prefix
            .as_deref(),
        Some("GLIBCXX_")
    );
}

#[test]
fn classifies_foundation_libraries() {
    let f = spec();
    for (name, component) in [
        ("libc.so.6", "glibc"),
        ("ld-linux-aarch64.so.1", "glibc"),
        ("libstdc++.so.6", "cxx-runtime"),
        ("libGL.so.1", "libglvnd"),
        ("libGLX.so.0", "libglvnd"),
        ("libEGL.so.1", "libglvnd"),
        ("libX11.so.6", "x11-driver-libs"),
        ("libxcb.so.1", "x11-driver-libs"),
        ("libwayland-client.so.0", "wayland"),
        ("libpipewire-0.3.so.0", "audio"),
        ("libasound.so.2", "audio"),
        ("libz.so.1", "driver-deps"),
        ("libzstd.so.1", "driver-deps"),
        ("libexpat.so.1", "driver-deps"),
        ("libffi.so.8", "driver-deps"),
        ("libudev.so.1", "driver-deps"),
    ] {
        match f.classify(name) {
            Class::Foundation(c) => assert_eq!(c.id, component, "{name}"),
            other => panic!("{name} classified as {other:?}"),
        }
    }
}

#[test]
fn classifies_driver_internal_libraries() {
    let f = spec();
    for name in [
        "libdrm_amdgpu.so.1",
        "libGLX_mesa.so.0",
        "libEGL_mesa.so.0",
        "libgallium-25.2.3.so",
        "libvulkan_radeon.so",
        "radeonsi_drv_video.so",
        "iris_dri.so",
        "libglapi.so.0",
        "libLLVM.so.22.1",
        "libLLVM-17.so",
        "libSPIRV-Tools.so",
        "libelf.so.1",
        "libdisplay-info.so.3",
    ] {
        assert!(
            matches!(f.classify(name), Class::DriverInternal(_)),
            "{name}"
        );
        assert!(!f.classify(name).may_bundle());
    }
}

#[test]
fn everything_else_is_bundled() {
    let f = spec();
    // Section 4's "always bundled" examples, including X11 libraries outside the guaranteed set.
    for name in [
        "libSDL2-2.0.so.0",
        "libfontconfig.so.1",
        "libfreetype.so.6",
        "libharfbuzz.so.0",
        "libssl.so.3",
        "libXrandr.so.2",
        "libXi.so.6",
        "libXcursor.so.1",
        "libxkbcommon-x11.so.0",
        "libva-x11.so.2",
        "libcrypt.so.2",
        "libGLU.so.1",
    ] {
        assert_eq!(f.classify(name), Class::Bundle, "{name}");
    }
}

#[test]
fn glob_patterns() {
    assert!(glob("libdrm_*.so.*", "libdrm_intel.so.1"));
    assert!(!glob("libdrm_*.so.*", "libdrm.so.2"));
    assert!(glob("*_dri.so", "iris_dri.so"));
    assert!(!glob("*_dri.so", "iris_dri.so.1"));
    assert!(glob("libgallium*.so", "libgallium.so"));
    assert!(glob("a*b*c", "abc"));
    assert!(!glob("a*bc*c", "abc"));
    assert!(glob("exact", "exact"));
    assert!(!glob("exact", "exactly"));
}

#[test]
fn platform_list_may_add_never_drop() {
    let spec = spec();
    let good = platform("[provides]\nglibc = \"2.40\"\nlibstdcxx = \"3.4.33\"\n");
    spec.check_platform(&good).unwrap();

    // Adding a soname to a component is fine.
    let added = SPEC_FOUNDATION_TOML.replace(
        "\"libXdmcp.so.6\",",
        "\"libXdmcp.so.6\",\n    \"libXinerama.so.1\",",
    );
    let added = Foundation::parse(&format!(
        "{added}\n[provides]\nglibc = \"2.40\"\nlibstdcxx = \"3.4.33\"\n"
    ))
    .unwrap();
    spec.check_platform(&added).unwrap();

    // Dropping one is not.
    let dropped = SPEC_FOUNDATION_TOML.replace("    \"libXxf86vm.so.1\",\n", "");
    let dropped = Foundation::parse(&format!(
        "{dropped}\n[provides]\nglibc = \"2.40\"\nlibstdcxx = \"3.4.33\"\n"
    ))
    .unwrap();
    let problems = spec.check_platform(&dropped).unwrap_err();
    assert!(
        problems.iter().any(|p| p.contains("libXxf86vm.so.1")),
        "{problems:?}"
    );

    // glibc and libstdcxx versions are mandatory.
    let problems = spec.check_platform(&platform("")).unwrap_err();
    assert_eq!(problems.len(), 2, "{problems:?}");
}

#[test]
fn requirements_checked_against_provides() {
    let p = platform(
        "[provides]\nglibc = \"2.40\"\nlibstdcxx = \"3.4.33\"\ngles = \"3.2\"\ngl = \"3.1\"\n",
    );
    assert!(p.check_requires(&requires("")).is_empty());
    assert!(
        p.check_requires(&requires("gles = \"3.2\"\nlibstdcxx = \"3.4.30\""))
            .is_empty()
    );

    let unmet = p.check_requires(&requires("gl = \"3.3\"\nvulkan = \"1.1\""));
    assert_eq!(
        unmet,
        vec![
            Unmet {
                key: "vulkan",
                needed: v("1.1"),
                provided: None
            },
            Unmet {
                key: "gl",
                needed: v("3.3"),
                provided: Some(v("3.1"))
            },
        ]
    );

    // After a rollback to an older system, a newer glibc requirement is unmet.
    let old = platform("[provides]\nglibc = \"2.38\"\nlibstdcxx = \"3.4.32\"\n");
    assert_eq!(old.check_requires(&requires(""))[0].key, "glibc");
}

#[test]
fn malformed_lists_are_refused() {
    let bad = |text: &str| assert!(Foundation::parse(text).is_err(), "{text}");
    bad("format = 2\ncomponent = []");
    bad(
        "format = 1\n[[component]]\nid = \"a\"\nsummary = \"\"\nsonames = [\"x.so\"]\n[[component]]\nid = \"a\"\nsummary = \"\"\nsonames = []",
    );
    bad("format = 1\n[[component]]\nid = \"a\"\nsummary = \"\"\nsonames = [\"x.so\", \"x.so\"]");
    bad("format = 1\n[[component]]\nid = \"a\"\nsummary = \"\"\nsonames = [\"lib/x.so\"]");
    bad(
        "format = 1\n[[component]]\nid = \"a\"\nsummary = \"\"\nsonames = []\nnever_bundle = [\"*\"]",
    );
    bad(
        "format = 1\n[[component]]\nid = \"a\"\nsummary = \"\"\nsonames = []\nrequires = [\"opencl\"]",
    );
    bad("format = 1\ncomponent = []\n[provides]\nopencl = \"3.0\"");
    bad("format = 1\ncomponent = []\n[provides]\nglibc = \"two\"");
}

#[test]
fn recognizes_full_version_file_names() {
    let f = spec();
    for (file, component) in [
        ("libstdc++.so.6.0.33", "cxx-runtime"),
        ("libz.so.1.3.1", "driver-deps"),
        ("libX11.so.6.4.0", "x11-driver-libs"),
        ("libvulkan.so.1.4.321", "vulkan"),
        ("libpipewire-0.3.so.0.1400.0", "audio"),
    ] {
        match f.classify(file) {
            Class::Foundation(c) => assert_eq!(c.id, component, "{file}"),
            other => panic!("{file} classified as {other:?}"),
        }
    }
    // Only a `.` after the soname continues it.
    for file in ["libc.so.60", "libz.so.10", "libGL.so.1x", "libz.so"] {
        assert_eq!(f.classify(file), Class::Bundle, "{file}");
    }
}
