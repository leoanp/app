# CLAUDE.md — the `.app` project

Read this file and `spec/spec.md` before doing anything. The spec is the source of truth for **what** to build; this file explains **why**, what was deliberately rejected, and **how** to build it.

## 1. What this project is

`.app` is an open, OS-neutral app format for modern Linux: one sealed file per app, isolated by the kernel, with nothing running beside it. It aims for iOS-like simplicity and reliability ("tap install, it works, it keeps working") while staying open (any store, sideloading, open spec).

This repository contains:
- the spec (`spec/spec.md`) and the machine-readable foundation list (`spec/foundation.toml`);
- the **runtime** that installs and runs apps on a device (`app` command, launcher, registry, store client, desktop integration);
- the **packager** tools (`app build`, `app convert`, `app check`, `app run`, `app sign`, `app inspect`), shipped as an optional package;
- tests, including sandbox-escape tests and a VM setup for kernel-dependent tests.

Not in this repository: the patched `xdg-desktop-portal` (separate fork), the store content and pipelines (`app-store` repo), and the UHAL operating system.

### The owner
The owner designed this with an AI over a long conversation and is **not a Linux systems expert**. When you make a technical choice, explain it in plain language in your summary. Never silently change a design decision from the spec. If implementation shows the spec is wrong or incomplete, stop, explain the problem and the options, and let the owner decide; then update `spec/spec.md` in the same change as the code.

### The first platform
UHAL OS is the first platform that will include this runtime: an immutable Buildroot-based OS with A/B OTA updates, a mainline kernel, a Wayland compositor and shell written in Rust (`uhal-daemon`, `uhal-compositor`, `uhal-shell`/Hydra store UI). **The runtime must not depend on any UHAL component.** UHAL includes the runtime the same way Fedora or Arch could. The weakest target device is an R36S handheld: Rockchip RK3326 (aarch64), 1 GB RAM, Mali-G31 GPU (Panfrost; OpenGL ES works well, Vulkan support is limited). Memory and CPU use matter.

## 2. Locked decisions and why (do not "improve" these)

Each of these was debated and chosen deliberately. Alternatives listed as rejected must not come back without the owner's approval.

| Decision | Why | Rejected alternative |
| --- | --- | --- |
| Small foundation (glibc, libstdc++/libgcc_s, Mesa/Vulkan, full libglvnd incl. `libGL.so.1`/`libGLX.so.0`/`libOpenGL.so.0`/EGL/GLES, libdrm/libgbm, the libs every GPU driver links (zlib, zstd, expat, libudev, libffi), a fixed set of X11 client libs Mesa's GLX is built against (libX11, libxcb and related), libva, Wayland client libs, libxkbcommon, PipeWire client, ALSA); everything else bundled | Only libraries that must come from the platform (drivers, or what drivers are built against) AND promise backward compatibility. Keeps apps working for years. The X11 set is fixed in `spec/foundation.toml`; platforms install all of it (may add, never drop) and build GL with GLX | Adding popular libs (SDL2, fontconfig, FreeType, HarfBuzz, OpenSSL, Qt, GTK, other X11 libs like libXrandr/libXi) to the foundation |
| One `.app` file = EROFS image, LZ4 | Single sealed file, kernel-mounted, no FUSE helper | squashfs, FUSE mounting, AppImage-style runtime |
| composefs + fs-verity on-device storage from day one | Identical files stored once, kernel-verified reads, delta updates | Plain loop-mounted images; adding dedup later |
| Per-app Linux user IDs (per person × app) + app registry | Kernel-verified app identity for the portal; apps can't reach the person's session bus because its runtime dir is closed to other users | Identity by cgroup or pidfd only; running apps as the person's own user |
| Landlock (ABI ≥ 6) + seccomp + cgroup per app, fail closed | Kernel-enforced isolation with no running process | Namespace containers as the main mechanism; running unprotected when a feature is missing |
| Separate app bus with portal, UnifiedPush distributor, and ONE shared `xdg-dbus-proxy` for standard services | Portals work, standard desktop features work, no per-app proxy | Per-app proxy for every app (Flatpak's overhead); exposing the session bus |
| Per-app proxy **only** for apps declaring `permissions.services` | Matches Flatpak for the rare apps that need extra services | Dropping those services entirely |
| Patched `xdg-desktop-portal` (identifies `.app` apps via the registry), shipped by the runtime until upstream accepts it | Reuses the standard every toolkit already speaks | Writing a custom portal protocol |
| Folder permissions: standard shared folders only (`documents`, `downloads`, `music`, `pictures`, `videos`, `roms`); never the whole home | Write access to home lets an app edit startup files and escape; Landlock can't carve exceptions | Flatpak-style `--filesystem=home` |
| Apps may execute code from their own data folders | Emulator cores, Steam games, plugins; code stays sandboxed | Forbidding exec outside the bundle |
| X11 apps bundle their own Xwayland + bridge (e.g. xwayland-satellite) | X11 stays out of the foundation and each X11 app is isolated | System Xwayland shared by all X11 apps; a `compat.x11` runtime feature |
| External files for proprietary apps (downloaded by the device from the vendor) | Legal, same as Flathub extra-data; stores never host vendor files | Redistributing vendor binaries |
| TUF for store metadata; stores sign, developers never do | Key rotation, expiry, rollback protection, revocation | Plain single-key signatures |
| Prebuilt composefs images published by stores (device verifies digest) | One signed digest covers the whole app tree | Always generating on device (still done for sideloads and external-file apps) |
| UnifiedPush for push (Web Push, RFC 8030) | Open standard; lets platforms pause apps | A custom push daemon |
| Password-free installs from trusted stores via polkit; admin for adding stores/sideloading | Same as Flatpak + GNOME Software | Always requiring admin |
| One command name `app`; packager subcommands via separate `app-pack` binary (`app build` → `app-pack build`, git-style) | Default-looking, one name | `appkit` (Apple's UI framework name), `bundlekit` |
| Pausing/closing background apps is platform policy, not format | Phones and desktops need different policies | Putting freeze/OOM policy in the runtime |
| Nothing UHAL-specific in the runtime | Other distros must be able to adopt it | Launcher inside `uhal-daemon` |

## 3. Repository layout

```
app/
├── Cargo.toml                  workspace
├── CLAUDE.md                   this file
├── README.md
├── LICENSE                     Apache-2.0 (code)
├── spec/
│   ├── spec.md                 the specification (CC BY 4.0)
│   ├── LICENSE                 CC BY 4.0
│   └── foundation.toml         foundation libraries, machine-readable
├── crates/                     all real logic lives in libraries
│   ├── manifest/               parse/write/validate manifest.toml (shared by runtime and packager)
│   ├── foundation/             load foundation.toml; classify a library as foundation or bundle
│   ├── objects/                content-addressed object store, fs-verity enable, garbage collection
│   ├── composefs/              generate, verify and mount composefs images
│   ├── registry/               app registry + user ID allocation
│   ├── sandbox/                cgroup, uid/gid switch, no_new_privs, Landlock, seccomp
│   ├── connections/            Wayland (security context), PipeWire, app bus, a11y bus hand-in
│   ├── store-client/           TUF (via `tough`), downloads, external files
│   ├── desktop/                .desktop entries, icons, MIME/URL registration
│   └── pack/                   packager: ELF deps, glibc version detection, convert, permission mapping, image building, signing
├── bins/                       thin wrappers only
│   ├── app/                    `app` CLI: install, update, remove, list; dispatches packager subcommands to `app-pack`
│   ├── app-pack/               packager CLI
│   └── app-launcher/           privileged, socket-activated launcher (keep it small and reviewable)
├── data/
│   ├── systemd/                launcher socket/service, mount-at-boot unit, app bus units
│   ├── polkit/                 password-free install rules
│   ├── dbus/                   app bus config, shared proxy allowlist
│   └── mime/                   shared-mime-info entry for .app
├── tests/
│   ├── fixtures/               tiny hand-made test apps
│   ├── sandbox/                escape tests (must fail to escape)
│   └── vm/                     scripts to run tests under a 6.12+ kernel (virtme-ng)
└── .github/workflows/ci.yml
```

Mark all crates `publish = false` for now.

## 4. Build order and milestones

Work in this order. Finish and test each step before starting the next.

1. `spec/foundation.toml` + `crates/manifest` + `crates/foundation` (pure Rust, fully unit-tested, no system access).
2. `crates/sandbox`: apply cgroup → private mount namespace (tmpfs over `/run`, `/tmp`, `/var/tmp`, `/dev/shm`; `/proc` with `hidepid=invisible`, granted read-only) → groups/gid/uid → `PR_SET_NO_NEW_PRIVS` → Landlock `restrict_self` → seccomp → `execve`, in that order. Test with a fixture binary. With `gamepad` granted, allow reading exactly what libudev-based gamepad discovery (SDL and others) needs under `/run/udev/data` and `/sys`, and nothing more.
3. `crates/objects` + `crates/composefs`: import files by hash, enable fs-verity, build/verify the composefs image, mount with verity required.
4. `crates/registry` + `bins/app-launcher`.
5. `bins/app` with `install` and `run`. `install` must run `app_manifest::bundle::check` and refuse any bundle containing a foundation or driver-internal library (classify every ELF file by its `DT_SONAME`, falling back to the file name, with `app_foundation::Foundation::classify`). Sideloaded bundles never pass through the packager, so the installer is the only guard.

   **Milestone 1 (proves the design on real hardware):** a hand-made fixture app (small program + one bundled `.so` + manifest), installed with `app install fixture.app` on the R36S and on an x86 dev machine, running as its own user. Tests must confirm it:
   - can read its own files and bundled library;
   - cannot read another app's data folder, the person's home, or `/etc/shadow`;
   - cannot open TCP or UDP sockets when `network = false`;
   - cannot reach the session bus;
   - does not start at all if Landlock ABI < 6 or fs-verity is unavailable.

6. `crates/pack` + `bins/app-pack`: `build`, `check`, `inspect`, then `convert` for AppImage, then Flathub merge route, then `sign`.
7. `crates/store-client` (TUF, delta downloads, external files, revocation); then the separate `app-store` repo with recipes and workflows.
8. `crates/desktop`, `data/` files, polkit, app bus + shared proxy, UnifiedPush distributor integration.
9. Portal patch (separate fork repo).

**Open items**

- Step 4: on systemd systems, create the app's cgroup through a systemd transient scope rather than directly under `/sys/fs/cgroup`.
- Step 8: PipeWire needs its access-control module (the one Flatpak uses with portals), so apps connecting as their own account get playback only.
- Step 8: game controllers plugged in after an app starts are not visible to it (Landlock rules cannot grow after launch). Likely design: the launcher or a small shared service passes new controller devices to the app as file descriptors, the way logind hands devices to compositors. Not decided yet.

## 5. Technology choices

- Rust stable, edition 2024. `cargo fmt`, `cargo clippy -- -D warnings` must pass.
- Suggested crates (verify current versions and APIs before use):
  - `clap` (CLI), `serde` + `toml` (manifest), `thiserror` (library errors), `anyhow` (binaries), `tracing` (logging)
  - `landlock` (the Landlock project's official Rust crate)
  - `libseccomp` (bindings to libseccomp)
  - `rustix` or `nix` (setresuid/setgroups/prctl/mount/ioctl)
  - `goblin` (ELF parsing: needed libraries, versioned symbol requirements such as `GLIBC_2.xx`)
  - `sha2` (hashing), `walkdir`, `tempfile`
  - `tough` (TUF client and repository tooling, by AWS)
  - `reqwest` with rustls (downloads), `zbus` (D-Bus, later)
- External tools the code may call (check they exist; fail with a clear message if not): `mkfs.erofs`, `fsck.erofs` (extract) or a read-only loop mount, `mkcomposefs` and `mount.composefs` from the composefs project (evaluate `composefs-rs` too), `fsverity` from fsverity-utils, `patchelf`, `flatpak` (packager side only).
- Reproducible images: use `mkfs.erofs` options for fixed timestamps and ownership, and pin tool versions.

## 6. Reference implementation defaults (NOT part of the spec)

The spec lets platforms choose paths. Use these defaults, all configurable:

- Object store: `/var/lib/app/objects/` (composefs layout)
- composefs images: `/var/lib/app/images/<app-id>/<build>.cfs`
- Registry: `/var/lib/app/registry.json` (root-owned, 0644, atomic writes via temp file + rename)
- App data: `/var/lib/app/data/<person-uid>/<app-id>/{config,data,state,cache,tmp}` (owned by the app account, 0700)
- Mounts: `/run/app/<app-id>`
- Trusted stores: `/etc/app/stores.d/*.toml`
- Foundation list: `/usr/share/app/foundation.toml`
- Installed apps are mounted at boot by a systemd oneshot unit and at install time.

**User ID range: do not guess.** Before choosing it, check systemd's documented UID/GID ranges (systemd.io "Users, Groups, UIDs and GIDs on systemd Systems") and typical `/etc/subuid` allocations, and pick a range that overlaps neither. Propose it to the owner, then record it in the spec.

## 7. Development environment

- Develop on an x86_64 Linux machine with kernel 6.12+ (current Fedora or Arch). The filesystem holding the object store must support fs-verity (ext4 with the `verity` feature enabled via `tune2fs -O verity`, or btrfs).
- Needed packages: erofs-utils, composefs, fsverity-utils, patchelf, libseccomp, and for packager work flatpak.
- Cross-compile for aarch64 with `cargo-zigbuild` or `cross`; test on the R36S.
- Kernel-dependent tests run in a VM with `virtme-ng` locally and in CI (GitHub runners may have an older kernel).
- R36S kernel must have: Landlock (ABI 6), EROFS, overlayfs with verity, fs-verity, cgroup v2, seccomp. Verify this first.

## 8. Security coding rules

The launcher and installer run with root privileges; a bug there is a security hole.

- `app-launcher` stays small. No `unwrap`/`expect` on privileged paths; every error aborts the launch.
- Fail closed: if any protection can't be applied, do not exec.
- Drop privileges in the documented order (section 4 step 2). Never exec anything as root on an app's behalf.
- Validate every manifest and path from a bundle as untrusted input (no `..`, no absolute paths, no symlinks escaping the bundle, no device files, strip setuid/setgid).
- Refuse bundles containing foundation or driver-internal libraries at install time, not only in the packager (spec section 5, rule 3).
- Verify signatures and digests before using any downloaded data.
- Every security property gets an escape test in `tests/sandbox/`.

## 9. Working rules

- Keep `spec/spec.md` and the code consistent; spec changes need the owner's approval.
- Prefer existing tools and libraries over new code; say which one you used and why.
- Small, reviewable commits, one milestone step at a time.
- At the end of each step, summarize for the owner in plain language: what now works, how it was tested, and what comes next.
