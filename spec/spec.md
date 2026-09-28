# .app Format Specification

Format version 1 · Sep 28, 2026

## 1. Purpose and scope

`.app` is an open, OS-neutral format for distributing applications on modern, up-to-date Linux systems. Each app is one sealed file, the kernel isolates it, and nothing runs beside it. The format combines existing, proven technologies and invents none. Status: final design for format version 1; no implementation yet.

**Goals**

- Installing an app is as simple and reliable as on iOS, and apps keep working as the system updates.
- No helper processes per app, except a filtering proxy for the few apps that declare extra desktop services; shared services start only when needed. Suitable for devices with 1 GB of RAM.
- The kernel isolates every app from the system, the user's files and other apps, and the user decides what each app may access.
- Tamper-proof from download to every file read.
- Existing open-source Linux apps can be converted without their developers' involvement.
- Open: anyone may implement the format, run a store or publish apps, without permission.

**Non-goals**

- Old systems, musl-based distributions and X11-only desktops.
- System software: drivers, VPNs, system tools and other operating system components.
- Updating the operating system itself.

**Terms**

- **Platform:** an operating system that implements this spec.
- **Bundle:** one `.app` file.
- **Foundation:** the libraries the platform guarantees to every app (section 4).
- **Runtime:** the platform components that install and run bundles (section 10).
- **Store:** a signed catalog of bundles that a device trusts (section 11).
- **Must, must not, should, may:** requirement levels, in the usual standards sense.

## 2. Background

A Linux program is three things: the program itself, the **libraries** it borrows at run time (for video, sound, windows and so on), and its **resources** (icons, translations, data). When a program starts, the system loads each library it needs. If one is missing or is the wrong version, the program fails.

Traditional Linux programs borrow their libraries from the operating system. That works when the distro built everything together, and breaks when a program meets a distro with different library versions. Every packaging format is an answer to that problem: either the app carries its libraries, or it relies on a known shared set.

| | AppImage | Flatpak | .app |
| --- | --- | --- | --- |
| Where libraries come from | Mostly inside the app, some from the host | Large shared runtimes (GNOME, KDE, Freedesktop) | Inside the app, except a small platform foundation |
| Reliably runs | Sometimes breaks on hosts missing a library | Yes | Yes, on platforms that implement the spec |
| Security isolation | None | Strong | Strong |
| Helper processes per running app | One (FUSE, to open the image) | Several (D-Bus filtering proxy, document portal, session helpers) | None, except for apps declaring extra desktop services |
| Tamper protection | No | Yes | Yes, verified by the kernel on every read |
| Store, updates, compatibility check | No | Yes | Yes |
| Runs on any distro | Mostly | Yes | No, by design |

Flatpak's weight comes from its goal, not from its sandbox: namespaces and seccomp cost almost nothing, but running on every distro requires large runtimes that never share memory with the host, and filtering helpers for apps that expect full desktop access. A platform that controls its own base can drop those compromises. That is the space `.app` is designed for.

## 3. Design principles

The core deal, borrowed from iOS and macOS: **the platform guarantees a small, stable foundation, and each app carries everything else.** Every other rule follows from it.

Architecture at a glance:

```
┌──────────────────────────────────────────────────────────────────┐
│ Sandboxed apps: each started by the launcher as its own user     │
│  [RetroArch.app]      [Firefox.app]        [Any other .app]      │
│  own user, Landlock, seccomp, cgroup; sealed read-only image     │
└──────┬─────────────────────┬────────────────────┬────────────────┘
       │ Wayland             │ PipeWire           │ app bus (+ accessibility bus)
┌──────▼───────┐     ┌───────▼──────┐     ┌───────▼──────────────────────────┐
│ Compositor   │     │ PipeWire     │     │ Portal, push distributor,        │
│ no screen    │     │ mic/camera   │     │ shared filtering proxy           │
│ capture      │     │ only if      │     │ (one process each, on demand)    │
│ for apps     │     │ allowed      │     │                                  │
└──────────────┘     └──────────────┘     └──────────────────────────────────┘
┌──────────────────────────────────────────────────────────────────┐
│ Platform foundation: kept up to date, never breaks old apps      │
│ glibc, libstdc++, Mesa, Vulkan, libglvnd (GL/GLX/EGL), libva,    │
│ driver-linked X11 client libs, Wayland/PipeWire clients          │
├──────────────────────────────────────────────────────────────────┤
│ Linux kernel: EROFS, composefs, fs-verity, Landlock, seccomp,    │
│ per-app user IDs, cgroups                                        │
└──────────────────────────────────────────────────────────────────┘
```

Each app is sealed, runs as its own user, and reaches the display, sound and the portal only through connections the launcher hands it. Every shared service is one process for all apps, started on demand.

1. **Small foundation, everything else bundled.** The platform provides only the libraries in section 4; each app carries the rest.
2. **Rolling, never breaking.** Platforms keep the foundation up to date, and an update never breaks an app that worked before.
3. **One app, one sealed file, stored once.** A bundle is a single read-only image. On the device, identical files across apps are stored once and verified by the kernel on every read.
4. **The kernel enforces isolation.** Each app runs as its own user, restricted by Landlock and seccomp, in its own cgroup.
5. **Connections are handed in, not discovered.** An app receives connections to the display, the audio server, the app bus and the accessibility bus, and cannot reach any other system service.
6. **The user decides.** A manifest only declares what an app wants; the user grants it, sees it, and can revoke it.
7. **No per-app helpers.** Nothing runs beside an app, except a filtering proxy for the rare apps that declare extra desktop services; shared services start when first needed.
8. **Reuse, don't reinvent.** Every mechanism is an existing, proven technology or protocol: EROFS, composefs, fs-verity, Landlock, seccomp, Wayland, PipeWire, Freedesktop portals, TUF.
9. **Fail closed.** If any protection is unavailable, the app does not run.
10. **Versioned and OS-neutral.** Every bundle names the format version it follows, and nothing in this spec depends on a particular operating system.

## 4. The platform foundation

The foundation is the only code an app may borrow from the platform; everything else must be inside the bundle. A library belongs in the foundation only if both of these hold:

1. It must come from the platform, because it loads hardware drivers, talks to a platform service, or is a library the platform's drivers are built against (such as the C and C++ runtimes).
2. Its developers keep a documented promise not to break programs built against older versions.

Popularity is never a reason. The foundation is what any modern, standard Linux system already provides.

**Foundation, format version 1**

| Component | Why it comes from the platform | Declared in the manifest as |
| --- | --- | --- |
| Linux kernel system calls | The kernel never breaks existing programs | not declared |
| glibc (C library and dynamic loader) | Platform drivers loaded into apps are built against it | `requires.glibc` |
| libstdc++, libgcc_s | C++ runtime of platform drivers such as Mesa | `requires.libstdcxx` |
| Vulkan loader, libglvnd (`libGL.so.1`, `libGLX.so.0`, `libOpenGL.so.0`, EGL, OpenGL ES), Mesa drivers, libdrm, libgbm | GPU drivers must match the hardware and kernel | `requires.vulkan`, `requires.gl`, `requires.gles` |
| A fixed set of X11 client libraries GPU drivers are built against (libX11, libxcb and related; listed below) | Mesa's GLX driver, and its EGL driver when built with X11 support, are built against them; their interfaces have been stable for decades | not declared; always present |
| libva and its drivers | Hardware video decoding and encoding drivers | `requires.libva` |
| Wayland client libraries, libxkbcommon | Talk to the platform's compositor | not declared; always present |
| PipeWire client library, ALSA library routed to PipeWire | Talk to the platform's audio server | not declared; always present |

**The X11 set** is fixed by this spec, so a bundle works the same on every platform: libX11, libX11-xcb, libxcb with its `glx`, `dri2`, `dri3`, `present`, `sync`, `xfixes`, `randr` and `shm` extensions, libXext, libXfixes, libXxf86vm, libxshmfence, libXau and libXdmcp. Every platform installs all of them, even if its own drivers use fewer. Platforms also build their OpenGL stack with GLX support (Mesa's GLX driver present), even on systems without an X11 desktop: the foundation promises `libGL.so.1` and `libGLX.so.0`, and X11 apps using OpenGL need a GLX driver behind them.

**Driver-internal libraries** (Mesa's driver files, the GPU-specific libdrm helpers such as `libdrm_amdgpu`, libglvnd's vendor libraries, libva and Vulkan drivers) belong to the foundation too. Bundles never contain them, but which ones a platform installs depends on its hardware.

**The foundation list.** The exact library list of each format version is published with this spec as a machine-readable file, `foundation.toml`. Tools use it to decide what a bundle must not contain.

**System data apps may read** (files, not libraries): installed fonts and font configuration, icon and cursor themes, trusted certificate authorities, time zone data, DNS and host name configuration, and locale settings.

**Always bundled, never foundation:** everything else, including SDL2, zlib, fontconfig, FreeType, HarfBuzz, libudev, OpenSSL, FFmpeg, ICU, Qt, GTK, Python, X11 libraries not listed above (such as libXrandr, libXi, libXcursor) and Xwayland. composefs stores identical copies once, so bundling costs no extra disk space for files shared between apps. Wayland apps never load the foundation's X11 libraries; only apps that use GLX or X11 do.

**Rules for platforms**

1. Foundation versions only move forward. An update never removes anything an app could be using.
2. If a foundation library releases an incompatible new major version, the new one is added beside the old one; the old one stays.
3. Each platform release carries its own foundation list, generated from its build: the spec's `foundation.toml` with any libraries the platform adds (it may add, never drop), plus a `[provides]` table giving the version of each requirement it meets, for example `glibc = "2.40"`. `glibc` and `libstdcxx` are always given; a graphics or video entry is left out on hardware without it, and apps requiring it do not run there. The list lives in the read-only system image, so after a rollback it describes the system that is actually running.
4. The platform also publishes that same file for each release, for example alongside its release notes. Stores and tools use these published copies, since they cannot read a device. The store client on the device makes the final compatibility check with the local file.
5. The runtime checks an app's `requires` against the local file at every launch, not only at install. After a system rollback, an app needing newer versions shows "Update your system to open this app" instead of starting.

**Processor architecture.** Each bundle is built for one architecture (`x86_64` or `aarch64`). The store serves the right file for each device. This keeps downloads small; one file per architecture is simpler than a combined file.

## 5. Bundle format and storage

A bundle is one file named `<Name>.app`: a read-only EROFS filesystem image compressed with LZ4, which decompresses quickly on weak processors. It is how apps are shipped and sideloaded. On the device, its contents are stored through composefs, so identical files across all apps are kept once.

**Internal layout**

```
RetroArch.app
├── manifest.toml        required: identity, requirements, permissions
├── bin/
│   └── retroarch        the program named by app.exec
├── lib/                 every library the app needs, except the foundation
├── share/               data, translations (share/locale), themes
└── icons/
    ├── 256.png          required
    └── scalable.svg     optional
```

**Rules for bundles**

1. `manifest.toml` and `icons/256.png` must be at the top level. `icons/256.png` must be a valid PNG of exactly 256×256 pixels; `icons/scalable.svg`, if present, is at most 1 MiB.
2. Programs must find bundled libraries through a relative search path (`$ORIGIN/../lib`) and must not depend on an absolute install location.
3. A bundle must not contain foundation libraries (section 4).
4. Special files are not allowed: the installer rejects device files and removes setuid and setgid flags.
5. An app that needs X11 bundles its own Xwayland and a small X11-to-Wayland bridge (such as xwayland-satellite), started by its own `exec`. The runtime treats it like any other app; each X11 app gets a private X server inside its own sandbox, so X11 apps cannot see each other.
6. Apps that were built to live at `/app` (converted from Flatpak) set `compat.prefix = "/app"`. The launcher then shows the app's files at `/app` inside that app's private view of the filesystem.
7. Symbolic links must be relative and, followed through the bundle's own files, must never lead outside it. A link to a missing file is allowed, as long as the part that exists stays inside.

**Storage on the device**

1. The installer verifies the bundle against its store's signed metadata (section 11), or asks the user to confirm a sideloaded bundle.
2. It copies each file into the platform's shared object store, named by the hash of its contents. A file that is already present, from any app, is not stored again.
3. It enables fs-verity on every stored object.
4. It obtains the app's composefs image, which describes the app's file tree and points to the stored objects. Stores publish a prebuilt image with its digest in their signed metadata, and the installer checks it matches. For sideloaded bundles, the installer generates the image itself. Images are reproducible: the same files and composefs format version always give the same image.
5. The runtime mounts the app read-only through composefs with verification required. The kernel checks every file against its digest on every read; a changed byte produces a read error.
6. The original `.app` file is not kept. Objects no app refers to any more are deleted after an update or uninstall.

The platform chooses where the object store and mount points live. The spec requires only that apps are mounted read-only, with verification enforced, at a stable path per app.

**External files.** A bundle may declare files that are not inside it, but downloaded by each device directly from their publisher at install time. This is how proprietary apps are distributed without any store hosting them, the same approach as Flathub's extra-data. For each external file, the manifest gives the publisher's download address, size, SHA-256 hash, where it goes inside the app, and optionally how to unpack it (`tar`, `zip` or `deb`). The installer downloads it from that address, checks size and hash against the store's signed metadata, unpacks it, and stores the result through composefs like any other app file. Because the final file tree depends on the download, the installer generates the composefs image itself for these apps. If the publisher's file no longer matches its hash, the install stops with a clear message until the store updates the entry. Stores never host external files.

Unpacking is strict. For `deb`, only the package's data archive is extracted; its maintainer scripts and control files are never run or used. For every format, the installer refuses entries that would land outside `dest`, absolute paths, device files, and hard links pointing outside the extracted files, and removes setuid and setgid flags. The unpacked files then follow the same rules as the rest of the bundle.

**File type registration.** Platforms register `.app` in the freedesktop shared-mime-info database, matched by both the `.app` extension and the EROFS signature at byte offset 1024, so every desktop recognizes a bundle by its contents and opens it with the installer.

## 6. Manifest

Every bundle carries `manifest.toml`, a TOML file stating what the app is, what it needs, and which install-time permissions it requests. Permissions requested at run time through the portal (camera, microphone, location, file picking) are never declared. Unknown fields are ignored, so newer bundles still install on older platforms whenever `format` allows it; the exact rules are under **Validation** below.

**Example**

```toml
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
```

**Field reference**

| Field | Required | Type | Meaning |
| --- | --- | --- | --- |
| `format` | yes | integer | Format version the bundle follows. This spec defines `1`. |
| `app.id` | yes | string | Unique reverse-domain ID. Converted apps keep their upstream ID. |
| `app.name` | yes | string | Name shown to users. |
| `app.version` | yes | string | Version shown to users. |
| `app.build` | yes | integer | Increases with every published build; decides which build is newer. |
| `app.arch` | yes | `x86_64` or `aarch64` | Processor the bundle is built for. |
| `app.exec` | yes | path | Program to start, relative to the bundle root. |
| `app.args` | no | list of strings | Arguments passed to the program. |
| `app.summary` | no | string | One line for stores. |
| `app.license` | yes | SPDX expression | License of the app. |
| `app.source` | yes, if open source | URL | Where the exact source code is published. |
| `app.homepage` | no | URL | Project website. |
| `app.categories` | no | list | Freedesktop menu categories. |
| `requires.glibc` | yes | version | Lowest glibc the app runs on. Filled in automatically by `app build`. |
| `requires.libstdcxx` | no | version | Lowest libstdc++ symbol version, for C++ apps. Filled in automatically. |
| `requires.vulkan`, `requires.gl`, `requires.gles`, `requires.libva` | no | version | Lowest Vulkan, desktop OpenGL, OpenGL ES or VA-API version needed. |
| `permissions.network` | no | boolean | Internet and local network access. |
| `permissions.audio` | no | boolean | Sound playback. |
| `permissions.gamepad` | no | boolean | Game controllers. |
| `permissions.folders.<name>` | no | `{ access, reason? }` | A shared user folder (section 8); `access` is `read` or `read-write`. |
| `permissions.removable` | no | `{ access, reason? }` | SD cards and USB drives. |
| `permissions.background` | no | boolean | Asks to keep running when not visible. The platform decides whether to honor it. |
| `reasons.<permission>` | no | string | Optional text shown in a prompt, for example `reasons.camera`. Never required. Keys: `network`, `audio`, `gamepad`, `removable`, `background`, `printing`, `ssh_agent`, `services`, and the run-time permissions `camera`, `microphone`, `location`, `notifications`, `screen_sharing`, `global_shortcuts`, `usb`, `autostart`. |
| `ui.inputs` | yes | list: `gamepad`, `touch`, `pointer`, `keyboard`, `remote` | Input methods the app can be fully used with. Stores hide apps a device cannot operate. |
| `ui.min_width` | no | integer (pixels) | Smallest usable window width. |
| `integration.mime_types` | no | list | File types the app opens, registered with the desktop. |
| `integration.url_schemes` | no | list | Link types the app handles, such as `mailto`. |
| `compat.prefix` | no | path | Only `/app` is allowed; for apps converted from Flatpak (section 5). |
| `compat.env` | no | table | Extra environment variables. Cannot override those the launcher sets. |

**Further permission fields.** `permissions.printing` (boolean): direct access to the printing system, for apps that print without the portal dialog. `permissions.ssh_agent` (boolean): access to the person's SSH agent, for developer tools. `permissions.services` (list of D-Bus names): extra desktop services beyond the standard ones (section 8). All follow the same rules as the other install-time permissions.

**External files in the manifest.** Each external file is one `[[external]]` entry with `url`, `sha256`, `size`, `dest` (a path inside the app) and optional `unpack` (`tar`, `zip` or `deb`). For example:

```toml
[[external]]
url = "https://vendor.example/downloads/app-1.2.3.tar.gz"
sha256 = "<64 hex characters>"
size = 104857600
dest = "vendor/"
unpack = "tar"
```

**Validation.** Every platform must accept and refuse exactly the same manifests, so a bundle behaves the same everywhere. A platform must refuse a bundle that breaks any rule below. Refusals because of `format` or `[requires]` are shown as "Needs a newer system version"; the others as a broken bundle. Rules marked *warning* never refuse; `app check` reports them.

*General*

- `manifest.toml` is valid TOML, UTF-8, at most 64 KiB.
- No string contains a NUL character.
- Unless a rule below says otherwise, strings are at most 1024 bytes and lists at most 64 entries. This applies to unknown fields too.
- Every required field is present, and every field has the type the field reference gives.

*Unknown keys and values*

- `format` must be `1`. It is checked first, since a newer format may change any other rule.
- An unknown key in `[requires]` is refused: a platform that cannot check a requirement must not install the app.
- Anywhere else, an unknown key is ignored (*warning*). An unknown key in `[permissions]` is never granted.
- A known field with an unknown value is refused: `app.arch`, a folder name other than the six in section 8, `access`, `unpack`, `compat.prefix`.
- `ui.inputs` entries this format does not know are ignored (*warning*), but at least one known entry is required.
- `app.categories` entries that are not registered Freedesktop categories are ignored (*warning*).
- `reasons.<permission>` keys that are not in the field reference are ignored (*warning*).

*Identity and versions*

- `app.id` follows Flatpak's rules, so converted apps keep their IDs: at least 3 dot-separated parts of letters, digits, `_` and `-`; `-` only in the last part; no part empty or starting with a digit; at most 255 bytes.
- `app.name` and `app.version`: 1–64 characters. `app.summary`: at most 200 characters. None of them contain control characters such as line breaks. `app.version` is only shown, never compared.
- `app.build`: a whole number from 1 to 2⁶³−1.
- Versions in `[requires]`: 1–4 dot-separated whole numbers without leading zeros (`"2.39"`, `"3.4.30"`). They compare part by part, and missing parts count as 0, so `2.39` equals `2.39.0`.
- `app.license`: a valid SPDX expression. Deprecated SPDX identifiers are accepted.
- `app.source`: required unless every license in the expression is a custom `LicenseRef-…` identifier, which marks a proprietary app.
- `app.source` and `app.homepage`: `https://` or `http://` URLs with a host.

*Paths*

- `app.exec` and `external.dest`: relative, `/`-separated, at most 4096 bytes, with no empty, `.` or `..` parts. `dest` may end with `/`.
- `app.exec` must lead, following symbolic links only inside the bundle, to a regular file marked executable. If it lies inside an external file's `dest`, this is checked after the download.
- `compat.prefix`: exactly `/app`.
- `app.args`: at most 256 entries of at most 4096 bytes each.

*Permissions*

- `permissions.network`, `audio`, `gamepad`, `background`, `printing` and `ssh_agent` are booleans.
- `permissions.folders.<name>` and `permissions.removable`: `access` is `read` or `read-write`; `reason`, like every `reasons.<permission>` text, is 1–500 characters without control characters.
- `permissions.services`: D-Bus well-known names (at least 2 dot-separated parts of letters, digits, `_` and `-`, no part starting with a digit, at most 255 bytes), with no wildcards. Names the app bus already provides are refused: `org.freedesktop.DBus`, `org.freedesktop.portal.*` and `org.freedesktop.impl.portal.*`.

*External files*

- `url`: `https://` only. `sha256`: exactly 64 lowercase hexadecimal characters. `size`: from 1 byte to 64 GiB. `unpack`: `tar` (compression detected automatically), `zip` or `deb`.

*Integration, interface and environment*

- `integration.mime_types`: `type/subtype`, at most 256 entries. `integration.url_schemes`: lowercase URL schemes; `file` is refused.
- `ui.min_width`: 1–16384.
- `compat.env`: names are letters, digits and `_`, not starting with a digit. Every variable the launcher sets or controls is refused: names starting with `LD_`, `XDG_`, `DBUS_`, `WAYLAND_`, `PIPEWIRE_` or `AT_SPI_`, and `HOME`, `TMPDIR`, `PATH`, `USER`, `LOGNAME`, `SHELL`, `GDK_BACKEND`, `QT_QPA_PLATFORM`, `SDL_VIDEODRIVER`, `GTK_USE_PORTAL`, `QT_QPA_PLATFORMTHEME`, `SECRET_BACKEND`, `SSH_AUTH_SOCK`, `DISPLAY`, `NOTIFY_SOCKET` and `LISTEN_FDS`. Implementations keep this as one list shared by their launcher and validator.

## 7. Security model

Every app runs under all of the layers below at once; each one covers gaps in the others, and none adds a running process.

| Layer | What it does |
| --- | --- |
| Own user account | Each app runs as its own Linux user, one per person and app. Other apps' data and the person's own session are closed to it by ordinary file permissions. |
| Landlock | Allows only the files, devices and network actions listed below; blocks signals and abstract sockets to programs outside the app. |
| seccomp | Blocks system calls an app never needs, and all internet sockets when network access is off. |
| cgroup | Holds every process of the app, so the platform can measure, pause or stop the whole app. |
| Handed-in connections | The app gets connections to the compositor, the audio server, the app bus and the accessibility bus, and cannot open others. |
| Wayland security context | The compositor knows each connection's app ID and refuses screen capture, global input and overlays over other apps. |
| PipeWire restrictions | Playback only, unless the user grants the microphone or camera through the portal. |
| composefs and fs-verity | App files are read-only and checked by the kernel on every read. |

**User accounts and the app registry.** The platform reserves a range of user IDs for apps and assigns one per person and app, like Android. Numbers must be unique, stay stable across updates, and are not reused while the account's data exists. All app accounts belong to one app group, used for shared folders (section 8). The runtime records which account belongs to which app and person in the **app registry**, a list only the system can write. The portal and every other platform service identify a calling app by looking up its account there, as Android's system services do. The person's session bus lives in a folder only the person can enter, so apps cannot reach it.

**Landlock rules**

- Read and run: the app's own mount, the foundation, and the system data listed in section 4.
- Read, write and run: the app's own data folders (section 9). Apps may run programs and load plugins they placed there themselves, such as downloaded emulator cores or games, as with Flatpak; they stay inside the app's sandbox.
- Read and write: shared folders, removable drives, the printing socket or the SSH agent socket the user granted, and files the user picked through the portal.
- Devices: the GPU render node (drawing and video decoding, never screen control); granted game controllers, both their input devices and their raw HID devices for rumble, motion and Steam Input (never keyboards or touchscreens); and standard harmless devices such as `/dev/null` and `/dev/urandom`.
- Network: TCP connect and bind are allowed only when `network` is granted.

**seccomp rules.** Blocks mounting, loading kernel code, kernel keyrings, performance monitoring, rebooting and changing system time. Blocks creating internet sockets (TCP and UDP) when `network` is off. It allows apps to create unprivileged user namespaces, because Chromium, Firefox and Electron build their own inner sandboxes with them; nothing created inside can escape the restrictions around it.

**Launch hardening.** The launcher sets no-new-privileges, so no program inside the app can gain rights, and applies Landlock and seccomp before starting the app. Both are inherited by every process the app starts.

**Fail closed.** The runtime must refuse to start any app if a required protection is unavailable. Platforms need Linux with Landlock ABI 6 or newer (Linux 6.12), fs-verity, EROFS, composefs support, cgroup v2, seccomp, the Wayland security context protocol in the compositor, and unprivileged user namespaces allowed for app accounts.

## 8. Permissions

The manifest only declares; the user decides. Install-time permissions are shown before installing and can each be switched off later in the platform's settings. Run-time permissions are asked for through the portal the first time an app uses them. Every answer is remembered and can be changed.

| Permission | Declared in manifest | How the user decides | Enforced by |
| --- | --- | --- | --- |
| Network | yes | Shown at install; can be revoked | seccomp, Landlock |
| Sound playback | yes | Shown at install; can be revoked | PipeWire |
| Game controllers, including rumble, motion and touchpads | yes | Shown at install; can be revoked | Landlock, device group |
| Shared folders | yes, per folder | Shown at install; each can be revoked | Landlock |
| Removable drives | yes | Shown at install; can be revoked | Landlock |
| Direct printing | yes | Shown at install; can be revoked | Landlock (printing system socket) |
| SSH agent, for developer tools | yes | Shown at install; can be revoked | Landlock (agent socket) |
| Running in background | yes | Platform policy | Platform |
| Picking a file or folder | no | The user picks it in the system dialog | Portal passes only what was picked |
| Camera, microphone | no | Prompt on first use | Portal, PipeWire |
| Location, notifications, screen sharing, global shortcuts, USB devices, starting at login | no | Prompt on first use | Portal |
| Opening links and files in other apps | no | Always allowed; the user's default app opens them | Portal |

A change to an install-time permission takes effect the next time the app starts; the platform should offer to restart it.

**Shared folders, format version 1:** `documents`, `downloads`, `music`, `pictures`, `videos`, `roms`. The platform maps them to its own locations, normally the person's standard user folders. An app never gets the whole home folder: write access to it would let an app change the person's startup files and escape its sandbox, a known weakness of granting it in Flatpak. Any other folder reaches an app only when the user picks it through the portal.

**Files apps save in shared folders.** Shared folders give the app group write access, and default permission rules make every new file fully readable and writable by the person. Files remain owned by the app's account on disk, but behave as the person's own. The platform lets the app group pass through the person's home folder to reach granted folders, without being able to list it.

**The portal.** The runtime uses the Freedesktop portal interfaces, the standard GTK, Qt, Firefox, Chromium and Electron already speak. Its settings interface also gives apps the system's light or dark mode and accent color. The implementation is `xdg-desktop-portal` with one addition: identifying `.app` apps by looking up the calling account in the app registry (section 7). Everything else in it is unchanged, including its split between the front part apps talk to and the back parts each desktop provides to draw dialogs. The runtime ships this patched build until the change is accepted upstream. The launcher sets the environment variables that make GTK and Qt apps use portal dialogs.

**The app bus.** Apps cannot reach the person's session bus (section 7), so the runtime runs one separate D-Bus bus per person for apps, started on demand, and hands each app its connection. On it are:

- the portal;
- the UnifiedPush distributor, where the platform provides one;
- one shared filtering proxy that forwards a fixed list of standard desktop services to the session bus (table below). It is `xdg-dbus-proxy`, the tool Flatpak uses, run once for all apps instead of once per app;
- the names apps publish themselves, such as media players and tray icons, which the platform's media controls and tray read from the app bus.

Nothing else on the session bus is reachable. The portal is connected to both buses: it hears apps on the app bus and uses the desktop's dialogs on the session bus.

**Push notifications.** Apps receive messages from their servers through UnifiedPush, an open standard whose server side is Web Push (IETF RFC 8030). One distributor on the app bus holds a single connection for all apps and delivers each message to its app. A platform that pauses background apps must provide a distributor and must wake an app briefly when a message arrives for it. Showing the notification goes through the portal's notification permission. Apps without UnifiedPush support rely on the `background` permission to stay running, where the platform allows it.

**Standard desktop features.** Every app can use the standard Linux desktop features below, through the same standards it uses on any desktop. Apps need no changes.

| Feature | Standard | How the app reaches it |
| --- | --- | --- |
| Media controls and now playing | MPRIS | Published on the app bus; the platform's media controls read it |
| Tray icons | StatusNotifierItem | Registered through the shared proxy; the platform's tray reads them from the app bus |
| Notifications | Notification portal, or `org.freedesktop.Notifications` | Portal, or forwarded by the shared proxy |
| Keeping the screen on during playback | Inhibit portal, or `org.freedesktop.ScreenSaver` | Portal, or forwarded by the shared proxy |
| Screen readers and other assistive tools | AT-SPI | The launcher hands in a connection to the accessibility bus |
| Typing in other languages | Wayland text-input and input-method protocols; IBus portal | Compositor and portal |
| Saved passwords | Secret portal | Each app gets its own encrypted store; the launcher sets libsecret to its file backend, whose key comes from the portal. Apps never see the whole keyring |
| Clipboard and drag and drop | Wayland | Compositor |
| Opening files and links in other apps | OpenURI portal | Portal |
| Printing | Print portal, or CUPS | Portal dialog; direct CUPS with `printing` |
| Screenshots and screen sharing | Screenshot and ScreenCast portals | Portal, with a prompt |
| Global keyboard shortcuts | GlobalShortcuts portal | Portal, with a prompt |
| Starting at login | Background portal | Portal, with a prompt |
| Network status and power saving mode | NetworkMonitor and PowerProfileMonitor portals | Portal |
| Game performance mode | GameMode portal | Portal |
| USB devices | USB portal | Portal, with a prompt |
| Dark mode, accent color, fonts, icon and cursor themes | Settings portal; system theme files | Portal, and read access to system themes |
| Location | Location portal | Portal, with a prompt |
| Camera and microphone | Camera portal and PipeWire | Portal, with a prompt |

**Picked files and folders.** Files and folders the user picks in the portal's dialog reach the app through the portal's document store, the same shared service Flatpak uses, which gives that app access to what was picked and nothing else. Access to a picked folder is remembered, so the app keeps it after restarting.

**Extra desktop services.** A few apps need a specific desktop service beyond the standard ones above, for example KDE Connect. They list its D-Bus name in `permissions.services`; the user sees it at install and can revoke it. Such an app gets its own instance of the filtering proxy, allowing only its listed services, exactly as Flatpak does. It is the only case where anything runs beside an app, and only for apps that ask. The proxy refuses any service that would let an app escape its sandbox or read other apps' secrets, such as keyrings, systemd, polkit, Flatpak's own services and `org.freedesktop.impl.portal.*`, even if the user allows it.

## 9. App data

Each person gets a private data folder for each app, owned by that person's app account and closed to everyone else. The platform chooses where these folders live, outside the person's home folder so the app never needs access to it. Each is split by how precious its contents are:

| Folder | Environment variable set by the launcher | Holds | Backed up | Platform may delete |
| --- | --- | --- | --- | --- |
| `config/` | `XDG_CONFIG_HOME` | Settings | Yes | No |
| `data/` | `XDG_DATA_HOME` | Saves, libraries, anything the user would miss | Yes | No |
| `state/` | `XDG_STATE_HOME` | History, logs, window positions | Optional | No |
| `cache/` | `XDG_CACHE_HOME` | Anything that can be rebuilt | No | Yes, when space runs low |
| `tmp/` | `TMPDIR` | Temporary files | No | Yes, at every launch |

The launcher also sets `HOME` to the app's private folder, so apps that write to `~` stay inside it.

**Uninstalling** asks one question: remove everything, or keep the app's data so a reinstall continues where it left off. Kept data stays owned by the app's account.

**Updates never touch data.** An app that changes its data layout between versions migrates it itself on first launch, as on iOS and Android.

**Backups.** Platforms may back up `config/` and `data/`. They are ordinary folders, so any backup tool can copy them.

## 10. Runtime and lifecycle

The runtime is the set of components a platform installs to support `.app`. Apart from the proxy for extra desktop services (section 8), none of them runs beside an app: each either runs briefly and exits, or starts on demand and serves all apps.

| Component | Role | When it runs |
| --- | --- | --- |
| `app` command | Install, update, remove, list apps. The optional packager package adds `build`, `convert`, `check`, `run`, `sign` and `inspect` (section 12) | When called |
| App registry | Records which user account belongs to which app and person; read by the portal and other platform services (section 7) | Written at install and removal |
| Launcher | Starts apps inside their sandbox; needs system privileges to switch user accounts | Started on demand, exits when idle |
| App bus, portal and push distributor | Permission requests, dialogs and push messages (section 8) | Started on demand, per person |
| Store client | Reads trusted catalogs, checks compatibility, downloads and verifies updates (section 11) | When checking or installing |
| Desktop integration | Adds apps to the desktop's menus, with icons, file types and link types, for each person | At install, update and removal |

Installing, updating and removing signed apps from trusted stores needs no password for the device's users; the runtime authorizes it through polkit, as GNOME Software does for Flatpak. Adding a store and sideloading a bundle require an administrator. Opening an app needs nothing.

**Install**

1. Verify the bundle against its store's signed metadata, or ask the user to confirm a sideloaded bundle.
2. Check `format`, `arch` and every `requires` entry. If anything fails, stop and say why, for example "Needs a newer system version".
3. Show the install-time permissions and let the user switch any off.
4. Download any external files from their publishers and check them against their signed hashes (section 5).
5. Store the files through composefs and check the image against its signed digest, or generate it for apps with external files (section 5).
6. Create the app's user account for each person who installs it, record it in the app registry, and create their data folders.
7. Register the app with the desktop.

If any step fails, everything done so far is undone. An install either completes or leaves no trace.

**Launch**

1. The desktop asks the launcher to start the app.
2. The launcher checks the app's requirements and that every protection in section 7 is available. If not, the app does not start.
3. It creates the app's cgroup.
4. It opens the connections: Wayland with the app's security context, PipeWire with the granted rights, the app bus, and the accessibility bus.
5. It sets the environment: data folders, `HOME`, toolkit settings for Wayland and portals, connection addresses.
6. It switches to the app's user account and groups, sets no-new-privileges, applies Landlock and seccomp, and starts the program.

The launcher does not stay attached to the app.

**Update**

1. Download only the files not already stored, and verify them (section 11).
2. Prepare the new version's composefs image beside the old one.
3. When the app is not running, switch to the new version in one step.
4. Keep the old version until the new one has started successfully, then release its files. If the new one fails to start, switch back.

**Uninstall**

1. Stop the app if it is running.
2. Remove its desktop registration and composefs image.
3. Delete its data folders and accounts, unless the user chose to keep the data (section 9).
4. Release files no other app uses.

## 11. Stores and trust

A store is a set of static files on any web host: bundles, stored files, and signed metadata. It needs no server code. Stores sign; app developers never have to.

**Signed metadata (TUF).** Store metadata follows The Update Framework, the established standard for secure software updates. It uses its four roles:

- **Root** names the keys trusted for everything else, and allows keys to be replaced safely.
- **Targets** lists every app build and its files, with their hashes.
- **Snapshot** fixes which versions of the metadata belong together.
- **Timestamp** is re-signed frequently and expires, so a device notices if an attacker keeps serving an old catalog to hold back a fix.

**What the catalog lists** for each app: ID, name, summary, icon, categories, `ui.inputs`, and for each architecture the latest build with its version, requirements, permissions, download size, the hash of the `.app` file, the hash of every file it contains, and its prebuilt composefs image with that image's digest. For apps with external files, it lists each file's publisher address, size and hash instead of hosting it.

**Downloads.** A store publishes both the `.app` files and each contained file, addressed by its hash. A new install downloads only files the device does not already have; so does every update. The `.app` file itself is used for sideloading and archiving.

**Revocation.** A store can mark a build or an app as revoked. Devices then refuse to start it and offer to remove it.

**Beta versions** are published as a separate store with its own metadata, as Flathub does with its beta repository. Users who want them add that store.

**Trust on the device**

- The platform decides which stores are trusted by default.
- Users can add other stores, with a clear warning.
- An installed app is only updated from the store it came from. Moving it to another store needs the user's confirmation.
- **Sideloading:** a user may install a bundle file directly, with a warning that no store has checked it. It is still verified by composefs and sandboxed like any other app.

**Openness**

- This specification is published under CC BY 4.0. Anyone may implement it without permission.
- The reference runtime and tools are published under Apache 2.0. The portal patch keeps the license of `xdg-desktop-portal`.
- A store's build recipes should be public, so anyone can check or rebuild what it ships.
- The format gives no store special status.

## 12. Tooling and conversion

Packaging uses the same `app` command. Its packager subcommands ship as an optional extra package, so devices do not carry them, and packaging needs no knowledge of this spec.

| Command | What it does |
| --- | --- |
| `app build <folder>` | Finds every library the program needs, bundles all except the foundation, rewrites library search paths, reads the program to fill in `requires`, writes the manifest, builds the image |
| `app convert <file or id>` | Turns an AppImage or a Flathub app into a bundle (below) |
| `app check <bundle>` | Validates manifest and layout; flags bundled foundation libraries, missing libraries and unusual permissions |
| `app run <bundle>` | Runs a bundle file directly under its real sandbox, for testing |
| `app sign` | Produces a store's signed metadata for a set of bundles |
| `app inspect <bundle>` | Shows manifest, contents, size and hashes |

Existing tools it builds on: `mkfs.erofs` and `mkcomposefs` for images, `fsverity-utils`, `patchelf` for library paths, linuxdeploy as a reference for finding libraries, the Landlock project's Rust libraries, libseccomp, and a TUF implementation for signing.

**Toolkit defaults.** `app convert` and `app build` configure every app to use Wayland natively where its toolkit supports it (SDL, GTK, Qt, Electron). Only apps that truly need X11 get a bundled Xwayland (section 5).

**Converting AppImages**

1. Extract the AppImage.
2. Remove foundation libraries; add any library the AppImage expected from the host that the foundation does not provide.
3. Build the manifest from the AppImage's desktop entry.
4. Build, run the launch test, sign.

**Converting Flathub apps.** A Flathub app depends on a separate runtime, so it cannot simply be copied. Two routes:

- **Merge:** take the app plus the runtime libraries it uses, drop the runtime's foundation libraries, and set `compat.prefix = "/app"`. Symbolic links pointing into `/app/...` are rewritten as relative links, since bundles only allow those (section 5). Fast; works for most apps.
- **Rebuild:** compile the app from its public Flathub recipe against the foundation. Smaller, cleaner bundles; the long-term route.

**Permissions from Flathub recipes.** `app convert` reads each app's declared Flathub permissions and translates them:

| Flathub permission | Becomes |
| --- | --- |
| Network | `network = true` |
| Sound (PulseAudio socket) | `audio = true` |
| Specific standard folders (for example Music) | The matching shared folder |
| Whole home or whole system | Each standard shared folder separately; other folders through the portal's picker |
| All devices | `gamepad = true` if the app uses controllers; nothing else |
| Printing system socket | `printing = true` |
| SSH agent socket | `ssh_agent = true` |
| Standard desktop services (notifications, tray, media controls, screen saver, accessibility) | Nothing to declare; the app bus provides them (section 8) |
| Other session bus names | `permissions.services`, shown to the user |
| System bus names | Dropped; system services are not available to apps |

**The build service.** Any CI service works, including GitHub Actions.

- Rebuild only apps whose source changed.
- For apps with external files, check publishers' download addresses for new versions automatically, as Flathub's flatpak-external-data-checker does, and update the recipe's address and hash.
- Every bundle must pass a launch test before publishing: start it under a headless Wayland compositor and confirm it keeps running.
- Generate each build's composefs image with a pinned version of the composefs tools, so the same app always produces the same image.
- Publish bundles, files, composefs images and signed metadata to static hosting.

**Licensing.** Open-source apps may be redistributed when their license terms are followed, which usually means linking to their exact source (`app.source`). Proprietary apps are never redistributed: `app convert` turns Flathub extra-data apps into bundles with external files (section 5), so each device downloads the program directly from its publisher, exactly as Flathub does.

## 13. Platform responsibilities and conformance

The format defines what every platform must do the same way; everything else is each platform's own choice.

| Every platform must | Each platform decides |
| --- | --- |
| Provide the foundation and system data (section 4) and keep them compatible | How its dialogs and prompts look (the portal's back part) |
| Meet the kernel and compositor requirements (section 7) | Its store interface |
| Install the runtime (section 10) | Which stores are trusted by default |
| Enforce every security layer, and refuse to run apps when one is missing | Whether and when to pause background apps, and which to close when memory runs low |
| Provide a UnifiedPush distributor, if it pauses background apps (section 8) | Where apps, stored files and app data live on disk |
| Follow the manifest, permission and store rules exactly | Where the shared folders map to |

**Conformance.** The project publishes a conformance test suite: sample bundles and automated checks proving a platform installs, runs, isolates and updates apps as this spec requires. That includes sandbox tests confirming an app cannot read other apps' data, reach the network without permission, or reach the session bus. A platform may call itself `.app`-compatible only if it passes.

**Threat model.** The design protects the user and the system against apps that are buggy, compromised or malicious, and against tampered downloads and stores serving old or altered metadata. It does not protect against kernel or GPU driver flaws, a store the user chose to trust turning malicious, or an app misusing access the user granted (for example sending away files from a folder the user shared with it).

## 14. Limits and glossary

**Accepted limits**

- Up-to-date glibc-based systems only; musl-based distributions and outdated installs are not supported.
- User apps only; drivers, VPNs and system tools remain part of the operating system.
- Proprietary apps need their vendors' permission to be redistributed.
- On platforms without the portal patch, portal features are unavailable until it is accepted upstream or the runtime's build is installed.

**Details to settle during implementation**

- [ ] The exact user ID ranges and numbering scheme.
- [ ] The app bus's configuration.
- [ ] How the portal's document store is made reachable by app accounts.
- [ ] Proposing the portal change upstream.
- [ ] Confirming on Repology that no packaged project already installs an `app` command.
- [ ] Choosing the MIME type name and registering it in shared-mime-info.

**Glossary**

- **ABI:** the binary contract between a program and a library; if it changes incompatibly, old programs break.
- **App bus:** a separate message bus for apps, carrying the portal, the push distributor, the shared proxy for standard desktop services, and apps' media and tray names.
- **App registry:** the system's list of which user account belongs to which app and person.
- **AT-SPI:** the Linux accessibility standard screen readers use to read apps.
- **cgroup:** a kernel group of processes that can be measured, limited, paused and stopped together.
- **composefs:** a kernel-backed way to mount an app whose files are stored once and shared with other apps.
- **D-Bus:** the message bus desktop programs use to send each other requests.
- **EROFS:** a compact, read-only Linux filesystem format, mounted directly by the kernel.
- **External files:** files an app's manifest lists but that each device downloads directly from their publisher.
- **fs-verity:** a kernel feature that checks a file against its digest on every read.
- **Landlock:** a kernel feature that limits which files, devices and network actions a process may use.
- **MPRIS:** the Linux standard through which media players expose playback controls to the system.
- **Portal:** the Freedesktop standard through which sandboxed apps ask for files, the camera and other resources.
- **seccomp:** a kernel feature that blocks chosen system calls for a process.
- **StatusNotifierItem:** the Linux standard for tray icons.
- **TUF:** The Update Framework, a standard for signing and securing software update metadata.
- **UnifiedPush:** an open standard for delivering server messages to apps, built on Web Push.
- **Web Push:** the internet standard (IETF RFC 8030) servers use to send push messages.
- **Xwayland:** an X server that shows X11 app windows on a Wayland display.
