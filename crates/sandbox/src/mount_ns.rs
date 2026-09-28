//! The app's private view of the filesystem (spec section 7, "Private mount
//! namespace"). A defense layer, not a container: Landlock stays the main
//! file boundary. It hides the places where world-writable sockets live
//! (the system D-Bus, X11, CUPS, Avahi), which Landlock can only block from
//! ABI 9, and gives the app a `/proc` that shows only its own processes.
//! It adds no running process.

use std::fs;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use rustix::fs::CWD;
use rustix::mount::{
    MountFlags, MountPropagationFlags, MoveMountFlags, OpenTreeFlags, mount, mount_change,
    mount_remount, move_mount, open_tree,
};
use rustix::thread::{UnshareFlags, unshare_unsafe};

use crate::{Bind, Error};

/// Folders replaced by an empty, private tmpfs.
pub const HIDDEN: &[&str] = &["/run", "/tmp", "/var/tmp", "/dev/shm"];

/// Options of the app's `/proc`: other users' processes are invisible. The
/// system-wide files (`cpuinfo`, `meminfo`, `stat`) stay, since browsers,
/// Electron, Java, .NET, SDL and FFmpeg read them.
pub const PROC_OPTIONS: &std::ffi::CStr = c"hidepid=invisible";

fn err(what: impl std::fmt::Display, e: impl std::fmt::Display) -> Error {
    Error::MountNamespace(format!("{what}: {e}"))
}

/// Checks bind targets: each must lie below one of the hidden folders, so a
/// bind can only add to the private tmpfs, never cover system files.
pub(crate) fn validate(binds: &[Bind]) -> Result<(), String> {
    for b in binds {
        let under_hidden = HIDDEN
            .iter()
            .any(|h| b.target.starts_with(h) && b.target != Path::new(h));
        if !under_hidden {
            return Err(format!(
                "bind target `{}` must be inside one of {HIDDEN:?}",
                b.target.display()
            ));
        }
    }
    Ok(())
}

/// Enters a new mount namespace and builds the private view. Must run as
/// root, before the identity switch.
pub(crate) fn enter(binds: &[Bind]) -> Result<(), Error> {
    // SAFETY: only the mount namespace is unshared, in a single-threaded
    // process; no memory or file-table state is affected.
    unsafe { unshare_unsafe(UnshareFlags::NEWNS) }.map_err(|e| err("unshare", e))?;
    // Mounts made outside (a new USB drive) still appear; nothing made here leaks out.
    mount_change(
        "/",
        MountPropagationFlags::DOWNSTREAM | MountPropagationFlags::REC,
    )
    .map_err(|e| err("make / a downstream mount", e))?;

    // Take detached copies of what stays visible before covering it.
    let mut clones: Vec<(OwnedFd, &Bind, bool)> = Vec::new();
    for b in binds {
        let is_dir = fs::metadata(&b.source)
            .map_err(|e| err(b.source.display(), e))?
            .is_dir();
        let flags = OpenTreeFlags::OPEN_TREE_CLONE
            | OpenTreeFlags::OPEN_TREE_CLOEXEC
            | OpenTreeFlags::AT_RECURSIVE;
        let fd = open_tree(CWD, &b.source, flags).map_err(|e| err(b.source.display(), e))?;
        clones.push((fd, b, is_dir));
    }

    for dir in HIDDEN {
        if !Path::new(dir).is_dir() {
            continue; // nothing there to hide
        }
        let mode = if *dir == "/run" {
            c"mode=0755"
        } else {
            c"mode=1777"
        };
        mount(
            "tmpfs",
            *dir,
            "tmpfs",
            MountFlags::NOSUID | MountFlags::NODEV,
            mode,
        )
        .map_err(|e| err(format!("tmpfs on {dir}"), e))?;
    }

    for (fd, b, is_dir) in clones {
        place(&fd, b, is_dir)?;
    }

    mount(
        "proc",
        "/proc",
        "proc",
        MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC,
        PROC_OPTIONS,
    )
    .map_err(|e| err("private /proc", e))?;
    std::env::set_current_dir("/").map_err(|e| err("chdir /", e))?;
    Ok(())
}

/// Puts one detached copy at its target inside the private tmpfs, read-only.
fn place(fd: &OwnedFd, b: &Bind, is_dir: bool) -> Result<(), Error> {
    let target: &PathBuf = &b.target;
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).map_err(|e| err(parent.display(), e))?;
    }
    let made = if is_dir {
        fs::create_dir(target)
    } else {
        fs::File::create(target).map(drop)
    };
    made.map_err(|e| err(target.display(), e))?;
    move_mount(fd, "", CWD, target, MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH)
        .map_err(|e| err(target.display(), e))?;
    let ro = MountFlags::BIND
        | MountFlags::RDONLY
        | MountFlags::NOSUID
        | MountFlags::NODEV
        | MountFlags::NOEXEC;
    mount_remount(target, ro, "").map_err(|e| err(format!("read-only {}", target.display()), e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bind(target: &str) -> Bind {
        Bind {
            source: "/run/udev/data".into(),
            target: target.into(),
        }
    }

    #[test]
    fn binds_only_inside_hidden_folders() {
        assert!(validate(&[bind("/run/udev/data")]).is_ok());
        assert!(validate(&[bind("/tmp/x/y")]).is_ok());
        for bad in ["/run", "/etc/passwd", "/usr/lib", "/runner", "/proc/self"] {
            assert!(validate(&[bind(bad)]).is_err(), "{bad}");
        }
    }
}
