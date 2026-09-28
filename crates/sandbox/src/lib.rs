//! Starts a program inside an app's sandbox (spec section 7).
//!
//! The protections are applied in this order, then the program is executed:
//!
//! 1. cgroup: the process joins the app's cgroup;
//! 2. private mount namespace: empty tmpfs over `/run`, `/tmp`, `/var/tmp`
//!    and `/dev/shm`, a `/proc` showing only the app's own processes
//!    (always granted read-write, never executable), and
//!    any read-only [`Bind`]s the launcher asks for;
//! 3. identity: supplementary groups, group ID, user ID (all three of real,
//!    effective and saved), after which the process holds no capabilities;
//! 4. `PR_SET_NO_NEW_PRIVS`: nothing the app runs can gain rights;
//! 5. Landlock: files, devices, network ports, signals, abstract sockets;
//! 6. seccomp: blocked system calls and socket types.
//!
//! First, the process starts a new session (`setsid`), so it has no
//! controlling terminal. Everything fails closed: if any step cannot be applied, [`exec`] returns
//! an error and nothing is executed. Before the first step, every open file
//! descriptor except those listed in [`Policy::keep_fds`] is marked
//! close-on-exec, and the environment is replaced entirely.
//!
//! [`exec`] must be called in a single-threaded process (normally a child
//! the launcher has just forked): identity changes and Landlock apply to the
//! calling thread only.

#![cfg(target_os = "linux")]

mod cgroup;
pub mod devices;
mod fds;
mod identity;
mod kernel;
mod landlock_rules;
mod mount_ns;
mod seccomp;

use std::ffi::OsString;
use std::os::fd::RawFd;
use std::path::{Component, PathBuf};

pub use kernel::{KernelInfo, MIN_LANDLOCK_ABI, check_kernel};
pub use mount_ns::{HIDDEN, PROC_OPTIONS};
pub use seccomp::{BLOCKED_IOCTLS, BLOCKED_SYSCALLS, NETLINK_ALLOWED};

/// What an app may do. Built by the launcher from the manifest, the
/// registry and the user's permission choices.
#[derive(Clone, Debug)]
pub struct Policy {
    /// The app account (never 0).
    pub uid: u32,
    /// The app account's primary group (never 0).
    pub gid: u32,
    /// Supplementary groups, such as the shared app group (never 0).
    pub groups: Vec<u32>,
    /// The app's cgroup: an absolute path under `/sys/fs/cgroup`, created if missing.
    pub cgroup: PathBuf,
    /// Landlock rules. Anything not listed is denied. Paths are resolved in
    /// the app's private view, so `/tmp` means its own empty tmpfs.
    pub paths: Vec<PathRule>,
    /// Read-only copies of outside files or folders placed into the private
    /// view, below one of [`HIDDEN`]: `/run/udev/data` for granted game
    /// controllers, sockets the app connects to by path.
    pub binds: Vec<Bind>,
    /// Whether TCP/UDP networking is allowed (`permissions.network`).
    pub network: bool,
    /// File descriptors handed to the app besides 0, 1 and 2.
    pub keep_fds: Vec<RawFd>,
}

/// A read-only bind of `source` (outside) at `target` (inside the private view).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bind {
    pub source: PathBuf,
    pub target: PathBuf,
}

/// Access to one file or directory tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathRule {
    pub path: PathBuf,
    pub access: Access,
}

/// Kinds of access a [`PathRule`] grants. Directories grant it to everything beneath.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    /// Read files and list folders (system data such as fonts).
    Read,
    /// Read and run (the app's own files, the foundation).
    ReadExec,
    /// Read, create, change and delete, but not run (shared folders).
    ReadWrite,
    /// Everything [`Access::ReadWrite`] allows, plus running (the app's data folders).
    ReadWriteExec,
    /// Open a device for reading and writing and send it device commands
    /// (GPU render node, granted game controllers, `/dev/null`).
    Device,
    /// Connect to a pathname UNIX socket (Wayland, PipeWire, the app bus).
    /// Enforced only where Landlock ABI 9 (Linux 7.1) is available.
    Connect,
}

/// The program to run and its environment.
#[derive(Clone, Debug)]
pub struct Command {
    pub program: PathBuf,
    /// Arguments after the program name (`argv[1..]`).
    pub args: Vec<OsString>,
    /// The complete environment; nothing is inherited.
    pub env: Vec<(OsString, OsString)>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the policy is invalid: {0}")]
    Policy(String),
    #[error("this system lacks a required protection: {0}")]
    Kernel(String),
    #[error("could not start a new session: {0}")]
    Session(String),
    #[error("could not join the app's cgroup: {0}")]
    Cgroup(String),
    #[error("could not set up the app's private view of the filesystem: {0}")]
    MountNamespace(String),
    #[error("could not prepare file descriptors: {0}")]
    Fds(String),
    #[error("could not switch to the app's account: {0}")]
    Identity(String),
    #[error("could not set no-new-privileges: {0}")]
    NoNewPrivs(String),
    #[error("could not apply Landlock: {0}")]
    Landlock(String),
    #[error("could not apply seccomp: {0}")]
    Seccomp(String),
    #[error("could not start the program: {0}")]
    Exec(std::io::Error),
}

/// Applies every protection in order, then replaces this process with the
/// program. Returns only on failure, in which case nothing was executed.
pub fn exec(policy: &Policy, command: &Command) -> Error {
    match apply(policy) {
        Ok(()) => exec_program(command),
        Err(e) => e,
    }
}

/// Applies every protection in order to the current process. After an
/// `Ok`, the process is sandboxed for good; after an `Err`, it may be
/// partly sandboxed and must exit without running app code.
pub fn apply(policy: &Policy) -> Result<(), Error> {
    validate(policy)?;
    let info = check_kernel()?;
    let filter = seccomp::prepare(policy.network)?;

    // A new session without a controlling terminal: the app can never
    // type into, or signal through, the terminal the launcher runs in.
    rustix::process::setsid().map_err(|e| Error::Session(e.to_string()))?;

    cgroup::join(&policy.cgroup)?;
    mount_ns::enter(&policy.binds)?;
    // Built inside the private view, so rules name its files, not the host's.
    let ruleset = landlock_rules::prepare(policy, &info)?;
    fds::close_on_exec_except(&policy.keep_fds)?;
    identity::switch(policy.uid, policy.gid, &policy.groups)?;
    rustix::thread::set_no_new_privs(true).map_err(|e| Error::NoNewPrivs(e.to_string()))?;
    landlock_rules::restrict_self(ruleset)?;
    seccomp::load(&filter)?;
    Ok(())
}

fn validate(policy: &Policy) -> Result<(), Error> {
    let bad = |m: &str| Err(Error::Policy(m.to_owned()));
    if policy.uid == 0 || policy.gid == 0 || policy.groups.contains(&0) {
        return bad("apps never run as root or in the root group");
    }
    let plain = |p: &std::path::Path| {
        p.components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
    };
    if !plain(&policy.cgroup)
        || !policy.cgroup.starts_with("/sys/fs/cgroup/")
        || policy.cgroup == std::path::Path::new("/sys/fs/cgroup")
    {
        return bad("the cgroup must be a plain path below /sys/fs/cgroup");
    }
    if let Some(r) = policy
        .paths
        .iter()
        .find(|r| !r.path.is_absolute() || !plain(&r.path))
    {
        return Err(Error::Policy(format!(
            "`{}` is not a plain absolute path",
            r.path.display()
        )));
    }
    for b in &policy.binds {
        if !b.source.is_absolute() || !plain(&b.source) || !plain(&b.target) {
            return Err(Error::Policy(format!(
                "bind `{}` must use plain absolute paths",
                b.target.display()
            )));
        }
    }
    mount_ns::validate(&policy.binds).map_err(Error::Policy)?;
    if policy.keep_fds.iter().any(|fd| *fd < 0) {
        return bad("negative file descriptor");
    }
    Ok(())
}

fn exec_program(command: &Command) -> Error {
    use std::os::unix::process::CommandExt;
    let err = std::process::Command::new(&command.program)
        .args(&command.args)
        .env_clear()
        .envs(command.env.iter().map(|(k, v)| (k, v)))
        .exec();
    Error::Exec(err)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy {
            uid: 1000,
            gid: 1000,
            groups: vec![],
            cgroup: "/sys/fs/cgroup/app/test".into(),
            paths: vec![],
            binds: vec![],
            network: false,
            keep_fds: vec![],
        }
    }

    #[test]
    fn refuses_root() {
        for p in [
            Policy { uid: 0, ..policy() },
            Policy { gid: 0, ..policy() },
            Policy {
                groups: vec![5, 0],
                ..policy()
            },
        ] {
            assert!(matches!(validate(&p), Err(Error::Policy(_))));
        }
        assert!(validate(&policy()).is_ok());
    }

    #[test]
    fn refuses_bad_paths() {
        let p = Policy {
            cgroup: "/tmp/cg".into(),
            ..policy()
        };
        assert!(validate(&p).is_err());
        // `Path::starts_with` compares components, so this would pass a naive check.
        let p = Policy {
            cgroup: "/sys/fs/cgroup/../../tmp".into(),
            ..policy()
        };
        assert!(validate(&p).is_err());
        let p = Policy {
            cgroup: "/sys/fs/cgroup".into(),
            ..policy()
        };
        assert!(validate(&p).is_err());
        let p = Policy {
            paths: vec![PathRule {
                path: "/usr/../etc".into(),
                access: Access::Read,
            }],
            ..policy()
        };
        assert!(validate(&p).is_err());
        let p = Policy {
            paths: vec![PathRule {
                path: "usr".into(),
                access: Access::Read,
            }],
            ..policy()
        };
        assert!(validate(&p).is_err());
    }
}
