//! The seccomp filter (spec section 7, "seccomp rules").
//!
//! A deny list, as the spec describes: ordinary system calls stay allowed,
//! and the ones below fail with an error the app can handle.

use libseccomp::{
    ScmpAction, ScmpArch, ScmpArgCompare, ScmpCompareOp, ScmpFilterContext, ScmpSyscall,
};

use crate::Error;

/// System calls no app needs, grouped as in the spec. They fail with `EPERM`.
pub const BLOCKED_SYSCALLS: &[&str] = &[
    // Mounting
    "mount",
    "umount2",
    "pivot_root",
    "open_tree",
    "move_mount",
    "fsopen",
    "fsconfig",
    "fsmount",
    "fspick",
    "mount_setattr",
    // Loading kernel code
    "init_module",
    "finit_module",
    "delete_module",
    "kexec_load",
    "kexec_file_load",
    "bpf",
    // Kernel keyrings
    "add_key",
    "request_key",
    "keyctl",
    // Performance monitoring
    "perf_event_open",
    // Rebooting
    "reboot",
    // Changing system time
    "settimeofday",
    "clock_settime",
    "clock_adjtime",
    "adjtimex",
    "stime",
    // Other system administration no app needs
    "syslog",
    "acct",
    "quotactl",
    "swapon",
    "swapoff",
    "ioperm",
    "iopl",
    "uselib",
    "vhangup",
];

/// io_uring can create sockets without the `socket` system call, bypassing
/// the network rule below, so it is unavailable. `ENOSYS` makes libraries
/// fall back to ordinary system calls.
const NO_IO_URING: &[&str] = &["io_uring_setup", "io_uring_enter", "io_uring_register"];

/// Socket families an app may create. Everything else fails with `EAFNOSUPPORT`.
fn allowed_families(network: bool) -> Vec<i32> {
    let mut f = vec![libc::AF_UNIX, libc::AF_NETLINK];
    if network {
        f.extend([libc::AF_INET, libc::AF_INET6]);
    }
    f
}

/// Larger than any address family the kernel knows; it refuses the rest itself.
const FAMILY_LIMIT: i32 = 64;

fn err(e: impl std::fmt::Display) -> Error {
    Error::Seccomp(e.to_string())
}

pub(crate) fn prepare(network: bool) -> Result<ScmpFilterContext, Error> {
    let mut f = ScmpFilterContext::new(ScmpAction::Allow).map_err(err)?;
    // Calls from an architecture not in the filter kill the process.
    f.set_act_badarch(ScmpAction::KillProcess).map_err(err)?;
    // 32-bit programs (games, Wine) use the compatibility architecture;
    // the same rules apply to them.
    let compat = match ScmpArch::native() {
        ScmpArch::X8664 => Some(ScmpArch::X86),
        ScmpArch::Aarch64 => Some(ScmpArch::Arm),
        _ => None,
    };
    if let Some(arch) = compat {
        f.add_arch(arch).map_err(err)?;
    }

    for name in BLOCKED_SYSCALLS {
        f.add_rule(ScmpAction::Errno(libc::EPERM), syscall(name)?)
            .map_err(err)?;
    }
    for name in NO_IO_URING {
        f.add_rule(ScmpAction::Errno(libc::ENOSYS), syscall(name)?)
            .map_err(err)?;
    }

    // Socket families: compare only the low 32 bits, as the kernel does, so
    // garbage in the upper bits cannot slip past.
    let allowed = allowed_families(network);
    for name in ["socket", "socketpair"] {
        let sc = syscall(name)?;
        for family in (0..FAMILY_LIMIT).filter(|f| !allowed.contains(f)) {
            let cmp =
                ScmpArgCompare::new(0, ScmpCompareOp::MaskedEqual(0xffff_ffff), family as u64);
            f.add_rule_conditional(ScmpAction::Errno(libc::EAFNOSUPPORT), sc, &[cmp])
                .map_err(err)?;
        }
    }
    Ok(f)
}

fn syscall(name: &str) -> Result<ScmpSyscall, Error> {
    ScmpSyscall::from_name(name)
        .map_err(|e| Error::Seccomp(format!("unknown system call `{name}`: {e}")))
}

pub(crate) fn load(filter: &ScmpFilterContext) -> Result<(), Error> {
    filter.load().map_err(err)?;
    // Confirm with the kernel directly (not /proc, which the app may not be
    // allowed to read): it must report filter mode.
    // SAFETY: PR_GET_SECCOMP takes no pointer arguments.
    let mode = unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) };
    if mode != libc::SECCOMP_MODE_FILTER as libc::c_int {
        return Err(Error::Seccomp(format!("filter not active (mode {mode})")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_listed_syscall_is_known() {
        for name in BLOCKED_SYSCALLS.iter().chain(NO_IO_URING) {
            assert!(syscall(name).is_ok(), "{name}");
        }
    }

    #[test]
    fn filters_build() {
        prepare(false).unwrap();
        prepare(true).unwrap();
    }

    #[test]
    fn network_families() {
        assert!(!allowed_families(false).contains(&libc::AF_INET));
        assert!(allowed_families(true).contains(&libc::AF_INET6));
        assert!(allowed_families(false).contains(&libc::AF_UNIX));
        assert!(!allowed_families(true).contains(&libc::AF_PACKET));
    }
}
