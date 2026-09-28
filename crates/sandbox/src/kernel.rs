//! Checks that the kernel offers every protection the sandbox needs
//! (spec section 7, "Fail closed").

use std::fs;

use crate::Error;

/// Lowest Landlock ABI accepted: version 6 (Linux 6.12) adds signal and
/// abstract-socket scoping.
pub const MIN_LANDLOCK_ABI: i32 = 6;

/// cgroup v2 filesystem magic number (`CGROUP2_SUPER_MAGIC`).
const CGROUP2_MAGIC: i64 = 0x6367_7270;

/// What the running kernel offers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KernelInfo {
    /// Landlock ABI version, or 0 if Landlock is off.
    pub landlock_abi: i32,
    /// Whether seccomp filters are available.
    pub seccomp: bool,
    /// Whether `/sys/fs/cgroup` is a cgroup v2 hierarchy.
    pub cgroup2: bool,
    /// Whether unprivileged user namespaces are allowed.
    pub user_namespaces: bool,
}

/// Reads what the kernel offers and refuses if anything is missing.
pub fn check_kernel() -> Result<KernelInfo, Error> {
    let info = KernelInfo {
        landlock_abi: landlock_abi(),
        seccomp: seccomp_available(),
        cgroup2: cgroup2_mounted(),
        user_namespaces: user_namespaces_allowed(),
    };
    evaluate(&info)?;
    Ok(info)
}

/// The decision, separate from probing so it can be tested.
pub(crate) fn evaluate(info: &KernelInfo) -> Result<(), Error> {
    if info.landlock_abi < MIN_LANDLOCK_ABI {
        return Err(Error::Kernel(if info.landlock_abi <= 0 {
            "Landlock is not enabled".into()
        } else {
            format!(
                "Landlock ABI {} is too old (need {MIN_LANDLOCK_ABI}, Linux 6.12)",
                info.landlock_abi
            )
        }));
    }
    if !info.seccomp {
        return Err(Error::Kernel("seccomp filters are not available".into()));
    }
    if !info.cgroup2 {
        return Err(Error::Kernel("/sys/fs/cgroup is not cgroup v2".into()));
    }
    if !info.user_namespaces {
        return Err(Error::Kernel(
            "unprivileged user namespaces are disabled".into(),
        ));
    }
    Ok(())
}

fn landlock_abi() -> i32 {
    // landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)
    // SAFETY: with a null attribute pointer and size 0 this syscall only
    // returns the ABI version (or -1); it reads no memory.
    let v = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<u8>(),
            0usize,
            1u32,
        )
    };
    i32::try_from(v).unwrap_or(0).max(0)
}

fn seccomp_available() -> bool {
    // PR_GET_SECCOMP fails with EINVAL on kernels without seccomp. The
    // filter mode itself is checked again when the filter loads.
    // SAFETY: PR_GET_SECCOMP takes no pointer arguments.
    let mode = unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) };
    mode >= 0
}

// `f_type`'s integer type differs between architectures.
#[allow(clippy::unnecessary_cast)]
fn cgroup2_mounted() -> bool {
    rustix::fs::statfs("/sys/fs/cgroup").is_ok_and(|s| s.f_type as i64 == CGROUP2_MAGIC)
}

fn user_namespaces_allowed() -> bool {
    let read = |p: &str| fs::read_to_string(p).ok().map(|s| s.trim().to_owned());
    let max_ok = read("/proc/sys/user/max_user_namespaces").is_some_and(|v| v != "0");
    // Debian and Ubuntu patches: a missing file means the switch does not exist.
    let debian_ok = read("/proc/sys/kernel/unprivileged_userns_clone").is_none_or(|v| v != "0");
    max_ok && debian_ok
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good() -> KernelInfo {
        KernelInfo {
            landlock_abi: 6,
            seccomp: true,
            cgroup2: true,
            user_namespaces: true,
        }
    }

    #[test]
    fn accepts_complete_kernel() {
        assert!(evaluate(&good()).is_ok());
        assert!(
            evaluate(&KernelInfo {
                landlock_abi: 9,
                ..good()
            })
            .is_ok()
        );
    }

    #[test]
    fn refuses_each_missing_protection() {
        for info in [
            KernelInfo {
                landlock_abi: 0,
                ..good()
            },
            KernelInfo {
                landlock_abi: 5,
                ..good()
            },
            KernelInfo {
                seccomp: false,
                ..good()
            },
            KernelInfo {
                cgroup2: false,
                ..good()
            },
            KernelInfo {
                user_namespaces: false,
                ..good()
            },
        ] {
            assert!(matches!(evaluate(&info), Err(Error::Kernel(_))), "{info:?}");
        }
    }
}
