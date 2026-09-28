//! Landlock rules (spec section 7, "Landlock rules").

use landlock::{
    ABI, Access as _, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, PathBeneath, PathFd,
    RestrictionStatus, Ruleset, RulesetAttr, RulesetCreated, RulesetCreatedAttr, RulesetStatus,
    Scope,
};

use crate::kernel::KernelInfo;
use crate::{Access, Error, Policy};

/// The ABI whose rights are always required.
const REQUIRED: ABI = ABI::V6;

fn err(e: impl std::fmt::Display) -> Error {
    Error::Landlock(e.to_string())
}

/// Rights for each [`Access`] kind, within what ABI 6 defines.
fn rights(access: Access) -> BitFlags<AccessFs> {
    let read = AccessFs::ReadFile | AccessFs::ReadDir;
    let write = AccessFs::WriteFile
        | AccessFs::RemoveDir
        | AccessFs::RemoveFile
        | AccessFs::MakeDir
        | AccessFs::MakeReg
        | AccessFs::MakeSym
        | AccessFs::MakeSock
        | AccessFs::MakeFifo
        | AccessFs::Refer
        | AccessFs::Truncate;
    match access {
        Access::Read => read,
        Access::ReadExec => read | AccessFs::Execute,
        Access::ReadWrite => read | write,
        Access::ReadWriteExec => read | write | AccessFs::Execute,
        Access::Device => AccessFs::ReadFile | AccessFs::WriteFile | AccessFs::IoctlDev,
        Access::Connect => BitFlags::empty(), // added only where ABI 9 exists
    }
}

/// Rights that apply to a single file.
fn file_rights() -> BitFlags<AccessFs> {
    AccessFs::ReadFile
        | AccessFs::WriteFile
        | AccessFs::Execute
        | AccessFs::Truncate
        | AccessFs::IoctlDev
        | AccessFs::ResolveUnix
}

/// Builds the ruleset: opens every listed path while still privileged, but
/// restricts nothing yet.
pub(crate) fn prepare(policy: &Policy, info: &KernelInfo) -> Result<RulesetCreated, Error> {
    // Every file right ABI 6 knows is handled (so denied unless granted),
    // and must be supported: HardRequirement turns any gap into an error.
    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(REQUIRED))
        .map_err(err)?
        .scope(Scope::from_all(REQUIRED))
        .map_err(err)?;
    if !policy.network {
        // Handled with no rule: every TCP bind and connect is denied.
        ruleset = ruleset
            .handle_access(AccessNet::from_all(REQUIRED))
            .map_err(err)?;
    }
    // Connecting to socket files is only controllable from ABI 9 (Linux 7.1).
    let resolve_unix = info.landlock_abi >= 9;
    if resolve_unix {
        ruleset = ruleset.handle_access(AccessFs::ResolveUnix).map_err(err)?;
    }
    let mut created = ruleset.create().map_err(err)?;

    // The private /proc the sandbox mounted: readable and writable, never
    // executable. Browsers write their own ID mapping (/proc/self/uid_map)
    // for their inner sandbox; file permissions still limit writes to the
    // app's own processes, and hidepid hides everyone else.
    let proc_fd = PathFd::new("/proc").map_err(err)?;
    created = created
        .add_rule(PathBeneath::new(proc_fd, rights(Access::ReadWrite)))
        .map_err(err)?;

    for rule in &policy.paths {
        let mut access = rights(rule.access);
        if rule.access == Access::Connect {
            if !resolve_unix {
                continue; // nothing to grant: connecting is not restricted here
            }
            access = AccessFs::ResolveUnix.into();
        }
        let fd = match PathFd::new(&rule.path) {
            Ok(fd) => fd,
            // A missing path grants nothing; skipping it can only deny more.
            Err(e) if is_not_found(&e) => continue,
            Err(e) => return Err(err(e)),
        };
        // A file takes only file rights; the strict mode refuses folder-only
        // ones (such as listing). Checked on the opened descriptor, not the name.
        let is_dir = rustix::fs::fstat(&fd).map_err(err)?.st_mode & libc::S_IFMT == libc::S_IFDIR;
        if !is_dir {
            access &= file_rights();
        }
        created = created
            .add_rule(PathBeneath::new(fd, access))
            .map_err(err)?;
    }
    Ok(created)
}

fn is_not_found(e: &landlock::PathFdError) -> bool {
    let landlock::PathFdError::OpenCall { source, .. } = e else {
        return false;
    };
    source.kind() == std::io::ErrorKind::NotFound
}

/// Enforces the ruleset on the current thread and everything it starts.
pub(crate) fn restrict_self(ruleset: RulesetCreated) -> Result<(), Error> {
    let status: RestrictionStatus = ruleset.restrict_self().map_err(err)?;
    if status.ruleset != RulesetStatus::FullyEnforced {
        return Err(Error::Landlock(format!(
            "ruleset only {:?}",
            status.ruleset
        )));
    }
    Ok(())
}
