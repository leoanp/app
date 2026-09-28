//! Switching to the app's account (spec section 7, "Own user account").

use rustix::process::{Gid, Uid};
use rustix::thread::{capabilities, set_thread_groups, set_thread_res_gid, set_thread_res_uid};

use crate::Error;

/// Sets supplementary groups, then real/effective/saved group and user IDs,
/// then verifies that the switch is complete and irreversible.
pub(crate) fn switch(uid: u32, gid: u32, groups: &[u32]) -> Result<(), Error> {
    let e = |what: &str, err: rustix::io::Errno| Error::Identity(format!("{what}: {err}"));
    let groups: Vec<Gid> = groups.iter().map(|g| Gid::from_raw(*g)).collect();
    let (uid, gid) = (Uid::from_raw(uid), Gid::from_raw(gid));

    // Groups first: once the user ID changes, groups can no longer be set.
    set_thread_groups(&groups).map_err(|err| e("setgroups", err))?;
    set_thread_res_gid(gid, gid, gid).map_err(|err| e("setresgid", err))?;
    set_thread_res_uid(uid, uid, uid).map_err(|err| e("setresuid", err))?;

    // Verify rather than trust.
    let status = std::fs::read_to_string("/proc/thread-self/status")
        .map_err(|err| Error::Identity(format!("cannot verify: {err}")))?;
    let field = |name: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(name))
            .map(str::split_whitespace)
    };
    let all_equal = |name: &str, want: u32| {
        field(name).is_some_and(|mut ids| ids.all(|id| id.parse() == Ok(want)))
    };
    if !all_equal("Uid:", uid.as_raw()) || !all_equal("Gid:", gid.as_raw()) {
        return Err(Error::Identity(
            "user or group IDs did not all change".into(),
        ));
    }
    let caps = capabilities(None).map_err(|err| e("capget", err))?;
    if !caps.effective.is_empty() || !caps.permitted.is_empty() {
        return Err(Error::Identity(
            "capabilities remain after the switch".into(),
        ));
    }
    // Going back must be impossible.
    if set_thread_res_uid(Uid::ROOT, Uid::ROOT, Uid::ROOT).is_ok() {
        return Err(Error::Identity("could switch back to root".into()));
    }
    Ok(())
}
