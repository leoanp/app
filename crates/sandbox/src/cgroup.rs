//! Joining the app's cgroup (spec section 7, "cgroup").

use std::fs;
use std::path::Path;

use crate::Error;

/// Creates `dir` if needed and moves the current process into it. Every
/// process the app starts later inherits it.
pub(crate) fn join(dir: &Path) -> Result<(), Error> {
    let err =
        |what: &str, e: std::io::Error| Error::Cgroup(format!("{what} {}: {e}", dir.display()));
    match fs::create_dir(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(err("cannot create", e)),
    }
    let procs = dir.join("cgroup.procs");
    fs::write(&procs, std::process::id().to_string()).map_err(|e| err("cannot join", e))?;

    // Confirm: the process's own view must name this cgroup.
    let own = fs::read_to_string("/proc/self/cgroup").map_err(|e| err("cannot verify", e))?;
    let expected = dir.strip_prefix("/sys/fs/cgroup").unwrap_or(dir);
    let joined = own
        .lines()
        .filter_map(|l| l.strip_prefix("0::"))
        .any(|p| Path::new(p) == Path::new("/").join(expected));
    if !joined {
        return Err(Error::Cgroup(format!(
            "process is not in {} after joining",
            dir.display()
        )));
    }
    Ok(())
}
