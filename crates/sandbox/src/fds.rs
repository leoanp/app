//! File descriptor hygiene: Landlock does not restrict files that are
//! already open, so nothing the launcher holds may reach the app by accident.

use std::os::fd::{BorrowedFd, RawFd};

use rustix::io::{FdFlags, fcntl_getfd, fcntl_setfd};

use crate::Error;

/// Marks every open descriptor from 3 up close-on-exec, except `keep`
/// (which are made inheritable).
pub(crate) fn close_on_exec_except(keep: &[RawFd]) -> Result<(), Error> {
    let entries =
        std::fs::read_dir("/proc/self/fd").map_err(|e| Error::Fds(format!("cannot list: {e}")))?;
    let mut fds = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| Error::Fds(format!("cannot list: {e}")))?;
        let name = entry.file_name();
        let fd: RawFd = name
            .to_str()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| Error::Fds(format!("unexpected entry {name:?}")))?;
        fds.push(fd);
    }
    // The listing's own descriptor is closed by now; skip ones that vanished.
    for fd in fds.into_iter().filter(|fd| *fd > 2) {
        // SAFETY: `fd` came from this process's descriptor table and is only
        // used for the duration of these two calls.
        let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
        let flags = match fcntl_getfd(borrowed) {
            Ok(f) => f,
            Err(rustix::io::Errno::BADF) => continue,
            Err(e) => return Err(Error::Fds(format!("fd {fd}: {e}"))),
        };
        let wanted = if keep.contains(&fd) {
            flags - FdFlags::CLOEXEC
        } else {
            flags | FdFlags::CLOEXEC
        };
        fcntl_setfd(borrowed, wanted).map_err(|e| Error::Fds(format!("fd {fd}: {e}")))?;
    }
    for fd in keep {
        // SAFETY: as above; a kept descriptor that is not open is an error.
        let borrowed = unsafe { BorrowedFd::borrow_raw(*fd) };
        fcntl_getfd(borrowed).map_err(|e| Error::Fds(format!("kept fd {fd} is not open: {e}")))?;
    }
    Ok(())
}
