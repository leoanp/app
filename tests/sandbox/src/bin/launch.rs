//! A minimal stand-in for the real launcher, for tests: builds a policy from
//! its arguments, then calls `app_sandbox::exec`. Runs as a fresh,
//! single-threaded process, as the real launcher's child does.
//!
//! ```text
//! launch --uid N --gid N [--group N]... --cgroup PATH [--net]
//!        [--rule ACCESS:PATH]... [--keep FD] [--open-leak PATH] [--env K=V]...
//!        -- PROGRAM [ARGS]...
//! ```
//! ACCESS is one of read, read-exec, read-write, read-write-exec, device, connect.
//! `--open-leak PATH` opens PATH (without close-on-exec) before sandboxing,
//! to prove it does not reach the program; `--keep` passes a descriptor on.

#[cfg(target_os = "linux")]
fn main() {
    let err = linux::run();
    eprintln!("launch: {err}");
    std::process::exit(111);
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("launch only runs on Linux");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
mod linux {
    use app_sandbox::{Access, Command, PathRule, Policy};

    pub fn run() -> String {
        let mut args = std::env::args_os().skip(1);
        let mut policy = Policy {
            uid: 0,
            gid: 0,
            groups: vec![],
            cgroup: Default::default(),
            paths: vec![],
            network: false,
            keep_fds: vec![],
        };
        let mut env = Vec::new();
        let mut program = None;
        let mut rest = Vec::new();
        while let Some(a) = args.next() {
            let a = a.to_string_lossy().into_owned();
            let mut val = || {
                args.next()
                    .map(|v| v.to_string_lossy().into_owned())
                    .unwrap_or_default()
            };
            match a.as_str() {
                "--uid" => policy.uid = val().parse().unwrap_or(0),
                "--gid" => policy.gid = val().parse().unwrap_or(0),
                "--group" => policy.groups.push(val().parse().unwrap_or(0)),
                "--cgroup" => policy.cgroup = val().into(),
                "--net" => policy.network = true,
                "--keep" => policy.keep_fds.push(val().parse().unwrap_or(-1)),
                "--env" => {
                    let v = val();
                    let (k, v) = v.split_once('=').unwrap_or((&v, ""));
                    env.push((k.into(), v.into()));
                }
                "--open-leak" => {
                    let path = std::ffi::CString::new(val()).unwrap_or_default();
                    // SAFETY: valid C string; the descriptor is deliberately leaked.
                    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY) };
                    if fd < 0 {
                        return format!(
                            "cannot open leak file: {}",
                            std::io::Error::last_os_error()
                        );
                    }
                }
                "--rule" => {
                    let v = val();
                    let Some((access, path)) = v.split_once(':') else {
                        return format!("bad rule {v}");
                    };
                    let access = match access {
                        "read" => Access::Read,
                        "read-exec" => Access::ReadExec,
                        "read-write" => Access::ReadWrite,
                        "read-write-exec" => Access::ReadWriteExec,
                        "device" => Access::Device,
                        "connect" => Access::Connect,
                        other => return format!("bad access {other}"),
                    };
                    policy.paths.push(PathRule {
                        path: path.into(),
                        access,
                    });
                }
                "--" => {
                    program = args.next();
                    rest.extend(args.by_ref());
                }
                other => return format!("unknown option {other}"),
            }
        }
        let Some(program) = program else {
            return "no program".into();
        };
        let command = Command {
            program: program.into(),
            args: rest,
            env,
        };
        app_sandbox::exec(&policy, &command).to_string()
    }
}
