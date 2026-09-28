//! Runs inside the sandbox and tries things. Each argument is one attempt;
//! each prints one line: `<attempt> ok` or `<attempt> err <errno>`.
//! `status`, `fds` and `env` print facts instead, prefixed with `@`.

#[cfg(target_os = "linux")]
fn main() {
    for arg in std::env::args().skip(1) {
        linux::attempt(&arg);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("the probe only runs on Linux");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::CString;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    fn report(what: &str, r: std::io::Result<()>) {
        match r {
            Ok(()) => println!("{what} ok"),
            Err(e) => println!("{what} err {}", e.raw_os_error().unwrap_or(-1)),
        }
    }

    fn check(rc: libc::c_long) -> std::io::Result<()> {
        if rc < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// A raw system call whose arguments are all plain integers or null.
    fn sys(nr: libc::c_long, a: [libc::c_long; 4]) -> std::io::Result<()> {
        // SAFETY: every call below passes only integers or null pointers,
        // which the kernel validates; nothing in this process is written.
        check(unsafe { libc::syscall(nr, a[0], a[1], a[2], a[3]) })
    }

    pub fn attempt(arg: &str) {
        let (cmd, param) = arg.split_once(':').unwrap_or((arg, ""));
        let r: std::io::Result<()> = match cmd {
            "noop" => Ok(()),
            "status" => {
                let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
                for key in [
                    "Uid:",
                    "Gid:",
                    "Groups:",
                    "NoNewPrivs:",
                    "Seccomp:",
                    "CapEff:",
                    "CapPrm:",
                ] {
                    if let Some(l) = s.lines().find(|l| l.starts_with(key)) {
                        println!("@{}", l.split_whitespace().collect::<Vec<_>>().join(" "));
                    }
                }
                let cg = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
                println!("@cgroup {}", cg.trim());
                return;
            }
            "fds" => {
                let mut fds: Vec<String> = std::fs::read_dir("/proc/self/fd")
                    .map(|d| {
                        d.flatten()
                            .map(|e| e.file_name().to_string_lossy().into_owned())
                            .collect()
                    })
                    .unwrap_or_default();
                fds.sort();
                println!("@fds {}", fds.join(" "));
                return;
            }
            "env" => {
                let mut vars: Vec<String> =
                    std::env::vars().map(|(k, v)| format!("{k}={v}")).collect();
                vars.sort();
                println!("@env {}", vars.join(" "));
                return;
            }
            "read" => std::fs::File::open(param).and_then(|mut f| f.read(&mut [0; 16]).map(|_| ())),
            "list" => std::fs::read_dir(param).map(|_| ()),
            "write" => std::fs::File::create(param).and_then(|mut f| f.write_all(b"x")),
            "exec" => std::process::Command::new(param)
                .arg("noop")
                .output()
                .and_then(|o| {
                    if o.status.success() {
                        Ok(())
                    } else {
                        Err(std::io::Error::from_raw_os_error(libc::ECHILD))
                    }
                }),
            "tcp" => std::net::TcpStream::connect(param).map(|_| ()),
            "udp" => std::net::UdpSocket::bind("127.0.0.1:0").map(|_| ()),
            "socket" => {
                let family: libc::c_long = param.parse().unwrap_or(-1);
                sys(libc::SYS_socket, [family, libc::SOCK_RAW as _, 0, 0])
            }
            "socket-high-bits" => {
                // AF_INET with garbage in the upper 32 bits: the kernel only looks at the low bits.
                sys(
                    libc::SYS_socket,
                    [
                        (1 << 32) | libc::AF_INET as libc::c_long,
                        libc::SOCK_STREAM as _,
                        0,
                        0,
                    ],
                )
            }
            "unix" => UnixStream::connect(param).map(|_| ()),
            "abstract" => {
                use std::os::linux::net::SocketAddrExt;
                std::os::unix::net::SocketAddr::from_abstract_name(param.as_bytes())
                    .and_then(|a| UnixStream::connect_addr(&a))
                    .map(|_| ())
            }
            "kill" => {
                let pid: libc::pid_t = param.parse().unwrap_or(0);
                // SAFETY: kill with signal 0 only checks permission.
                check(unsafe { libc::kill(pid, 0) } as _)
            }
            "mount" => {
                let (src, tgt, fs) = (c("none"), c("/tmp"), c("tmpfs"));
                // SAFETY: valid C strings; the call is expected to be refused.
                check(unsafe {
                    libc::mount(src.as_ptr(), tgt.as_ptr(), fs.as_ptr(), 0, std::ptr::null())
                } as _)
            }
            "netlink" => {
                let proto: libc::c_long = param.parse().unwrap_or(-1);
                sys(
                    libc::SYS_socket,
                    [libc::AF_NETLINK as _, libc::SOCK_RAW as _, proto, 0],
                )
            }
            "umount" => {
                let target = c(param);
                // SAFETY: valid C string; expected to be refused.
                check(unsafe { libc::umount2(target.as_ptr(), libc::MNT_DETACH) } as _)
            }
            "keyctl" => sys(libc::SYS_keyctl, [0, 0, 0, 0]),
            "bpf" => sys(libc::SYS_bpf, [0, 0, 0, 0]),
            "perf" => sys(libc::SYS_perf_event_open, [0, 0, -1, -1]),
            "reboot" => sys(libc::SYS_reboot, [0, 0, 0, 0]),
            "settime" => sys(libc::SYS_settimeofday, [0, 0, 0, 0]),
            "module" => sys(libc::SYS_init_module, [0, 0, 0, 0]),
            "io_uring" => sys(libc::SYS_io_uring_setup, [1, 0, 0, 0]),
            "userns" => {
                // SAFETY: unshare takes only flags.
                check(unsafe { libc::unshare(libc::CLONE_NEWUSER) } as _)
            }
            "setuid-root" => {
                // SAFETY: plain integer arguments.
                check(unsafe { libc::setresuid(0, 0, 0) } as _)
            }
            _ => {
                println!("{arg} unknown");
                return;
            }
        };
        report(arg, r);
    }

    fn c(s: &str) -> CString {
        CString::new(s).unwrap_or_default()
    }
}
