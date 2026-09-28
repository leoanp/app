//! Sandbox escape tests (CLAUDE.md section 8: every security property gets
//! an escape test). A probe program runs inside the sandbox and tries to get
//! out; every attempt that should fail must fail.
//!
//! These need root and Linux 6.12+, so they are ignored by default. Run them
//! with `tests/vm/sandbox-tests.sh` inside the VM.

#![cfg(target_os = "linux")]
// Test code: a panic is how a test fails.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{PermissionsExt, chown};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Test-only account numbers. The real app range is chosen in step 4.
const APP_UID: u32 = 1_900_000_001;
const OTHER_UID: u32 = 1_900_000_002;

const EPERM: &str = "err 1";
const EACCES: &str = "err 13";
const ENOSYS: &str = "err 38";
const EAFNOSUPPORT: &str = "err 97";
const ENOENT: &str = "err 2";
const EROFS: &str = "err 30";
const EPROTONOSUPPORT: &str = "err 93";

/// A private folder tree for one test, plus a cgroup.
struct World {
    root: PathBuf,
    cgroup: PathBuf,
}

impl World {
    fn new(name: &str) -> World {
        assert!(
            rustix_is_root(),
            "sandbox escape tests must run as root (use tests/vm/sandbox-tests.sh)"
        );
        // Not in /tmp: the app sees its own empty /tmp.
        let root = PathBuf::from(format!(
            "/var/lib/app-sandbox-test/{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("app/bin")).unwrap();
        fs::set_permissions(root.parent().unwrap(), fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        fs::copy(env!("CARGO_BIN_EXE_probe"), root.join("app/bin/probe")).unwrap();

        // The app's own data folder: owned by the app account, closed to others.
        let data = root.join("data");
        fs::create_dir(&data).unwrap();
        fs::copy(env!("CARGO_BIN_EXE_probe"), data.join("probe")).unwrap();
        chown(&data, Some(APP_UID), Some(APP_UID)).unwrap();
        chown(data.join("probe"), Some(APP_UID), Some(APP_UID)).unwrap();
        fs::set_permissions(&data, fs::Permissions::from_mode(0o700)).unwrap();

        // Another app's data, deliberately world-readable: only Landlock stops the probe.
        let other = root.join("other");
        fs::create_dir(&other).unwrap();
        fs::write(other.join("secret"), "secret").unwrap();
        chown(&other, Some(OTHER_UID), Some(OTHER_UID)).unwrap();
        fs::set_permissions(&other, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(other.join("secret"), fs::Permissions::from_mode(0o644)).unwrap();

        // A world-readable file outside every granted path.
        fs::write(root.join("outside.txt"), "outside").unwrap();
        fs::set_permissions(root.join("outside.txt"), fs::Permissions::from_mode(0o644)).unwrap();

        let cgroup = PathBuf::from(format!(
            "/sys/fs/cgroup/app-sandbox-test/{name}-{}",
            std::process::id()
        ));
        fs::create_dir_all(cgroup.parent().unwrap()).unwrap();
        World { root, cgroup }
    }

    fn app(&self) -> PathBuf {
        self.root.join("app")
    }
    fn data(&self) -> PathBuf {
        self.root.join("data")
    }

    /// The rules every test starts from: the foundation (all of `/usr` in
    /// this test), the loader cache, `/proc`, `/dev/null`, the app, its data.
    fn base_args(&self) -> Vec<String> {
        let mut a: Vec<String> = [
            "--uid",
            &APP_UID.to_string(),
            "--gid",
            &APP_UID.to_string(),
            "--cgroup",
            self.cgroup.to_str().unwrap(),
        ]
        .map(String::from)
        .to_vec();
        for rule in [
            "read-exec:/usr".to_owned(),
            "read:/etc/ld.so.cache".to_owned(),
            "device:/dev/null".to_owned(),
            format!("read-exec:{}", self.app().display()),
            format!("read-write-exec:{}", self.data().display()),
        ] {
            a.push("--rule".into());
            a.push(rule);
        }
        a
    }

    /// Runs the probe with `attempts` under the base policy plus `extra`.
    fn run(&self, extra: &[&str], attempts: &[&str]) -> Outcome {
        self.run_with(extra, attempts, |_| {})
    }

    /// Like [`World::run`], letting the test adjust the launcher's process first.
    fn run_with(
        &self,
        extra: &[&str],
        attempts: &[&str],
        adjust: impl FnOnce(&mut Command),
    ) -> Outcome {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_launch"));
        adjust(&mut cmd);
        cmd.args(self.base_args())
            .args(extra)
            .arg("--")
            .arg(self.app().join("bin/probe"))
            .args(attempts);
        let out = cmd.output().unwrap();
        let _ = fs::remove_dir(&self.cgroup);
        Outcome::parse(out)
    }
}

impl Drop for World {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
        let _ = fs::remove_dir(&self.cgroup);
    }
}

struct Outcome {
    code: Option<i32>,
    results: BTreeMap<String, String>,
    facts: Vec<String>,
    stderr: String,
}

impl Outcome {
    fn parse(out: std::process::Output) -> Outcome {
        let stdout = String::from_utf8_lossy(&out.stdout);
        let mut results = BTreeMap::new();
        let mut facts = Vec::new();
        for line in stdout.lines() {
            if let Some(f) = line.strip_prefix('@') {
                facts.push(f.to_owned());
            } else if let Some((what, res)) = line.split_once(' ') {
                results.insert(what.to_owned(), res.to_owned());
            }
        }
        Outcome {
            code: out.status.code(),
            results,
            facts,
            stderr: String::from_utf8_lossy(&out.stderr).into(),
        }
    }

    fn get(&self, attempt: &str) -> &str {
        self.results
            .get(attempt)
            .map(String::as_str)
            .unwrap_or_else(|| panic!("no result for {attempt}; stderr:\n{}", self.stderr))
    }

    fn expect(&self, attempt: &str, want: &str) {
        assert_eq!(
            self.get(attempt),
            want,
            "{attempt}; stderr:\n{}",
            self.stderr
        );
    }

    fn fact(&self, prefix: &str) -> &str {
        self.facts
            .iter()
            .find(|f| f.starts_with(prefix))
            .map(String::as_str)
            .unwrap_or_else(|| {
                panic!(
                    "no fact {prefix}; facts {:?}; stderr:\n{}",
                    self.facts, self.stderr
                )
            })
    }
}

fn rustix_is_root() -> bool {
    // SAFETY: getuid has no arguments and cannot fail.
    unsafe { libc::getuid() == 0 }
}

// ---------------------------------------------------------------------------

#[test]
#[ignore = "needs root and Linux 6.12+; run tests/vm/sandbox-tests.sh"]
fn runs_as_app_account_with_every_protection_active() {
    let w = World::new("identity");
    let o = w.run(&[], &["status"]);
    assert_eq!(o.code, Some(0), "{}", o.stderr);
    let u = APP_UID;
    assert_eq!(o.fact("Uid:"), format!("Uid: {u} {u} {u} {u}"));
    assert_eq!(o.fact("Gid:"), format!("Gid: {u} {u} {u} {u}"));
    assert_eq!(o.fact("Groups:"), "Groups:");
    assert_eq!(o.fact("NoNewPrivs:"), "NoNewPrivs: 1");
    assert_eq!(o.fact("Seccomp:"), "Seccomp: 2");
    assert_eq!(o.fact("CapEff:"), "CapEff: 0000000000000000");
    assert_eq!(o.fact("CapPrm:"), "CapPrm: 0000000000000000");
    let rel = w.cgroup.strip_prefix("/sys/fs/cgroup").unwrap();
    assert_eq!(o.fact("cgroup"), format!("cgroup 0::/{}", rel.display()));
}

#[test]
#[ignore = "needs root and Linux 6.12+; run tests/vm/sandbox-tests.sh"]
fn cannot_become_root_again() {
    let w = World::new("setuid");
    w.run(&[], &["setuid-root"]).expect("setuid-root", EPERM);
}

#[test]
#[ignore = "needs root and Linux 6.12+; run tests/vm/sandbox-tests.sh"]
fn reads_and_runs_its_own_files() {
    let w = World::new("own");
    let app_file = format!("read:{}", w.app().join("bin/probe").display());
    let app_run = format!("exec:{}", w.app().join("bin/probe").display());
    let data_write = format!("write:{}", w.data().join("saved").display());
    let data_read = format!("read:{}", w.data().join("saved").display());
    let data_run = format!("exec:{}", w.data().join("probe").display());
    let o = w.run(
        &[],
        &[&app_file, &app_run, &data_write, &data_read, &data_run],
    );
    for a in [&app_file, &app_run, &data_write, &data_read, &data_run] {
        o.expect(a, "ok");
    }
}

#[test]
#[ignore = "needs root and Linux 6.12+; run tests/vm/sandbox-tests.sh"]
fn cannot_change_its_own_app_files() {
    let w = World::new("readonly");
    let a = format!("write:{}", w.app().join("bin/new").display());
    w.run(&[], &[&a]).expect(&a, EACCES);
}

#[test]
#[ignore = "needs root and Linux 6.12+; run tests/vm/sandbox-tests.sh"]
fn cannot_read_other_apps_or_anything_outside() {
    let w = World::new("outside");
    let other = format!("read:{}", w.root.join("other/secret").display());
    let other_dir = format!("list:{}", w.root.join("other").display());
    let outside = format!("read:{}", w.root.join("outside.txt").display());
    // A unique name, so a file left by an earlier run cannot confuse this one.
    let escaped = format!("/tmp/app-sbx-escaped-{}", std::process::id());
    let _ = fs::remove_file(&escaped);
    let tmp = format!("write:{escaped}");
    let o = w.run(
        &[],
        &[
            &other,
            &other_dir,
            &outside,
            "read:/etc/shadow",
            "read:/etc/passwd",
            "list:/home",
            &tmp,
        ],
    );
    for a in [
        other.as_str(),
        &other_dir,
        &outside,
        "read:/etc/shadow",
        "read:/etc/passwd",
        "list:/home",
        &tmp,
    ] {
        o.expect(a, EACCES);
    }
    assert!(!Path::new(&escaped).exists());
}

#[test]
#[ignore = "needs root and Linux 6.12+; run tests/vm/sandbox-tests.sh"]
fn no_network_without_permission() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let tcp = format!("tcp:{}", listener.local_addr().unwrap());
    let w = World::new("nonet");
    let o = w.run(
        &[],
        &[&tcp, "udp", "socket-high-bits", "socket:17", "io_uring"],
    );
    o.expect(&tcp, EAFNOSUPPORT);
    o.expect("udp", EAFNOSUPPORT);
    o.expect("socket-high-bits", EAFNOSUPPORT);
    o.expect("socket:17", EAFNOSUPPORT); // AF_PACKET
    o.expect("io_uring", ENOSYS);
}

#[test]
#[ignore = "needs root and Linux 6.12+; run tests/vm/sandbox-tests.sh"]
fn network_with_permission() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let tcp = format!("tcp:{}", listener.local_addr().unwrap());
    let w = World::new("net");
    let o = w.run(&["--net"], &[&tcp, "udp", "socket:17"]);
    o.expect(&tcp, "ok");
    o.expect("udp", "ok");
    o.expect("socket:17", EAFNOSUPPORT); // raw packet sockets stay blocked
}

#[test]
#[ignore = "needs root and Linux 6.12+; run tests/vm/sandbox-tests.sh"]
fn blocked_system_calls() {
    let w = World::new("syscalls");
    let calls = [
        "mount", "keyctl", "bpf", "perf", "reboot", "settime", "module",
    ];
    let o = w.run(&[], &calls);
    for c in calls {
        o.expect(c, EPERM);
    }
}

#[test]
#[ignore = "needs root and Linux 6.12+; run tests/vm/sandbox-tests.sh"]
fn user_namespaces_are_allowed() {
    // Chromium, Firefox and Electron build their inner sandboxes with them.
    let w = World::new("userns");
    w.run(&[], &["userns"]).expect("userns", "ok");
}

#[test]
#[ignore = "needs root and Linux 6.12+; run tests/vm/sandbox-tests.sh"]
fn cannot_signal_processes_outside_even_as_the_same_user() {
    let mut sleeper = Command::new("/usr/bin/sleep")
        .arg("30")
        .uid(APP_UID)
        .gid(APP_UID)
        .spawn()
        .unwrap();
    let w = World::new("signal");
    let a = format!("kill:{}", sleeper.id());
    let o = w.run(&[], &[&a]);
    let _ = sleeper.kill();
    let _ = sleeper.wait();
    o.expect(&a, EPERM);
}

#[test]
#[ignore = "needs root and Linux 6.12+; run tests/vm/sandbox-tests.sh"]
fn cannot_reach_abstract_sockets_outside() {
    use std::os::linux::net::SocketAddrExt;
    let name = format!("app-sbx-test-{}", std::process::id());
    let addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
    let _listener = std::os::unix::net::UnixListener::bind_addr(&addr).unwrap();
    let w = World::new("abstract");
    let a = format!("abstract:{name}");
    w.run(&[], &[&a]).expect(&a, EPERM);
}

/// Connecting to a socket file outside the sandbox can only be blocked from
/// Landlock ABI 9 (Linux 7.1). This test records which case applies.
#[test]
#[ignore = "needs root and Linux 6.12+; run tests/vm/sandbox-tests.sh"]
fn socket_files_outside_before_and_after_abi_9() {
    let w = World::new("unixsock");
    let path = w.root.join("public.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o777)).unwrap();
    let abi = app_sandbox::check_kernel().unwrap().landlock_abi;
    let a = format!("unix:{}", path.display());
    let o = w.run(&[], &[&a]);
    if abi >= 9 {
        o.expect(&a, EACCES);
    } else {
        eprintln!(
            "NOTE: Landlock ABI {abi}: sockets outside the sandbox are reachable (needs ABI 9)"
        );
        o.expect(&a, "ok");
    }
}

#[test]
#[ignore = "needs root and Linux 6.12+; run tests/vm/sandbox-tests.sh"]
fn granted_socket_is_reachable() {
    let w = World::new("grantsock");
    let path = w.root.join("wayland-0");
    let _listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o777)).unwrap();
    let rule = format!("connect:{}", path.display());
    let a = format!("unix:{}", path.display());
    w.run(&["--rule", &rule], &[&a]).expect(&a, "ok");
}

#[test]
#[ignore = "needs root and Linux 6.12+; run tests/vm/sandbox-tests.sh"]
fn open_files_of_the_launcher_do_not_leak() {
    let w = World::new("fds");
    // /etc/shadow is opened as root before sandboxing; Landlock would not stop an inherited descriptor.
    let o = w.run(&["--open-leak", "/etc/shadow"], &["fds"]);
    assert_eq!(
        o.fact("fds"),
        "fds 0 1 2 3",
        "only stdio and the listing itself"
    ); // 3 = the probe's own listing
    let o = w.run(&["--open-leak", "/etc/shadow", "--keep", "3"], &["fds"]);
    assert_eq!(
        o.fact("fds"),
        "fds 0 1 2 3 4",
        "a kept descriptor is passed on"
    );
}

#[test]
#[ignore = "needs root and Linux 6.12+; run tests/vm/sandbox-tests.sh"]
fn environment_is_exactly_what_the_launcher_sets() {
    let w = World::new("env");
    let o = w.run(&["--env", "APP_TEST=1"], &["env"]);
    assert_eq!(o.fact("env"), "env APP_TEST=1");
}

#[test]
#[ignore = "needs root and Linux 6.12+; run tests/vm/sandbox-tests.sh"]
fn devices_only_when_granted() {
    let w = World::new("devices");
    let o = w.run(&[], &["read:/dev/null", "read:/dev/zero", "read:/dev/mem"]);
    o.expect("read:/dev/null", "ok");
    o.expect("read:/dev/zero", EACCES);
    o.expect("read:/dev/mem", EACCES);
}

#[test]
#[ignore = "needs root and Linux 6.12+; run tests/vm/sandbox-tests.sh"]
fn fails_closed_on_a_bad_policy() {
    let w = World::new("failclosed");
    for bad in [
        vec!["--uid", "0"],
        vec!["--gid", "0"],
        vec!["--group", "0"],
        vec!["--cgroup", "/tmp/not-a-cgroup"],
        vec!["--rule", "read:relative/path"],
        vec!["--keep", "99"],
    ] {
        // Later options override the base ones.
        let o = w.run(&bad, &["noop"]);
        assert_eq!(
            o.code,
            Some(111),
            "{bad:?} should be refused; stderr:\n{}",
            o.stderr
        );
        assert!(o.results.is_empty(), "{bad:?}: the probe must not run");
    }
}

// ---- Private mount namespace ----------------------------------------------

/// World-writable sockets in /run and /tmp (the system D-Bus, X11, CUPS,
/// Avahi) must be unreachable on every kernel, including before Landlock ABI 9.
#[test]
#[ignore = "needs root and Linux 6.12+; run tests/vm/sandbox-tests.sh"]
fn system_bus_and_tmp_sockets_are_unreachable() {
    let bus = Path::new("/run/dbus/system_bus_socket");
    assert!(bus.exists(), "the test system needs a system D-Bus");
    let tmp_sock = PathBuf::from(format!("/tmp/app-sbx-sock-{}", std::process::id()));
    let _ = fs::remove_file(&tmp_sock);
    let _listener = std::os::unix::net::UnixListener::bind(&tmp_sock).unwrap();
    fs::set_permissions(&tmp_sock, fs::Permissions::from_mode(0o777)).unwrap();

    let w = World::new("hidden");
    let a_bus = format!("unix:{}", bus.display());
    let a_tmp = format!("unix:{}", tmp_sock.display());
    let o = w.run(&[], &[&a_bus, &a_tmp]);
    let _ = fs::remove_file(&tmp_sock);
    o.expect(&a_bus, ENOENT);
    o.expect(&a_tmp, ENOENT);
}

#[test]
#[ignore = "needs root and Linux 6.12+; run tests/vm/sandbox-tests.sh"]
fn proc_shows_only_its_own_processes() {
    // No /proc rule is given: the sandbox grants its private /proc itself.
    let w = World::new("proc");
    let attempts = [
        "read:/proc/self/status",
        "read:/proc/1/status",
        "list:/proc/1",
        "read:/proc/cpuinfo",
        "read:/proc/meminfo",
        "read:/proc/stat",
        "write:/proc/self/comm",
    ];
    let o = w.run(&[], &attempts);
    o.expect("read:/proc/self/status", "ok");
    o.expect("read:/proc/1/status", ENOENT); // root's process: invisible
    o.expect("list:/proc/1", ENOENT);
    o.expect("read:/proc/cpuinfo", "ok");
    o.expect("read:/proc/meminfo", "ok");
    o.expect("read:/proc/stat", "ok");
    o.expect("write:/proc/self/comm", EACCES); // read-only
}

#[test]
#[ignore = "needs root and Linux 6.12+; run tests/vm/sandbox-tests.sh"]
fn private_tmp_is_empty_and_its_own() {
    let marker = PathBuf::from(format!("/tmp/app-sbx-marker-{}", std::process::id()));
    fs::write(&marker, "host").unwrap();
    fs::set_permissions(&marker, fs::Permissions::from_mode(0o644)).unwrap();
    let written = PathBuf::from(format!("/tmp/app-sbx-written-{}", std::process::id()));
    let _ = fs::remove_file(&written);

    let w = World::new("privtmp");
    let a_marker = format!("read:{}", marker.display());
    let a_write = format!("write:{}", written.display());
    let o = w.run(&["--rule", "read-write:/tmp"], &[&a_marker, &a_write]);
    let _ = fs::remove_file(&marker);
    o.expect(&a_marker, ENOENT); // the host's /tmp is not visible
    o.expect(&a_write, "ok"); // its own /tmp works
    assert!(
        !written.exists(),
        "the write must stay inside the app's private /tmp"
    );
}

#[test]
#[ignore = "needs root and Linux 6.12+; run tests/vm/sandbox-tests.sh"]
fn binds_are_read_only_and_only_what_was_asked() {
    assert!(
        Path::new("/run/udev/data").is_dir(),
        "the test system needs udev"
    );
    let w = World::new("binds");
    let args = [
        "--bind",
        "/run/udev/data:/run/udev/data",
        "--rule",
        "read-write:/run/udev",
    ];
    let o = w.run(
        &args,
        &[
            "list:/run/udev/data",
            "write:/run/udev/data/x",
            "list:/run/dbus",
            "write:/run/new",
        ],
    );
    o.expect("list:/run/udev/data", "ok");
    o.expect("write:/run/udev/data/x", EROFS);
    o.expect("list:/run/dbus", ENOENT);
    o.expect("write:/run/new", EACCES); // Landlock: /run itself was not granted
    // Without the bind, udev data is not there at all.
    w.run(&["--rule", "read:/run/udev"], &["list:/run/udev/data"])
        .expect("list:/run/udev/data", ENOENT);
}

#[test]
#[ignore = "needs root and Linux 6.12+; run tests/vm/sandbox-tests.sh"]
fn cannot_undo_the_private_view() {
    let w = World::new("umount");
    let o = w.run(&[], &["umount:/run", "umount:/proc", "umount:/tmp"]);
    for a in ["umount:/run", "umount:/proc", "umount:/tmp"] {
        o.expect(a, EPERM);
    }
}

#[test]
#[ignore = "needs root and Linux 6.12+; run tests/vm/sandbox-tests.sh"]
fn only_route_and_uevent_netlink() {
    let w = World::new("netlink");
    let o = w.run(
        &[],
        &[
            "netlink:0",
            "netlink:15",
            "netlink:9",
            "netlink:4",
            "netlink:16",
        ],
    );
    o.expect("netlink:0", "ok"); // NETLINK_ROUTE
    o.expect("netlink:15", "ok"); // NETLINK_KOBJECT_UEVENT
    o.expect("netlink:9", EPROTONOSUPPORT); // NETLINK_AUDIT
    o.expect("netlink:4", EPROTONOSUPPORT); // NETLINK_SOCK_DIAG
    o.expect("netlink:16", EPROTONOSUPPORT); // NETLINK_GENERIC
}

// ---- Terminal injection, placed sockets, browser sandboxes -----------------

/// A new pseudo-terminal: (controlling side, terminal side).
fn pty() -> (fs::File, fs::File) {
    use std::os::fd::FromRawFd;
    // SAFETY: standard pty setup; every returned descriptor is checked and owned.
    unsafe {
        let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        assert!(master >= 0);
        assert_eq!(libc::grantpt(master), 0);
        assert_eq!(libc::unlockpt(master), 0);
        let mut name = [0 as libc::c_char; 128];
        assert_eq!(libc::ptsname_r(master, name.as_mut_ptr(), name.len()), 0);
        let slave = libc::open(name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY);
        assert!(slave >= 0);
        (fs::File::from_raw_fd(master), fs::File::from_raw_fd(slave))
    }
}

/// The launcher runs in a terminal (its session's controlling terminal is
/// on fd 0). The app must not be able to type commands into it.
#[test]
#[ignore = "needs root and Linux 6.12+; run tests/vm/sandbox-tests.sh"]
fn cannot_type_into_the_launchers_terminal() {
    let (_master, terminal) = pty();
    let w = World::new("tiocsti");
    let o = w.run_with(&[], &["tiocsti"], |cmd| {
        cmd.stdin(terminal);
        // SAFETY: only async-signal-safe calls between fork and exec.
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    });
    o.expect("tiocsti", EPERM);
}

/// Sockets the launcher places into the private /run are reachable; any
/// other socket, even one right beside it outside, is not.
#[test]
#[ignore = "needs root and Linux 6.12+; run tests/vm/sandbox-tests.sh"]
fn placed_socket_reachable_unplaced_not() {
    let dir = PathBuf::from(format!("/run/app-sbx-sockets-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let (a, b) = (dir.join("a.sock"), dir.join("b.sock"));
    let _la = std::os::unix::net::UnixListener::bind(&a).unwrap();
    let _lb = std::os::unix::net::UnixListener::bind(&b).unwrap();
    for s in [&a, &b] {
        fs::set_permissions(s, fs::Permissions::from_mode(0o777)).unwrap();
    }
    let w = World::new("placed");
    let bind = format!("{}:/run/app/a.sock", a.display());
    let placed = "unix:/run/app/a.sock";
    let unplaced = format!("unix:{}", b.display());
    let original = format!("unix:{}", a.display());
    let o = w.run(
        &["--bind", &bind, "--rule", "connect:/run/app/a.sock"],
        &[placed, &unplaced, &original],
    );
    let _ = fs::remove_dir_all(&dir);
    o.expect(placed, "ok");
    o.expect(&unplaced, ENOENT);
    o.expect(&original, ENOENT);
}
