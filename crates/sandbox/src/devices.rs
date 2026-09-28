//! Finding the files a granted game controller needs (spec section 7,
//! "Devices": input devices and raw HID devices of game controllers, never
//! keyboards or touchscreens).
//!
//! SDL and other libraries find controllers through libudev: they read the
//! device's properties in `/run/udev/data/c<major>:<minor>` and its folder
//! in `/sys`, then open its nodes in `/dev`. For each controller present,
//! this grants exactly that: its udev data files, its own `/sys` folder, and
//! its device nodes (input events, joystick, raw HID for rumble and motion).
//!
//! Controllers are recognized by udev's `ID_INPUT_JOYSTICK=1`. Every input
//! and raw HID node of the same physical controller is included (motion
//! sensors, touchpads), except any that udev marks as a keyboard or touchscreen.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::{Access, PathRule};

/// What a sandboxed app needs to use the controllers present right now.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Gamepads {
    /// Device nodes to open: `/dev/input/event*`, `/dev/input/js*`, `/dev/hidraw*`.
    pub nodes: Vec<PathBuf>,
    /// udev property files, one per node.
    pub udev_data: Vec<PathBuf>,
    /// Each controller's own folder under `/sys/devices`.
    pub sysfs: Vec<PathBuf>,
}

impl Gamepads {
    /// Landlock rules granting this access. Also lets libudev list
    /// `/sys/class/input` and `/sys/class/hidraw` (names only; reading any
    /// other device there is still denied).
    pub fn rules(&self, root: &Path) -> Vec<PathRule> {
        let rule = |path: &Path, access| PathRule {
            path: path.to_owned(),
            access,
        };
        let mut rules: Vec<PathRule> = self.nodes.iter().map(|p| rule(p, Access::Device)).collect();
        rules.extend(
            self.udev_data
                .iter()
                .chain(&self.sysfs)
                .map(|p| rule(p, Access::Read)),
        );
        for class in ["sys/class/input", "sys/class/hidraw"] {
            rules.push(rule(&root.join(class), Access::Read));
        }
        rules
    }
}

/// Properties udev recorded for one device.
struct Props(String);

impl Props {
    fn is(&self, key: &str) -> bool {
        self.0
            .lines()
            .any(|l| l.strip_prefix("E:").and_then(|kv| kv.strip_prefix(key)) == Some("=1"))
    }
}

/// Finds the controllers present under `root` (`/` on a real system).
pub fn discover(root: &Path) -> io::Result<Gamepads> {
    let udev = root.join("run/udev/data");
    let mut found = Gamepads::default();
    let entries = match fs::read_dir(&udev) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(found),
        Err(e) => return Err(e),
    };
    let mut physical_dirs = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let Some(devnum) = name.to_str().and_then(|n| n.strip_prefix('c')) else {
            continue;
        };
        let props = Props(fs::read_to_string(entry.path()).unwrap_or_default());
        if !props.is("ID_INPUT_JOYSTICK") || excluded(&props) {
            continue;
        }
        let Ok(sys) = fs::canonicalize(root.join("sys/dev/char").join(devnum)) else {
            continue;
        };
        if let Some(dir) = physical_dir(&sys)
            && !physical_dirs.contains(&dir)
        {
            physical_dirs.push(dir);
        }
    }
    physical_dirs.sort();
    for dir in physical_dirs {
        collect(root, &dir, &mut found)?;
        found.sysfs.push(dir);
    }
    Ok(found)
}

fn excluded(props: &Props) -> bool {
    props.is("ID_INPUT_KEYBOARD") || props.is("ID_INPUT_TOUCHSCREEN") || props.is("ID_INPUT_TABLET")
}

/// The controller's folder: the part of its `/sys` path before
/// `/input/input<N>`. Virtual devices (uinput, as remapping tools and Steam
/// Input create) all share `/sys/devices/virtual/input`, so for them the
/// `input<N>` folder itself is the controller's folder.
fn physical_dir(sys: &Path) -> Option<PathBuf> {
    let mut dir = sys;
    while let Some(parent) = dir.parent() {
        if parent.file_name().is_some_and(|n| n == "input")
            && dir
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("input"))
        {
            let above = parent.parent()?;
            if above.ends_with("devices/virtual") {
                return Some(dir.to_owned());
            }
            return Some(above.to_owned());
        }
        dir = parent;
    }
    None
}

/// Adds every usable node below `dir`: input nodes that are not keyboards or
/// touchscreens, and raw HID nodes.
fn collect(root: &Path, dir: &Path, found: &mut Gamepads) -> io::Result<()> {
    let mut stack = vec![dir.to_owned()];
    while let Some(d) = stack.pop() {
        for entry in fs::read_dir(&d)? {
            let entry = entry?;
            let ft = entry.file_type()?;
            if ft.is_symlink() {
                continue; // `device`, `subsystem`: links out of this folder
            }
            if ft.is_dir() {
                stack.push(entry.path());
                continue;
            }
            if entry.file_name() != "uevent" {
                continue;
            }
            let uevent = fs::read_to_string(entry.path()).unwrap_or_default();
            let get = |k: &str| {
                uevent
                    .lines()
                    .find_map(|l| l.strip_prefix(k))
                    .map(str::to_owned)
            };
            let (Some(devname), Some(major), Some(minor)) =
                (get("DEVNAME="), get("MAJOR="), get("MINOR="))
            else {
                continue;
            };
            let is_node = devname.starts_with("input/event")
                || devname.starts_with("input/js")
                || devname.starts_with("hidraw");
            if !is_node || devname.contains("..") {
                continue;
            }
            let data = root.join("run/udev/data").join(format!("c{major}:{minor}"));
            let props = Props(fs::read_to_string(&data).unwrap_or_default());
            if excluded(&props) {
                continue;
            }
            found.nodes.push(root.join("dev").join(&devname));
            found.udev_data.push(data);
        }
    }
    found.nodes.sort();
    found.udev_data.sort();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    /// Builds a fake `/sys`, `/run/udev/data` and `/dev` for one input or hidraw node.
    fn node(root: &Path, sys_dir: &str, devname: &str, devnum: (u32, u32), props: &[&str]) {
        let dir = root.join(sys_dir);
        fs::create_dir_all(&dir).unwrap();
        let (ma, mi) = devnum;
        fs::write(
            dir.join("uevent"),
            format!("MAJOR={ma}\nMINOR={mi}\nDEVNAME={devname}\n"),
        )
        .unwrap();
        let data = root.join("run/udev/data");
        fs::create_dir_all(&data).unwrap();
        let text: String = props.iter().map(|p| format!("E:{p}\n")).collect();
        fs::write(data.join(format!("c{ma}:{mi}")), text).unwrap();
        let link_dir = root.join("sys/dev/char");
        fs::create_dir_all(&link_dir).unwrap();
        symlink(&dir, link_dir.join(format!("{ma}:{mi}"))).unwrap();
    }

    const PAD: &str = "sys/devices/usb1/1-1/0003:054C:0CE6.0001";
    const KBD: &str = "sys/devices/usb1/1-2/0003:046D:C31C.0002";

    fn fake() -> tempfile::TempDir {
        let t = tempfile::tempdir().unwrap();
        let r = t.path();
        // A PlayStation-style controller: gamepad, touchpad, motion sensors, raw HID.
        node(
            r,
            &format!("{PAD}/input/input5/event5"),
            "input/event5",
            (13, 69),
            &["ID_INPUT=1", "ID_INPUT_JOYSTICK=1"],
        );
        node(
            r,
            &format!("{PAD}/input/input5/js0"),
            "input/js0",
            (13, 0),
            &["ID_INPUT=1", "ID_INPUT_JOYSTICK=1"],
        );
        node(
            r,
            &format!("{PAD}/input/input6/event6"),
            "input/event6",
            (13, 70),
            &["ID_INPUT=1", "ID_INPUT_TOUCHPAD=1"],
        );
        node(
            r,
            &format!("{PAD}/input/input7/event7"),
            "input/event7",
            (13, 71),
            &["ID_INPUT=1", "ID_INPUT_ACCELEROMETER=1"],
        );
        node(
            r,
            &format!("{PAD}/hidraw/hidraw0"),
            "hidraw0",
            (243, 0),
            &[],
        );
        // A keyboard, with its own raw HID node.
        node(
            r,
            &format!("{KBD}/input/input3/event3"),
            "input/event3",
            (13, 67),
            &["ID_INPUT=1", "ID_INPUT_KEYBOARD=1", "ID_INPUT_KEY=1"],
        );
        node(
            r,
            &format!("{KBD}/hidraw/hidraw1"),
            "hidraw1",
            (243, 1),
            &[],
        );
        t
    }

    #[test]
    fn finds_controller_and_nothing_else() {
        let t = fake();
        let r = fs::canonicalize(t.path()).unwrap();
        let g = discover(t.path()).unwrap();
        let dev = |n: &str| r.join("dev").join(n);
        assert_eq!(
            g.nodes,
            vec![
                dev("hidraw0"),
                dev("input/event5"),
                dev("input/event6"),
                dev("input/event7"),
                dev("input/js0")
            ]
        );
        assert_eq!(g.sysfs, vec![r.join(PAD)]);
        assert_eq!(g.udev_data.len(), 5);
        assert!(
            !g.nodes
                .iter()
                .any(|n| n.ends_with("event3") || n.ends_with("hidraw1"))
        );
        assert!(
            !g.udev_data
                .iter()
                .any(|d| d.ends_with("c13:67") || d.ends_with("c243:1"))
        );
    }

    #[test]
    fn keyboard_flagged_joystick_is_excluded() {
        let t = tempfile::tempdir().unwrap();
        node(
            t.path(),
            "sys/devices/x/input/input1/event1",
            "input/event1",
            (13, 65),
            &["ID_INPUT_JOYSTICK=1", "ID_INPUT_KEYBOARD=1"],
        );
        assert_eq!(discover(t.path()).unwrap(), Gamepads::default());
    }

    #[test]
    fn built_in_controller_without_hid() {
        // Handhelds such as the R36S: a platform device, no USB or HID.
        let t = tempfile::tempdir().unwrap();
        node(
            t.path(),
            "sys/devices/platform/joypad/input/input0/event0",
            "input/event0",
            (13, 64),
            &["ID_INPUT_JOYSTICK=1"],
        );
        let g = discover(t.path()).unwrap();
        assert_eq!(g.nodes.len(), 1);
        assert!(g.sysfs[0].ends_with("sys/devices/platform/joypad"));
    }

    #[test]
    fn virtual_gamepad_alone_is_granted() {
        // uinput devices from remapping tools: a gamepad, a mouse and a
        // keyboard, all under /sys/devices/virtual/input.
        let t = tempfile::tempdir().unwrap();
        let r = t.path();
        let v = "sys/devices/virtual/input";
        node(
            r,
            &format!("{v}/input9/event9"),
            "input/event9",
            (13, 73),
            &["ID_INPUT=1", "ID_INPUT_JOYSTICK=1"],
        );
        node(
            r,
            &format!("{v}/input9/js1"),
            "input/js1",
            (13, 1),
            &["ID_INPUT=1", "ID_INPUT_JOYSTICK=1"],
        );
        node(
            r,
            &format!("{v}/input10/event10"),
            "input/event10",
            (13, 74),
            &["ID_INPUT=1", "ID_INPUT_MOUSE=1"],
        );
        node(
            r,
            &format!("{v}/input11/event11"),
            "input/event11",
            (13, 75),
            &["ID_INPUT=1", "ID_INPUT_KEYBOARD=1"],
        );
        let root = fs::canonicalize(r).unwrap();
        let g = discover(r).unwrap();
        assert_eq!(
            g.nodes,
            vec![root.join("dev/input/event9"), root.join("dev/input/js1")]
        );
        assert_eq!(g.sysfs, vec![root.join(v).join("input9")]);
        assert_eq!(g.udev_data.len(), 2);
    }

    #[test]
    fn no_udev_means_no_controllers() {
        let t = tempfile::tempdir().unwrap();
        assert_eq!(discover(t.path()).unwrap(), Gamepads::default());
    }
}
