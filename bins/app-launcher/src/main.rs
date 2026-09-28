//! `app-launcher`: privileged, socket-activated launcher.
//!
//! Keep this small and reviewable. No `unwrap`/`expect`: every error aborts
//! the launch, and nothing is ever executed as root on an app's behalf.

use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!("app-launcher: not implemented yet");
    ExitCode::FAILURE
}
