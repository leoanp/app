//! `app`: install, update, remove and list apps.
//!
//! Packager subcommands (`build`, `convert`, `check`, `run`, `sign`,
//! `inspect`) are forwarded to the separate `app-pack` binary, git-style.

use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!("app: not implemented yet");
    ExitCode::FAILURE
}
