//! Problems (refusals) and warnings produced while checking a manifest or bundle.

use std::fmt;

/// Why a manifest or bundle was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProblemKind {
    /// The bundle is malformed or breaks a rule.
    Invalid,
    /// The bundle needs something this system does not understand (a newer
    /// `format`, an unknown `requires` key). Shown as "Needs a newer system version".
    NeedsNewerSystem,
}

/// One reason a manifest or bundle was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Problem {
    pub kind: ProblemKind,
    /// Dotted field path (`app.id`) or bundle path (`icons/256.png`); empty for the whole file.
    pub field: String,
    pub message: String,
}

/// Something `app check` reports but the installer accepts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Warning {
    pub field: String,
    pub message: String,
}

/// A refused manifest or bundle, with every problem found.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub struct Error {
    pub problems: Vec<Problem>,
}

impl Error {
    /// Whether the user should be told to update their system rather than
    /// that the bundle is broken.
    pub fn needs_newer_system(&self) -> bool {
        self.problems
            .iter()
            .any(|p| p.kind == ProblemKind::NeedsNewerSystem)
    }
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.field.is_empty() {
            f.write_str(&self.message)
        } else {
            write!(f, "{}: {}", self.field, self.message)
        }
    }
}

impl fmt::Display for Warning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.field, self.message)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let lines: Vec<String> = self.problems.iter().map(Problem::to_string).collect();
        f.write_str(&lines.join("\n"))
    }
}

/// Collects problems and warnings during a check.
#[derive(Default, Debug)]
pub(crate) struct Report {
    pub problems: Vec<Problem>,
    pub warnings: Vec<Warning>,
}

impl Report {
    pub fn invalid(&mut self, field: impl Into<String>, message: impl Into<String>) {
        self.problems.push(Problem {
            kind: ProblemKind::Invalid,
            field: field.into(),
            message: message.into(),
        });
    }

    pub fn newer_system(&mut self, field: impl Into<String>, message: impl Into<String>) {
        self.problems.push(Problem {
            kind: ProblemKind::NeedsNewerSystem,
            field: field.into(),
            message: message.into(),
        });
    }

    pub fn warn(&mut self, field: impl Into<String>, message: impl Into<String>) {
        self.warnings.push(Warning {
            field: field.into(),
            message: message.into(),
        });
    }

    /// Records `result` as a problem on `field` if it is an error.
    pub fn check(&mut self, field: impl Into<String>, result: Result<(), String>) {
        if let Err(message) = result {
            self.invalid(field, message);
        }
    }

    pub fn finish(self) -> Result<Vec<Warning>, Error> {
        if self.problems.is_empty() {
            Ok(self.warnings)
        } else {
            Err(Error {
                problems: self.problems,
            })
        }
    }
}
