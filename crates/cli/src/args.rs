//! Command-line interface definition.
//!
//! The CLI surface is intentionally small: one path, a few behavior
//! switches, and the exit-code contract (`0` pass, `2` policy breach,
//! `1` system error) that CI gates rely on.

use std::path::PathBuf;

use clap::{Parser, ValueEnum};
use rivet_core::severity::Severity;

/// rivet — GitHub Actions security auditor.
///
/// Reads `.github/workflows/*.yml|*.yaml` files, runs the R01–R10 security
/// rules against them, and reports findings. Never executes workflow
/// logic, never evaluates `${{ }}` expressions beyond pattern-matching, and
/// never touches the network.
#[derive(Debug, Parser)]
#[command(name = "rivet", version, about, long_about = None)]
pub struct Args {
    /// Path to a repository or directory to scan.
    #[arg(short, long, default_value = ".")]
    pub path: PathBuf,

    /// Recurse into subdirectories looking for `.github/workflows`.
    #[arg(short, long)]
    pub recursive: bool,

    /// Exit non-zero when a finding at or above this severity exists.
    #[arg(short = 'f', long, value_enum, default_value_t = FailOn::High)]
    pub fail_on: FailOn,

    /// Output format.
    #[arg(short = 'o', long, value_enum, default_value_t = Format::Text)]
    pub format: Format,

    /// Suppress all output; only the exit code is meaningful.
    #[arg(short, long)]
    pub quiet: bool,

    /// Disable colored output.
    #[arg(short = 'c', long)]
    pub no_color: bool,

    /// Override repository visibility (gates the self-hosted runner rule).
    #[arg(short = 'v', long, value_enum)]
    pub repo_visibility: Option<VisibilityArg>,

    /// Show what a patched workflow would look like, without writing.
    #[arg(short = 'd', long)]
    pub fix_dry: bool,

    /// List all rules with severity and description, then exit.
    #[arg(short = 'l', long, conflicts_with_all = ["path", "recursive", "fail_on", "format", "quiet", "repo_visibility", "fix_dry"])]
    pub list_rules: bool,
}

/// `--fail-on` severity threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FailOn {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl FailOn {
    /// Map to the core severity used in the policy comparison.
    pub fn to_severity(self) -> Severity {
        match self {
            FailOn::Critical => Severity::Critical,
            FailOn::High => Severity::High,
            FailOn::Medium => Severity::Medium,
            FailOn::Low => Severity::Low,
            FailOn::Info => Severity::Info,
        }
    }
}

/// Output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Format {
    Text,
    Json,
    Table,
}

/// `--repo-visibility` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum VisibilityArg {
    Public,
    Private,
    Unknown,
}

impl From<VisibilityArg> for rivet_core::config::Visibility {
    fn from(v: VisibilityArg) -> Self {
        use rivet_core::config::Visibility;
        match v {
            VisibilityArg::Public => Visibility::Public,
            VisibilityArg::Private => Visibility::Private,
            VisibilityArg::Unknown => Visibility::Unknown,
        }
    }
}
