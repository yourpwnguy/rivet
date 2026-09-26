//! Error type for the CLI layer.
//!
//! Hand-rolled instead of pulling in `thiserror`: the CLI has exactly two
//! failure modes, and both are presented identically to the user.

use std::fmt;

/// A fatal CLI-level error (exit code 1).
#[derive(Debug)]
pub enum CliError {
    /// A path could not be read or walked.
    Io {
        /// What rivet was trying to do.
        context: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// `rivet.yaml` was malformed.
    Config {
        /// What rivet was trying to do.
        context: String,
        /// Underlying parse error.
        source: rivet_core::config::ConfigError,
    },
}

impl CliError {
    /// Wrap an I/O error with context.
    pub fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }

    /// Wrap a config error with context.
    pub fn config(context: impl Into<String>, source: rivet_core::config::ConfigError) -> Self {
        Self::Config {
            context: context.into(),
            source,
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::Io { context, source } => write!(f, "{context}: {source}"),
            CliError::Config { context, source } => write!(f, "{context}: {source}"),
        }
    }
}

impl std::error::Error for CliError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CliError::Io { source, .. } => Some(source),
            CliError::Config { source, .. } => Some(source),
        }
    }
}

/// Allow `?` on I/O results at call sites where the underlying error
/// already carries the path (e.g. `DirEntry::file_type`).
impl From<std::io::Error> for CliError {
    fn from(source: std::io::Error) -> Self {
        Self::Io {
            context: "I/O error".into(),
            source,
        }
    }
}
