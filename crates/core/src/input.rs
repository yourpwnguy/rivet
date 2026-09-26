//! The per-file analysis bundle.
//!
//! `ParsedWorkflow` owns the raw text and the parsed model together, so
//! rules can borrow both through one context without self-referential
//! structs or clones.

use std::path::PathBuf;

use crate::model::Workflow;

/// A workflow file that has been read and parsed, raw text retained.
pub struct ParsedWorkflow {
    /// Path as discovered; the CLI relativizes it for display.
    pub path: PathBuf,
    /// Original file text — source of truth for line numbers and ignore
    /// comments.
    pub raw: String,
    /// Normalized domain model the rules evaluate.
    pub model: Workflow,
}

impl ParsedWorkflow {
    /// Bundle a parsed file. Ownership of `raw` moves in — no clones.
    pub fn new(path: PathBuf, raw: String, model: Workflow) -> Self {
        Self { path, raw, model }
    }

    /// 1-based line of the first line containing `needle`.
    pub fn find_line(&self, needle: &str) -> Option<usize> {
        crate::locate::find_line(&self.raw, needle)
    }
}
