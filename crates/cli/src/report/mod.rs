//! Output rendering — the only module that knows what findings look like.
//!
//! Rendering is streaming: findings are written one at a time through a
//! locked stdout, so report generation never buffers the whole output and
//! never becomes a bottleneck relative to the analysis itself.

use std::io::{IsTerminal, Write};

use rivet_core::finding::Finding;
use rivet_core::severity::Severity;

pub mod json;
pub mod table;
pub mod text;

/// Rendered scan statistics shown in text and table mode.
#[derive(Debug, Clone, Copy)]
pub struct Stats {
    /// Workflow files audited.
    pub workflows: usize,
    /// Total jobs across those workflows.
    pub jobs: usize,
    /// Workflows with at least one finding.
    pub dirty_workflows: usize,
    /// Wall-clock time for discovery + analysis.
    pub elapsed_ms: u128,
}

/// Everything rendering needs, bundled so `emit`'s signature stays small.
pub struct RenderOptions<'a> {
    /// Scan statistics for text/table mode.
    pub stats: Stats,
    /// Per-repo workflow counts for table mode.
    pub workflows_per_repo: &'a [(String, usize)],
    /// Output format.
    pub format: crate::args::Format,
    /// Breach threshold for table STATUS.
    pub fail_on: Severity,
    /// ANSI color.
    pub color: bool,
    /// Render `--fix-dry` patches.
    pub fix_dry: bool,
}

/// Write findings to `out` in the requested format.
pub fn emit<W: Write>(
    out: &mut W,
    findings: &[Finding],
    opts: &RenderOptions<'_>,
) -> std::io::Result<()> {
    match opts.format {
        crate::args::Format::Json => json::write(out, findings),
        crate::args::Format::Text => {
            text::write(out, findings, &opts.stats, opts.color, opts.fix_dry)
        }
        crate::args::Format::Table => {
            table::write(out, findings, opts.workflows_per_repo, opts.fail_on)
        }
    }
}

/// True when ANSI color should be used: not explicitly disabled, no
/// `NO_COLOR`, not a dumb terminal, and stdout is a TTY (piped output —
/// CI logs, `jq` — stays machine-clean).
pub fn color_enabled(no_color: bool) -> bool {
    if no_color {
        return false;
    }
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    if std::env::var("TERM").is_ok_and(|t| t == "dumb") {
        return false;
    }
    std::io::stdout().is_terminal()
}
