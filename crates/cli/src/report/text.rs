//! Human-readable terminal report.
//!
//! Layout (one block per finding):
//!
//! ```text
//! ✗ CRITICAL script-injection .github/workflows/pr.yml:24
//!   │ run step interpolates untrusted context `github.event.issue.title`
//!   │ Event fields like issue titles are fully attacker-controlled…
//!   └ fix: Bind the value to an env var, then reference it
//! ```
//!
//! Long strings are truncated so one pathological workflow cannot wreck the
//! layout. Colors follow severity and are stripped entirely when disabled.
//!
//! `--fix-dry` renders each fix as a full paste-ready block; normal mode
//! shows a compact one-line summary.

use std::io::Write;

use rivet_core::finding::Finding;
use rivet_core::severity::Severity;

use super::Stats;

/// ANSI reset.
const RESET: &str = "\x1b[0m";

/// Maximum rendered length of a single line of message/explanation/code.
const MAX_LINE: usize = 100;

/// Write the full text report: header, finding blocks, summary.
pub fn write<W: Write>(
    out: &mut W,
    findings: &[Finding],
    stats: &Stats,
    color: bool,
    fix_dry: bool,
) -> std::io::Result<()> {
    writeln!(
        out,
        "rivet · {} workflows · {} jobs · {}ms",
        stats.workflows, stats.jobs, stats.elapsed_ms
    )?;
    writeln!(out, "{}", "─".repeat(64))?;

    for f in findings {
        write_finding(out, f, color, fix_dry)?;
    }

    writeln!(out)?;
    writeln!(out, "{}", "─".repeat(64))?;
    writeln!(out, "{}", summary_line(findings, stats))?;
    Ok(())
}

/// Render one finding block.
fn write_finding<W: Write>(
    out: &mut W,
    f: &Finding,
    color: bool,
    fix_dry: bool,
) -> std::io::Result<()> {
    writeln!(out)?;
    let sev = if color {
        format!(
            "{}{:<8}{}",
            severity_color(f.severity),
            f.severity.to_string().to_uppercase(),
            RESET
        )
    } else {
        format!("{:<8}", f.severity.to_string().to_uppercase())
    };
    let location = f
        .line
        .map(|l| format!("{}:{}", f.file.display(), l))
        .unwrap_or_else(|| f.file.display().to_string());
    writeln!(
        out,
        "{} {} {} {}",
        glyph(f.severity),
        sev,
        f.rule.as_str(),
        location
    )?;
    writeln!(out, "  │ {}", truncate(&f.message))?;
    writeln!(out, "  │ {}", truncate(&f.explanation))?;
    // Fix: a compact one-liner normally; the full paste-ready block with
    // --fix-dry.
    let mut fix_lines = f.fix.lines();
    if let Some(first) = fix_lines.next() {
        writeln!(
            out,
            "  └ {} {}",
            if fix_dry { "fix-dry:" } else { "fix:" },
            truncate(first)
        )?;
    }
    if fix_dry {
        for line in fix_lines {
            writeln!(out, "     {}", truncate(line))?;
        }
    }
    Ok(())
}

/// Severity glyph: ✗ for actionable findings, ℹ for informational.
fn glyph(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "ℹ",
        _ => "✗",
    }
}

/// ANSI color per severity.
fn severity_color(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "\x1b[1;31m", // bold red
        Severity::High => "\x1b[31m",       // red
        Severity::Medium => "\x1b[33m",     // yellow
        Severity::Low => "\x1b[34m",        // blue
        Severity::Info => "\x1b[2m",        // dim
    }
}

/// Truncate to [`MAX_LINE`] chars on a char boundary, with an ellipsis.
fn truncate(s: &str) -> String {
    if s.chars().count() <= MAX_LINE {
        return s.to_owned();
    }
    let truncated: String = s.chars().take(MAX_LINE - 1).collect();
    format!("{truncated}…")
}

/// The closing summary: severity breakdown, or a clean bill of health.
fn summary_line(findings: &[Finding], stats: &Stats) -> String {
    if findings.is_empty() {
        let clean = stats.workflows.saturating_sub(stats.dirty_workflows);
        let plural = if clean == 1 { "" } else { "s" };
        return format!(
            "✓ {clean} clean workflow{plural} · 0 findings · {}ms",
            stats.elapsed_ms
        );
    }
    let mut counts = [0usize; 5];
    for f in findings {
        counts[f.severity as usize] += 1;
    }
    let parts: Vec<String> = [
        (Severity::Critical, counts[0]),
        (Severity::High, counts[1]),
        (Severity::Medium, counts[2]),
        (Severity::Low, counts[3]),
        (Severity::Info, counts[4]),
    ]
    .iter()
    .filter(|(_, n)| *n > 0)
    .map(|(s, n)| format!("{n} {s}"))
    .collect();
    format!("{} · {}ms", parts.join(" · "), stats.elapsed_ms)
}
