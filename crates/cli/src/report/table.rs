//! Per-repo summary table for multi-repo (recursive) scans.
//!
//! ```text
//! REPO          WORKFLOWS  CRITICAL  HIGH  MED  LOW  STATUS
//! api-server    5          1         2     1    0    FAIL
//! web-frontend  3          0         0     0    1    PASS
//! ```
//!
//! Repos are the top-level directories under the scan root. STATUS is FAIL
//! when the repo has a finding at or above the `--fail-on` threshold.

use std::collections::BTreeMap;
use std::io::Write;

use rivet_core::finding::Finding;
use rivet_core::severity::Severity;

/// Aggregated counts for one repo.
#[derive(Debug, Default)]
struct RepoRow {
    workflows: usize,
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    breach: bool,
}

/// Write the per-repo table.
///
/// `workflows_per_repo` maps each top-level directory under the scan root to
/// its audited workflow count, reconstructed by the caller from the
/// discovered files.
pub fn write<W: Write>(
    out: &mut W,
    findings: &[Finding],
    workflows_per_repo: &[(String, usize)],
    fail_on: Severity,
) -> std::io::Result<()> {
    let mut rows: BTreeMap<String, RepoRow> = BTreeMap::new();
    for (repo, count) in workflows_per_repo {
        rows.entry(repo.clone()).or_default().workflows = *count;
    }
    for f in findings {
        let row = rows.entry(repo_name(&f.file)).or_default();
        match f.severity {
            Severity::Critical => row.critical += 1,
            Severity::High => row.high += 1,
            Severity::Medium => row.medium += 1,
            Severity::Low => row.low += 1,
            Severity::Info => {}
        }
        if f.severity <= fail_on {
            row.breach = true;
        }
    }

    writeln!(
        out,
        "{:<14} {:>9} {:>8} {:>5} {:>4} {:>4}  STATUS",
        "REPO", "WORKFLOWS", "CRITICAL", "HIGH", "MED", "LOW"
    )?;
    let mut totals = RepoRow::default();
    for (repo, row) in &rows {
        writeln!(
            out,
            "{:<14} {:>9} {:>8} {:>5} {:>4} {:>4}  {}",
            repo,
            row.workflows,
            row.critical,
            row.high,
            row.medium,
            row.low,
            if row.breach { "FAIL" } else { "PASS" },
        )?;
        totals.workflows += row.workflows;
        totals.critical += row.critical;
        totals.high += row.high;
        totals.medium += row.medium;
        totals.low += row.low;
        totals.breach |= row.breach;
    }
    writeln!(out, "{}", "─".repeat(58))?;
    writeln!(
        out,
        "{} repos · {} critical · {} high · {} med · {} low",
        rows.len(),
        totals.critical,
        totals.high,
        totals.medium,
        totals.low,
    )?;
    Ok(())
}

/// The repo for a finding: its first path component, or `.` for a bare file.
fn repo_name(path: &std::path::Path) -> String {
    path.components()
        .next()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .unwrap_or_else(|| ".".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rivet_core::finding::RuleId;
    use rivet_core::severity::Severity;
    use std::path::PathBuf;

    fn finding(repo: &str, name: &str, severity: Severity) -> Finding {
        Finding {
            rule: RuleId::UnpinnedAction,
            severity,
            file: PathBuf::from(format!("{repo}/{name}")),
            line: Some(1),
            job: None,
            message: "m".into(),
            explanation: "e".into(),
            fix: "t".into(),
        }
    }

    #[test]
    fn aggregates_by_repo() {
        let findings = vec![
            finding("api", "a.yml", Severity::Critical),
            finding("api", "b.yml", Severity::High),
            finding("web", "c.yml", Severity::Low),
        ];
        let mut buf = Vec::new();
        write(
            &mut buf,
            &findings,
            &[("api".into(), 2), ("web".into(), 1)],
            Severity::High,
        )
        .unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert!(text.contains("api"));
        assert!(text.contains("FAIL"));
        assert!(text.contains("PASS"));
        assert!(text.contains("2 repos · 1 critical · 1 high · 0 med · 1 low"));
    }
}
