//! `# rivet:ignore <rule-id>` suppression.
//!
//! rivet errs toward flagging, so it needs an escape hatch for accepted
//! risk. A comment on the finding's line — or the line directly above it,
//! for block comments — suppresses that one rule's finding at that
//! location. Syntax: `# rivet:ignore unpinned-action`.

use crate::finding::{Finding, RuleId};
use crate::input::ParsedWorkflow;

/// Drop findings suppressed by an inline `# rivet:ignore <rule-id>`.
pub fn apply(parsed: &ParsedWorkflow, findings: Vec<Finding>) -> Vec<Finding> {
    findings
        .into_iter()
        .filter(|f| !is_ignored(parsed, f))
        .collect()
}

fn is_ignored(parsed: &ParsedWorkflow, finding: &Finding) -> bool {
    let Some(line) = finding.line else {
        return false;
    };
    // Check the finding's own line and the line above it. Iterating lines
    // directly avoids collecting the whole file into a Vec per finding.
    // `line` is 1-based; convert to 0-based indices for this and the line above.
    let own_idx = line.saturating_sub(1);
    let above_idx = own_idx.saturating_sub(1);
    parsed
        .raw
        .lines()
        .enumerate()
        .filter(|(idx, _)| *idx == own_idx || *idx == above_idx)
        .any(|(_, text)| ignore_comment_covers(text, finding.rule))
}

/// True if a YAML comment line suppresses `rule`.
///
/// Matches the exact two-token sequence `rivet:ignore <rule-id>` so that
/// a comment merely mentioning a rule ID cannot accidentally suppress it.
fn ignore_comment_covers(line: &str, rule: RuleId) -> bool {
    let Some(comment) = line.split_once('#').map(|(_, c)| c) else {
        return false;
    };
    comment
        .split_whitespace()
        .collect::<Vec<_>>()
        .windows(2)
        .any(|w| w[0] == "rivet:ignore" && w[1] == rule.as_str())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::finding::RuleId;
    use crate::model::Workflow;
    use crate::severity::Severity;

    fn finding(rule: RuleId, line: Option<usize>) -> Finding {
        Finding {
            rule,
            severity: Severity::High,
            file: PathBuf::from("w.yml"),
            line,
            job: None,
            message: "m".into(),
            explanation: "e".into(),
            fix: "t".into(),
        }
    }

    fn parsed(raw: &str) -> ParsedWorkflow {
        ParsedWorkflow::new(PathBuf::from("w.yml"), raw.to_owned(), Workflow::default())
    }

    #[test]
    fn suppresses_on_same_line() {
        let p = parsed("run: echo x # rivet:ignore secret-exfiltration\n");
        let f = finding(RuleId::SecretExfiltration, Some(1));
        assert!(apply(&p, vec![f]).is_empty());
    }

    #[test]
    fn suppresses_on_line_above() {
        let p = parsed("# rivet:ignore secret-exfiltration\nrun: echo x\n");
        let f = finding(RuleId::SecretExfiltration, Some(2));
        assert!(apply(&p, vec![f]).is_empty());
    }

    #[test]
    fn does_not_suppress_other_rules() {
        let p = parsed("run: echo x # rivet:ignore unpinned-action\n");
        let f = finding(RuleId::SecretExfiltration, Some(1));
        assert_eq!(apply(&p, vec![f]).len(), 1);
    }

    #[test]
    fn comment_mentioning_rule_is_not_suppression() {
        let p = parsed("run: echo x # see secret-exfiltration docs\n");
        let f = finding(RuleId::SecretExfiltration, Some(1));
        assert_eq!(apply(&p, vec![f]).len(), 1);
    }

    /// Workflow-level findings (R04's "no permissions block") have no line
    /// anchor when the file has no `permissions:` line to point at. Without
    /// an anchor there is nothing to attach a comment to, so the finding
    /// must always survive.
    #[test]
    fn unanchored_finding_is_never_suppressed() {
        let p = parsed("on: push\njobs: {}\n# rivet:ignore overly-broad-permissions\n");
        let f = finding(RuleId::OverlyBroadPermissions, None);
        assert_eq!(apply(&p, vec![f]).len(), 1);
    }

    /// A finding on line 1 has no line above it. The rewrite indexes the
    /// "line above" position with `saturating_sub`, so this must not
    /// underflow and must still match a same-line comment.
    #[test]
    fn first_line_finding_does_not_underflow() {
        let p = parsed("run: echo x # rivet:ignore secret-exfiltration\n");
        let f = finding(RuleId::SecretExfiltration, Some(1));
        assert!(apply(&p, vec![f]).is_empty());
    }

    /// A line number past end-of-file must not panic; there is simply no
    /// comment to find.
    #[test]
    fn out_of_range_line_is_safe() {
        let p = parsed("on: push\n");
        let f = finding(RuleId::SecretExfiltration, Some(9999));
        assert_eq!(apply(&p, vec![f]).len(), 1);
    }
}
