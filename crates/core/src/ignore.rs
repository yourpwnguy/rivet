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
    let lines: Vec<&str> = parsed.raw.lines().collect();
    // Check the finding's own line and the line above it.
    for l in [line.saturating_sub(1), line] {
        if let Some(text) = lines.get(l.wrapping_sub(1))
            && ignore_comment_covers(text, finding.rule)
        {
            return true;
        }
    }
    false
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

    fn finding(rule: RuleId, line: usize) -> Finding {
        Finding {
            rule,
            severity: Severity::High,
            file: PathBuf::from("w.yml"),
            line: Some(line),
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
        assert!(apply(&p, vec![finding(RuleId::SecretExfiltration, 1)]).is_empty());
    }

    #[test]
    fn suppresses_on_line_above() {
        let p = parsed("# rivet:ignore secret-exfiltration\nrun: echo x\n");
        assert!(apply(&p, vec![finding(RuleId::SecretExfiltration, 2)]).is_empty());
    }

    #[test]
    fn does_not_suppress_other_rules() {
        let p = parsed("run: echo x # rivet:ignore unpinned-action\n");
        assert_eq!(
            apply(&p, vec![finding(RuleId::SecretExfiltration, 1)]).len(),
            1
        );
    }

    #[test]
    fn comment_mentioning_rule_is_not_suppression() {
        let p = parsed("run: echo x # see secret-exfiltration docs\n");
        assert_eq!(
            apply(&p, vec![finding(RuleId::SecretExfiltration, 1)]).len(),
            1
        );
    }
}
