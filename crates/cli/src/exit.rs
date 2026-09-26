//! Exit-code policy — rivet's machine-readable contract.
//!
//! * `0` — pass: no finding at or above the `--fail-on` threshold.
//! * `2` — policy breach: at least one finding at or above the threshold.
//! * `1` — system error: the audit could not complete (I/O failure,
//!   unparseable workflow, malformed config).
//!
//! Precedence: breach (2) wins over error (1) — if critical issues were
//! found, that is the most important signal even if some file also failed
//! to parse.

use rivet_core::finding::Finding;
use rivet_core::severity::Severity;

/// Decide the process exit code.
///
/// `had_errors` covers parse failures and I/O errors encountered during the
/// scan — "unknown ≠ safe", so they surface as exit 1.
pub fn decide(findings: &[Finding], fail_on: Severity, had_errors: bool) -> i32 {
    let breach = findings.iter().any(|f| f.severity <= fail_on);
    if breach {
        2
    } else if had_errors {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rivet_core::finding::RuleId;
    use rivet_core::severity::Severity;
    use std::path::PathBuf;

    fn finding(severity: Severity) -> Finding {
        Finding {
            rule: RuleId::UnpinnedAction,
            severity,
            file: PathBuf::from("w.yml"),
            line: Some(1),
            job: None,
            message: "m".into(),
            explanation: "e".into(),
            fix: "t".into(),
        }
    }

    #[test]
    fn pass_when_nothing_at_threshold() {
        assert_eq!(decide(&[], Severity::High, false), 0);
        assert_eq!(
            decide(&[finding(Severity::Medium)], Severity::High, false),
            0
        );
    }

    #[test]
    fn breach_when_finding_at_or_above_threshold() {
        assert_eq!(decide(&[finding(Severity::High)], Severity::High, false), 2);
        assert_eq!(
            decide(&[finding(Severity::Critical)], Severity::High, false),
            2
        );
    }

    #[test]
    fn error_when_audit_incomplete() {
        assert_eq!(decide(&[], Severity::High, true), 1);
    }

    #[test]
    fn breach_wins_over_error() {
        assert_eq!(
            decide(&[finding(Severity::Critical)], Severity::High, true),
            2
        );
    }
}
