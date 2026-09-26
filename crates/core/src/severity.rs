//! Severity classification for findings.
//!
//! `Severity` is a fieldless enum whose **declaration order defines rank**:
//! `Critical` (declared first) is the most severe, `Info` the least. The
//! derived `Ord` turns the `--fail-on` policy into a single zero-cost
//! comparison — `finding.severity <= threshold` — with no integer mapping
//! table to keep in sync.

use std::fmt;

/// How dangerous a finding is.
///
/// Declaration order is severity rank: earlier = more severe. Do not
/// reorder variants without updating the policy semantics; a unit test
/// pins the ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Direct path to secret theft or attacker-controlled code execution.
    Critical,
    /// Serious misconfiguration that is a known, actively-exploited vector.
    High,
    /// Meaningful risk that is often context-dependent.
    Medium,
    /// Hygiene issue with low direct impact.
    Low,
    /// Informational hardening note.
    Info,
}

impl Severity {
    /// Stable lowercase name used in CLI output, JSON, and `--fail-on`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declaration_order_is_severity_rank() {
        // The `--fail-on` comparison (`<=`) depends on this ordering.
        assert!(Severity::Critical < Severity::High);
        assert!(Severity::High < Severity::Medium);
        assert!(Severity::Medium < Severity::Low);
        assert!(Severity::Low < Severity::Info);
    }

    #[test]
    fn as_str_is_stable() {
        assert_eq!(Severity::Critical.as_str(), "critical");
        assert_eq!(Severity::High.as_str(), "high");
        assert_eq!(Severity::Medium.as_str(), "medium");
        assert_eq!(Severity::Low.as_str(), "low");
        assert_eq!(Severity::Info.as_str(), "info");
    }
}
