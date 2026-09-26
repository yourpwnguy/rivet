//! The `Finding` — rivet's single output currency.
//!
//! Every rule produces `Finding`s, and every finding is fully
//! self-contained: it carries everything a renderer or JSON consumer needs
//! (what was found, where, why it matters, and how to fix it), so
//! presentation code never re-derives domain knowledge.

use std::fmt;
use std::path::PathBuf;

use crate::severity::Severity;

/// Stable, kebab-case rule identifiers.
///
/// These strings are part of rivet's public contract: they appear in JSON
/// output and in `# rivet:ignore <id>` suppression comments. Renaming a
/// variant is a breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuleId {
    /// R01 — untrusted event context interpolated into a `run:` script.
    ScriptInjection,
    /// R02 — `pull_request_target` workflow that checks out PR head code.
    PullRequestTargetCheckout,
    /// R03 — action referenced by a mutable ref instead of a commit SHA.
    UnpinnedAction,
    /// R04 — overly broad `GITHUB_TOKEN` permissions.
    OverlyBroadPermissions,
    /// R05 — secret referenced directly inside a `run:` script.
    SecretExfiltration,
    /// R06 — self-hosted runner used in a public repository.
    SelfHostedRunner,
    /// R07 — secrets exposed to fork-triggered (`pull_request`) workflows.
    ForkSecretsAccess,
    /// R08 — reusable workflow called with a mutable ref.
    ReusableWorkflowPin,
    /// R09 — step debug logging enabled in a `pull_request_target` context.
    DebugLogging,
    /// R10 — artifact consumed from `workflow_run` without SHA validation.
    ArtifactPoisoning,
}

impl RuleId {
    /// Stable kebab-case identifier. Never rename without a major version.
    pub const fn as_str(self) -> &'static str {
        match self {
            RuleId::ScriptInjection => "script-injection",
            RuleId::PullRequestTargetCheckout => "pull-request-target",
            RuleId::UnpinnedAction => "unpinned-action",
            RuleId::OverlyBroadPermissions => "overly-broad-permissions",
            RuleId::SecretExfiltration => "secret-exfiltration",
            RuleId::SelfHostedRunner => "self-hosted-runner",
            RuleId::ForkSecretsAccess => "fork-secrets",
            RuleId::ReusableWorkflowPin => "reusable-workflow-pin",
            RuleId::DebugLogging => "debug-logging",
            RuleId::ArtifactPoisoning => "artifact-poisoning",
        }
    }
}

impl fmt::Display for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One audited issue: what was found, where, why it matters, and the fix.
#[derive(Debug)]
pub struct Finding {
    /// Which rule produced this.
    pub rule: RuleId,
    /// Computed at evaluation time — R02 downgrades HIGH→INFO in context.
    pub severity: Severity,
    /// Display path, relativized to the scan root by the CLI.
    pub file: PathBuf,
    /// 1-based line, when the finding anchors to a specific line.
    pub line: Option<usize>,
    /// Job ID, when the finding is job-scoped.
    pub job: Option<String>,
    /// One-line "what was found".
    pub message: String,
    /// Plain-English "why it matters".
    pub explanation: String,
    /// Concrete remediation. Multi-line suggestions are rendered as a
    /// paste-ready block by `--fix-dry` and as a one-line summary otherwise.
    pub fix: String,
}

/// Sort findings worst-first: severity rank, then file, line, and rule ID.
///
/// Deterministic output is a requirement for stable snapshots and CI
/// diffs, so both the engine (per-file) and the CLI (combined list) sort
/// with this one function.
pub fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.rule.as_str().cmp(b.rule.as_str()))
    });
}
