//! The rule framework: the `Rule` trait, its context, and the registry.
//!
//! A rule is a pure function from a workflow to zero or more findings.
//! Adding a rule means adding one file in this directory and one line in
//! [`default_rules`] — the engine never changes.

use std::path::Path;

use crate::config::Config;
use crate::finding::{Finding, RuleId};
use crate::model::Workflow;
use crate::severity::Severity;

mod r01_script_injection;
mod r02_pull_request_target_checkout;
mod r03_unpinned_action;
mod r04_permissions;
mod r05_secret_exfiltration;
mod r06_self_hosted_runner;
mod r07_fork_secrets;
mod r08_reusable_workflow_pin;
mod r09_debug_logging;
mod r10_artifact_poisoning;

pub use r01_script_injection::ScriptInjection;
pub use r02_pull_request_target_checkout::PullRequestTargetCheckout;
pub use r03_unpinned_action::UnpinnedAction;
pub use r04_permissions::OverlyBroadPermissions;
pub use r05_secret_exfiltration::SecretExfiltration;
pub use r06_self_hosted_runner::SelfHostedRunner;
pub use r07_fork_secrets::ForkSecretsAccess;
pub use r08_reusable_workflow_pin::ReusableWorkflowPin;
pub use r09_debug_logging::DebugLogging;
pub use r10_artifact_poisoning::ArtifactPoisoning;

/// A single security rule.
pub trait Rule: Send + Sync {
    /// Stable identifier used in output and `# rivet:ignore` comments.
    fn id(&self) -> RuleId;

    /// Evaluate the rule against one workflow. Pure: no I/O, no mutation.
    fn evaluate<'a>(&self, ctx: &RuleContext<'a>) -> Vec<Finding>;
}

/// Everything a rule may look at, borrowed for the evaluation.
pub struct RuleContext<'a> {
    /// The parsed workflow model.
    pub workflow: &'a Workflow,
    /// The file's display path.
    pub path: &'a Path,
    /// Resolved configuration (visibility, permission ceilings).
    pub config: &'a Config,
    /// Raw file text — for line lookups.
    pub raw: &'a str,
}

impl RuleContext<'_> {
    /// 1-based line of the first line containing `needle`.
    pub fn find_line(&self, needle: &str) -> Option<usize> {
        crate::locate::find_line(self.raw, needle)
    }
}

/// Static catalog of all rules: `(rule id, base severity, description)`.
///
/// Consumed by `--list-rules` to print what rivet checks without running a
/// scan. The severity listed is the base severity; R02 downgrades to INFO at
/// evaluation time when the workflow is metadata-only. Kept as a static table
/// next to [`default_rules`] rather than a trait method so the listing and the
/// registry live in one place and cannot drift apart.
pub fn rule_catalog() -> &'static [(RuleId, Severity, &'static str)] {
    &[
        (
            RuleId::ScriptInjection,
            Severity::Critical,
            "run: steps interpolating untrusted event context into shell",
        ),
        (
            RuleId::PullRequestTargetCheckout,
            Severity::High,
            "pull_request_target workflow checking out PR head code; downgrades to INFO when metadata-only",
        ),
        (
            RuleId::UnpinnedAction,
            Severity::High,
            "uses: pinned to a branch HEAD or mutable tag instead of a full commit SHA",
        ),
        (
            RuleId::OverlyBroadPermissions,
            Severity::High,
            concat!(
                "missing permissions block, write-all, id-token: write without ",
                "OIDC, or grants beyond the rivet.yaml ceiling"
            ),
        ),
        (
            RuleId::SecretExfiltration,
            Severity::High,
            "secrets.* referenced directly inside a run: step, especially next to curl/wget/nc",
        ),
        (
            RuleId::SelfHostedRunner,
            Severity::Medium,
            "runs-on: self-hosted in a repository declared public",
        ),
        (
            RuleId::ForkSecretsAccess,
            Severity::Medium,
            "secrets.* referenced in pull_request workflows",
        ),
        (
            RuleId::ReusableWorkflowPin,
            Severity::Low,
            "reusable workflow called with a mutable ref",
        ),
        (
            RuleId::DebugLogging,
            Severity::Info,
            "ACTIONS_STEP_DEBUG enabled in pull_request_target with no add-mask",
        ),
        (
            RuleId::ArtifactPoisoning,
            Severity::Medium,
            "workflow_run downloading artifacts without SHA validation",
        ),
    ]
}

/// The full v1 rule set, in ID order. The only edit point for new rules.
pub fn default_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(ScriptInjection),
        Box::new(PullRequestTargetCheckout),
        Box::new(UnpinnedAction),
        Box::new(OverlyBroadPermissions),
        Box::new(SecretExfiltration),
        Box::new(SelfHostedRunner),
        Box::new(ForkSecretsAccess),
        Box::new(ReusableWorkflowPin),
        Box::new(DebugLogging),
        Box::new(ArtifactPoisoning),
    ]
}
