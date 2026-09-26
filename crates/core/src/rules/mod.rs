//! The rule framework: the `Rule` trait, its context, and the registry.
//!
//! A rule is a pure function from a workflow to zero or more findings.
//! Adding a rule means adding one file in this directory and one line in
//! [`default_rules`] — the engine never changes.

use std::path::Path;

use crate::config::Config;
use crate::finding::{Finding, RuleId};
use crate::model::Workflow;

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
