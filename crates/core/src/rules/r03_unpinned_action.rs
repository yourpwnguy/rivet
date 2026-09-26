//! R03 — Unpinned or mutable action references. **HIGH** / **MEDIUM**.
//!
//! `@v1` tags and `@master` branch HEADs can be force-pushed by whoever
//! controls the upstream repo, silently shipping malicious code to every
//! consumer. SHA pinning is the only safe pattern. Local (`./…`) actions
//! are first-party and pass; reusable workflows are R08's job.

use crate::finding::{Finding, RuleId};
use crate::model::Step;
use crate::refs::{self, RefKind};
use crate::rules::RuleContext;
use crate::severity::Severity;

pub struct UnpinnedAction;

impl crate::rules::Rule for UnpinnedAction {
    fn id(&self) -> RuleId {
        RuleId::UnpinnedAction
    }

    fn evaluate<'a>(&self, ctx: &RuleContext<'a>) -> Vec<Finding> {
        let mut findings = Vec::new();
        for job in &ctx.workflow.jobs {
            for step in &job.steps {
                let Step::Uses { target, .. } = step else {
                    continue;
                };
                if refs::is_reusable(target) {
                    continue; // R08 covers reusable workflows
                }
                let (severity, why) = match refs::classify(target) {
                    RefKind::BranchHead => (Severity::High, "branch HEAD, can move at any time"),
                    RefKind::MutableTag | RefKind::Unknown => {
                        (Severity::Medium, "mutable tag, can be force-pushed")
                    }
                    RefKind::Sha | RefKind::Local => continue,
                };
                let (target_name, _) = target.split_once('@').unwrap_or((target, ""));
                findings.push(Finding {
                    rule: RuleId::UnpinnedAction,
                    severity,
                    file: ctx.path.to_path_buf(),
                    line: ctx.find_line(target),
                    job: Some(job.id.clone()),
                    message: format!("`{target}` is pinned to a {why}"),
                    explanation: concat!(
                        "A mutable ref means the code that runs in CI is ",
                        "whatever the upstream repo serves today — including ",
                        "after a compromise or hostile force-push."
                    )
                    .to_owned(),
                    fix: format!("Pin to a full commit SHA: `uses: {target_name}@<full-sha>`"),
                });
            }
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::ParsedWorkflow;
    use crate::parse::parse_workflow;
    use crate::rules::Rule;
    use std::path::PathBuf;

    fn evaluate(raw: &str) -> Vec<Finding> {
        let model = parse_workflow(raw).unwrap();
        let parsed = ParsedWorkflow::new(PathBuf::from("w.yml"), raw.to_owned(), model);
        let config = crate::config::Config::default();
        UnpinnedAction.evaluate(&RuleContext {
            workflow: &parsed.model,
            path: &parsed.path,
            config: &config,
            raw: &parsed.raw,
        })
    }

    const SHA: &str = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";

    #[test]
    fn flags_branch_head_and_mutable_tag() {
        let f = evaluate(&format!(
            "on: push\njobs:\n  b:\n    steps:\n      - uses: actions/checkout@master\n      - uses: actions/checkout@v3\n      - uses: actions/checkout@{SHA}\n"
        ));
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[1].severity, Severity::Medium);
    }

    #[test]
    fn passes_sha_pinned_and_local() {
        let f = evaluate(&format!(
            "on: push\njobs:\n  b:\n    steps:\n      - uses: actions/checkout@{SHA}\n      - uses: ./.github/actions/x\n"
        ));
        assert!(f.is_empty());
    }
}
