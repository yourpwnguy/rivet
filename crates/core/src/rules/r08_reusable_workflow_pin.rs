//! R08 — Unpinned third-party action in reusable workflow. **LOW.**
//!
//! Same supply-chain concern as R03, but for workflow-level reuse:
//! `uses: org/repo/.github/workflows/x.yml@ref` runs whatever the upstream
//! repo serves at `ref`. SHA pinning applies here too.

use crate::finding::{Finding, RuleId};
use crate::model::Step;
use crate::refs::{self, RefKind};
use crate::rules::RuleContext;
use crate::severity::Severity;

pub struct ReusableWorkflowPin;

impl crate::rules::Rule for ReusableWorkflowPin {
    fn id(&self) -> RuleId {
        RuleId::ReusableWorkflowPin
    }

    fn evaluate<'a>(&self, ctx: &RuleContext<'a>) -> Vec<Finding> {
        let mut findings = Vec::new();
        for job in &ctx.workflow.jobs {
            for step in &job.steps {
                let Step::Uses { target, .. } = step else {
                    continue;
                };
                if !refs::is_reusable(target) || refs::classify(target) == RefKind::Sha {
                    continue;
                }
                let (target_name, _) = target.split_once('@').unwrap_or((target, ""));
                findings.push(Finding {
                    rule: RuleId::ReusableWorkflowPin,
                    severity: Severity::Low,
                    file: ctx.path.to_path_buf(),
                    line: ctx.find_line(target),
                    job: Some(job.id.clone()),
                    message: format!("reusable workflow `{target}` is not SHA-pinned"),
                    explanation: concat!(
                        "A mutable ref on a reusable workflow means the ",
                        "downstream workflow runs whatever the upstream repo ",
                        "serves today — including after a compromise."
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
        ReusableWorkflowPin.evaluate(&RuleContext {
            workflow: &parsed.model,
            path: &parsed.path,
            config: &config,
            raw: &parsed.raw,
        })
    }

    const SHA: &str = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";

    #[test]
    fn flags_unpinned_reusable_workflow() {
        let f = evaluate(
            "on: push\njobs:\n  b:\n    steps:\n      - uses: org/repo/.github/workflows/x.yml@main\n",
        );
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Low);
    }

    #[test]
    fn passes_sha_pinned_reusable_workflow() {
        let f = evaluate(&format!(
            "on: push\njobs:\n  b:\n    steps:\n      - uses: org/repo/.github/workflows/x.yml@{SHA}\n"
        ));
        assert!(f.is_empty());
    }
}
