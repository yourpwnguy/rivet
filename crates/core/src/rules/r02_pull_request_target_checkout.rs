//! R02 — `pull_request_target` with checkout. **HIGH** (INFO downgrade).
//!
//! `pull_request_target` runs in the base repo's context with secrets.
//! Checking out untrusted PR head code and then running it (tests, build,
//! lint) gives the PR author arbitrary code execution against the base
//! repo. Safe usage reads only metadata (posting comments, labels) —
//! which rivet reports as INFO so the workflow is visibly acknowledged.

use crate::finding::{Finding, RuleId};
use crate::model::Step;
use crate::rules::RuleContext;
use crate::severity::Severity;

pub struct PullRequestTargetCheckout;

impl crate::rules::Rule for PullRequestTargetCheckout {
    fn id(&self) -> RuleId {
        RuleId::PullRequestTargetCheckout
    }

    fn evaluate<'a>(&self, ctx: &RuleContext<'a>) -> Vec<Finding> {
        if !ctx.workflow.triggers.pull_request_target() {
            return Vec::new();
        }
        let mut findings = Vec::new();
        let mut checked_out = false;
        for job in &ctx.workflow.jobs {
            for step in &job.steps {
                let Step::Uses { target, with } = step else {
                    continue;
                };
                if !target.starts_with("actions/checkout") {
                    continue;
                }
                // Checking out the PR head is the dangerous case; omitting
                // `ref` checks out the (safe) base repo by default.
                let refs_head = with
                    .iter()
                    .any(|(k, v)| k == "ref" && (v.contains("head.sha") || v.contains("head.ref")));
                if !refs_head {
                    continue;
                }
                checked_out = true;
                findings.push(Finding {
                    rule: RuleId::PullRequestTargetCheckout,
                    severity: Severity::High,
                    file: ctx.path.to_path_buf(),
                    line: ctx.find_line(target),
                    job: Some(job.id.clone()),
                    message: "pull_request_target workflow checks out PR head".to_owned(),
                    explanation: concat!(
                        "pull_request_target runs with the base repo's secrets. ",
                        "Checking out the PR head and running it gives the fork ",
                        "author arbitrary code execution in that privileged context."
                    )
                    .to_owned(),
                    fix: "Remove the checkout step, or switch the trigger to `pull_request`"
                        .to_owned(),
                });
            }
        }
        if !checked_out {
            findings.push(Finding {
                rule: RuleId::PullRequestTargetCheckout,
                severity: Severity::Info,
                file: ctx.path.to_path_buf(),
                line: ctx.find_line("pull_request_target"),
                job: None,
                message: "pull_request_target workflow reads metadata only".to_owned(),
                explanation: concat!(
                    "No PR-head checkout was found. Metadata-only workflows ",
                    "(comments, labels) are the safe way to use this trigger; ",
                    "re-check after adding steps that execute code."
                )
                .to_owned(),
                fix: "No action needed; keep it that way".to_owned(),
            });
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
        PullRequestTargetCheckout.evaluate(&RuleContext {
            workflow: &parsed.model,
            path: &parsed.path,
            config: &config,
            raw: &parsed.raw,
        })
    }

    #[test]
    fn flags_head_checkout() {
        let f = evaluate(
            "on: pull_request_target\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v3\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n",
        );
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
    }

    #[test]
    fn downgrades_metadata_only_to_info() {
        let f = evaluate(
            "on: pull_request_target\njobs:\n  label:\n    steps:\n      - run: echo \"${{ github.event.pull_request.number }}\"\n",
        );
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Info);
    }

    #[test]
    fn ignores_other_triggers() {
        let f = evaluate(
            "on: pull_request\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v3\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n",
        );
        assert!(f.is_empty());
    }
}
