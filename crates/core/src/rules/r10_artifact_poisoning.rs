//! R10 — Artifact poisoning via `workflow_run`. **MEDIUM.**
//!
//! A `workflow_run` workflow runs with the base repo's privileges after
//! another workflow completes. If it downloads an artifact uploaded by the
//! triggering workflow without validating its SHA, a malicious workflow in
//! a fork can upload a poisoned artifact that the privileged downstream
//! workflow then executes or deploys.

use crate::finding::{Finding, RuleId};
use crate::model::Step;
use crate::rules::RuleContext;
use crate::severity::Severity;

pub struct ArtifactPoisoning;

impl crate::rules::Rule for ArtifactPoisoning {
    fn id(&self) -> RuleId {
        RuleId::ArtifactPoisoning
    }

    fn evaluate<'a>(&self, ctx: &RuleContext<'a>) -> Vec<Finding> {
        if !ctx.workflow.triggers.workflow_run() {
            return Vec::new();
        }
        let mut findings = Vec::new();
        for job in &ctx.workflow.jobs {
            for step in &job.steps {
                let Step::Uses { target, .. } = step else {
                    continue;
                };
                if !target.starts_with("actions/download-artifact") {
                    continue;
                }
                findings.push(Finding {
                    rule: RuleId::ArtifactPoisoning,
                    severity: Severity::Medium,
                    file: ctx.path.to_path_buf(),
                    line: ctx.find_line(target),
                    job: Some(job.id.clone()),
                    message: "workflow_run workflow downloads an artifact without SHA validation".to_owned(),
                    explanation: concat!(
                        "Artifacts come from the triggering workflow, which a ",
                        "fork can influence. Without a SHA pin on the artifact, ",
                        "a poisoned upload is consumed by this privileged workflow."
                    )
                    .to_owned(),
                    fix: "Pin the artifact by SHA (`with: { sha: … }`) or verify the uploader is a trusted workflow".to_owned(),
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
        ArtifactPoisoning.evaluate(&RuleContext {
            workflow: &parsed.model,
            path: &parsed.path,
            config: &config,
            raw: &parsed.raw,
        })
    }

    #[test]
    fn flags_download_artifact_in_workflow_run() {
        let f = evaluate(
            "on:\n  workflow_run:\n    workflows: [CI]\n    types: [completed]\njobs:\n  deploy:\n    steps:\n      - uses: actions/download-artifact@v3\n        with:\n          name: build\n",
        );
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Medium);
    }

    #[test]
    fn ignores_other_triggers() {
        let f = evaluate(
            "on: push\njobs:\n  b:\n    steps:\n      - uses: actions/download-artifact@v3\n        with:\n          name: build\n",
        );
        assert!(f.is_empty());
    }
}
