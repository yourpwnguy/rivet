//! R06 — Self-hosted runners in public repos. **MEDIUM.**
//!
//! A self-hosted runner in a public repo means any fork PR can execute
//! code on infrastructure the org controls, with whatever credentials the
//! runner holds. Visibility cannot be determined from local files, so the
//! rule fires only when the operator declares the repo public via
//! `--repo-visibility` or `rivet.yaml`.

use crate::config::Visibility;
use crate::finding::{Finding, RuleId};
use crate::rules::RuleContext;
use crate::severity::Severity;

pub struct SelfHostedRunner;

impl crate::rules::Rule for SelfHostedRunner {
    fn id(&self) -> RuleId {
        RuleId::SelfHostedRunner
    }

    fn evaluate<'a>(&self, ctx: &RuleContext<'a>) -> Vec<Finding> {
        if ctx.config.repo_visibility != Visibility::Public {
            return Vec::new();
        }
        let mut findings = Vec::new();
        for job in &ctx.workflow.jobs {
            if !job.runs_on.is_self_hosted() {
                continue;
            }
            findings.push(Finding {
                rule: RuleId::SelfHostedRunner,
                severity: Severity::Medium,
                file: ctx.path.to_path_buf(),
                line: ctx.find_line("runs-on"),
                job: Some(job.id.clone()),
                message: format!("job `{}` runs on a self-hosted runner", job.id),
                explanation: concat!(
                    "In a public repo, any fork PR can execute code on a ",
                    "self-hosted runner — infrastructure the org controls, ",
                    "holding whatever credentials the runner environment has."
                )
                .to_owned(),
                fix: "Use GitHub-hosted runners in public repos, or make the repo private"
                    .to_owned(),
            });
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Visibility};
    use crate::input::ParsedWorkflow;
    use crate::parse::parse_workflow;
    use crate::rules::Rule;
    use std::path::PathBuf;

    fn evaluate(raw: &str, visibility: Visibility) -> Vec<Finding> {
        let model = parse_workflow(raw).unwrap();
        let parsed = ParsedWorkflow::new(PathBuf::from("w.yml"), raw.to_owned(), model);
        let config = Config {
            repo_visibility: visibility,
            ..Config::default()
        };
        SelfHostedRunner.evaluate(&RuleContext {
            workflow: &parsed.model,
            path: &parsed.path,
            config: &config,
            raw: &parsed.raw,
        })
    }

    #[test]
    fn flags_self_hosted_in_public_repo() {
        let f = evaluate(
            "on: pull_request\njobs:\n  b:\n    runs-on: self-hosted\n    steps:\n      - run: echo hi\n",
            Visibility::Public,
        );
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Medium);
    }

    #[test]
    fn silent_when_visibility_unknown() {
        let f = evaluate(
            "on: pull_request\njobs:\n  b:\n    runs-on: self-hosted\n    steps:\n      - run: echo hi\n",
            Visibility::Unknown,
        );
        assert!(f.is_empty());
    }

    #[test]
    fn passes_github_hosted() {
        let f = evaluate(
            "on: pull_request\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n",
            Visibility::Public,
        );
        assert!(f.is_empty());
    }
}
