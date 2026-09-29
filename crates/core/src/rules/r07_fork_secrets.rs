//! R07 — Fork secrets access. **MEDIUM.**
//!
//! `on: pull_request` workflows run from forks with a read-only
//! `GITHUB_TOKEN` and no secrets. Referencing `secrets.*` there means the
//! job will fail at runtime — or worse, leak if the org has a custom setup
//! that does provide secrets to fork runs.

use crate::expressions;
use crate::finding::{Finding, RuleId};
use crate::model::Step;
use crate::rules::RuleContext;
use crate::severity::Severity;

pub struct ForkSecretsAccess;

impl crate::rules::Rule for ForkSecretsAccess {
    fn id(&self) -> RuleId {
        RuleId::ForkSecretsAccess
    }

    fn evaluate<'a>(&self, ctx: &RuleContext<'a>) -> Vec<Finding> {
        if !ctx.workflow.triggers.pull_request() {
            return Vec::new();
        }
        let mut findings = Vec::new();
        for job in &ctx.workflow.jobs {
            for (key, value) in &job.env {
                if expressions::references_secrets(value) {
                    findings.push(secret_finding(
                        ctx,
                        job,
                        ctx.find_line(key),
                        format!(
                            "env var `{key}` references secrets.* in a fork-triggered workflow"
                        ),
                    ));
                }
            }
            for step in &job.steps {
                let Step::Run { script, .. } = step else {
                    continue;
                };
                let exprs = expressions::extract(script);
                let uses_secrets = exprs.iter().any(|e| e.text.contains("secrets."));
                if uses_secrets {
                    findings.push(secret_finding(
                        ctx,
                        job,
                        ctx.find_line(first_nonempty_line(script)),
                        "run step references secrets.* in a fork-triggered workflow".to_owned(),
                    ));
                }
            }
        }
        findings
    }
}

/// Build the shared finding shape for R07.
fn secret_finding(
    ctx: &RuleContext<'_>,
    job: &crate::model::Job,
    line: Option<usize>,
    message: String,
) -> Finding {
    Finding {
        rule: RuleId::ForkSecretsAccess,
        severity: Severity::Medium,
        file: ctx.path.to_path_buf(),
        line,
        job: Some(job.id.clone()),
        message,
        explanation: concat!(
            "Fork PRs get a read-only GITHUB_TOKEN and no secrets. A job that ",
            "references secrets.* will fail at runtime — or, under a custom org ",
            "setup that does provide them, leak them to the fork."
        )
        .to_owned(),
        fix: concat!(
            "Guard secret access behind a non-fork condition, e.g. `if: ",
            "github.event.pull_request.head.repo.full_name == github.repository`"
        )
        .to_owned(),
    }
}

/// First non-empty line of a script, used to anchor the finding's line.
fn first_nonempty_line(script: &str) -> &str {
    script.lines().find(|l| !l.trim().is_empty()).unwrap_or("")
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
        ForkSecretsAccess.evaluate(&RuleContext {
            workflow: &parsed.model,
            path: &parsed.path,
            config: &config,
            raw: &parsed.raw,
        })
    }

    #[test]
    fn flags_secrets_in_fork_workflow() {
        let f = evaluate(
            "on: pull_request\njobs:\n  b:\n    env:\n      K: ${{ secrets.API_KEY }}\n    steps:\n      - run: echo \"$K\"\n",
        );
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Medium);
    }

    #[test]
    fn ignores_non_fork_triggers() {
        let f = evaluate(
            "on: push\njobs:\n  b:\n    env:\n      K: ${{ secrets.API_KEY }}\n    steps:\n      - run: echo \"$K\"\n",
        );
        assert!(f.is_empty());
    }
}
