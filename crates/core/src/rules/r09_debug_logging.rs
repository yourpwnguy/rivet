//! R09 — Debug logging enabled. **INFO.**
//!
//! `ACTIONS_STEP_DEBUG: true` makes the runner print masked secrets in
//! full. In a `pull_request_target` context — where the workflow legitimately
//! has secrets — that quietly defeats masking. The rule only fires when no
//! `::add-mask::` is present anywhere in the workflow's scripts, since an
//! explicit masking step shows the operator knows what they are doing.

use crate::finding::{Finding, RuleId};
use crate::model::Step;
use crate::rules::RuleContext;
use crate::severity::Severity;

pub struct DebugLogging;

impl crate::rules::Rule for DebugLogging {
    fn id(&self) -> RuleId {
        RuleId::DebugLogging
    }

    fn evaluate<'a>(&self, ctx: &RuleContext<'a>) -> Vec<Finding> {
        if !ctx.workflow.triggers.pull_request_target() {
            return Vec::new();
        }
        if !debug_set(ctx) {
            return Vec::new();
        }
        let has_mask = ctx.workflow.jobs.iter().any(|job| {
            job.steps.iter().any(|step| {
                let Step::Run { script, .. } = step else {
                    return false;
                };
                script.contains("::add-mask::")
            })
        });
        if has_mask {
            return Vec::new();
        }
        vec![Finding {
            rule: RuleId::DebugLogging,
            severity: Severity::Info,
            file: ctx.path.to_path_buf(),
            line: ctx.find_line("ACTIONS_STEP_DEBUG"),
            job: None,
            message: "ACTIONS_STEP_DEBUG is enabled in a pull_request_target workflow".to_owned(),
            explanation: concat!(
                "Step debug logging can print masked secrets in full. In a ",
                "pull_request_target context — where secrets are legitimately ",
                "present — that silently defeats masking."
            )
            .to_owned(),
            fix: "Remove ACTIONS_STEP_DEBUG, or scope it to non-privileged triggers".to_owned(),
        }]
    }
}

/// True if `ACTIONS_STEP_DEBUG` is set to a truthy value in the workflow or
/// any job environment.
fn debug_set(ctx: &RuleContext<'_>) -> bool {
    let workflow_set = ctx
        .workflow
        .env
        .iter()
        .any(|(k, v)| k == "ACTIONS_STEP_DEBUG" && is_truthy(v));
    workflow_set
        || ctx.workflow.jobs.iter().any(|job| {
            job.env
                .iter()
                .any(|(k, v)| k == "ACTIONS_STEP_DEBUG" && is_truthy(v))
        })
}

/// Truthy values GitHub accepts for `ACTIONS_STEP_DEBUG`.
fn is_truthy(v: &str) -> bool {
    matches!(v, "true" | "1" | "yes")
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
        DebugLogging.evaluate(&RuleContext {
            workflow: &parsed.model,
            path: &parsed.path,
            config: &config,
            raw: &parsed.raw,
        })
    }

    #[test]
    fn flags_debug_in_pr_target() {
        let f = evaluate(
            "on: pull_request_target\nenv:\n  ACTIONS_STEP_DEBUG: true\njobs:\n  b:\n    steps:\n      - run: echo hi\n",
        );
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Info);
    }

    #[test]
    fn passes_with_add_mask() {
        let f = evaluate(
            "on: pull_request_target\nenv:\n  ACTIONS_STEP_DEBUG: true\njobs:\n  b:\n    steps:\n      - run: echo \"::add-mask::${{ secrets.X }}\"\n",
        );
        assert!(f.is_empty());
    }

    #[test]
    fn silent_without_debug() {
        let f =
            evaluate("on: pull_request_target\njobs:\n  b:\n    steps:\n      - run: echo hi\n");
        assert!(f.is_empty());
    }
}
