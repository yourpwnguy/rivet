//! R04 — Overly broad permissions. **HIGH.**
//!
//! An absent `permissions:` block defaults to whatever the org grants —
//! often write-all. `write-all` is explicit. `id-token: write` without an
//! OIDC use case hands out cloud credentials. And `rivet.yaml` can declare
//! the maximum grants the repo needs; anything beyond is flagged.
//!
//! Workflow- and job-level blocks are both audited: a job can re-grant
//! what the workflow restricted. Jobs without their own block inherit the
//! workflow's and are not double-reported.

use crate::finding::{Finding, RuleId};
use crate::model::{Access, Permission, Step};
use crate::rules::RuleContext;
use crate::severity::Severity;

pub struct OverlyBroadPermissions;

impl crate::rules::Rule for OverlyBroadPermissions {
    fn id(&self) -> RuleId {
        RuleId::OverlyBroadPermissions
    }

    fn evaluate<'a>(&self, ctx: &RuleContext<'a>) -> Vec<Finding> {
        let mut findings = Vec::new();
        check_scope(
            ctx,
            "workflow",
            "permissions",
            ctx.workflow.permissions.as_ref(),
            &mut findings,
        );
        for job in &ctx.workflow.jobs {
            // A job without its own block inherits the workflow's block —
            // already covered by the workflow-level check above.
            if let Some(perms) = &job.permissions {
                check_scope(ctx, &job.id, &job.id, Some(perms), &mut findings);
            }
        }
        findings
    }
}

/// Audit one permissions scope (workflow-level or job-level).
///
/// `scope` labels the finding, `needle` locates it in the raw file, and
/// `perms` is the scope's block — `None` only happens at workflow level,
/// since jobs are only checked when they declare their own block.
fn check_scope(
    ctx: &RuleContext<'_>,
    scope: &str,
    needle: &str,
    perms: Option<&crate::model::Permissions>,
    findings: &mut Vec<Finding>,
) {
    let Some(perms) = perms else {
        findings.push(Finding {
            rule: RuleId::OverlyBroadPermissions,
            severity: Severity::High,
            file: ctx.path.to_path_buf(),
            line: ctx.find_line(needle),
            job: None,
            message: format!("{scope} has no permissions block"),
            explanation: concat!(
                "Without an explicit block, the token's scopes come ",
                "from the org default — write-all in many org settings. ",
                "Least privilege starts with declaring what you need."
            )
            .to_owned(),
            fix: "Add a `permissions:` block with only the scopes each job needs, e.g. `permissions: contents: read`".to_owned(),
        });
        return;
    };
    if perms.write_all {
        findings.push(Finding {
            rule: RuleId::OverlyBroadPermissions,
            severity: Severity::High,
            file: ctx.path.to_path_buf(),
            line: ctx.find_line(needle),
            job: None,
            message: format!("{scope} sets permissions: write-all"),
            explanation: "write-all grants every scope to every job; one compromised step becomes a repo-wide breach.".to_owned(),
            fix: "Replace `write-all` with the minimal set of scopes each job needs".to_owned(),
        });
        return;
    }
    for (perm, access) in &perms.grants {
        if *perm == Permission::IdToken && *access == Access::Write && !has_oidc_input(ctx.workflow)
        {
            findings.push(Finding {
                rule: RuleId::OverlyBroadPermissions,
                severity: Severity::High,
                file: ctx.path.to_path_buf(),
                line: ctx.find_line(needle),
                job: None,
                message: format!("{scope} grants id-token: write without an OIDC use case"),
                explanation: concat!(
                    "id-token: write mints OIDC tokens that can assume ",
                    "cloud roles. With no role-to-assume input anywhere, ",
                    "the capability is unused — or uncontrolled."
                )
                .to_owned(),
                fix: "Drop `id-token: write` unless the job assumes a cloud role".to_owned(),
            });
        }
        if let Some(max) = ctx.config.granted_max.get(perm)
            && *access > *max
        {
            findings.push(Finding {
                rule: RuleId::OverlyBroadPermissions,
                severity: Severity::High,
                file: ctx.path.to_path_buf(),
                line: ctx.find_line(needle),
                job: None,
                message: format!(
                    "{scope} grants {perm}: {access}, beyond the configured maximum of {max}"
                ),
                explanation: "rivet.yaml declares the most this repo needs; a larger grant is either a mistake or an escalation path.".to_owned(),
                fix: format!(
                    "Reduce {perm} to {max}, or update rivet.yaml if the broader grant is intentional"
                ),
            });
        }
    }
}

/// True if any step passes an OIDC role input (`role-to-assume` or
/// `role_arn`), the signal that `id-token: write` is actually used.
fn has_oidc_input(workflow: &crate::model::Workflow) -> bool {
    workflow.jobs.iter().any(|job| {
        job.steps.iter().any(|step| {
            let Step::Uses { with, .. } = step else {
                return false;
            };
            with.iter().any(|(k, _)| {
                k.eq_ignore_ascii_case("role-to-assume") || k.eq_ignore_ascii_case("role_arn")
            })
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::input::ParsedWorkflow;
    use crate::model::Access;
    use crate::parse::parse_workflow;
    use crate::rules::Rule;
    use std::path::PathBuf;

    fn evaluate_with(raw: &str, config: &Config) -> Vec<Finding> {
        let model = parse_workflow(raw).unwrap();
        let parsed = ParsedWorkflow::new(PathBuf::from("w.yml"), raw.to_owned(), model);
        OverlyBroadPermissions.evaluate(&RuleContext {
            workflow: &parsed.model,
            path: &parsed.path,
            config,
            raw: &parsed.raw,
        })
    }

    fn evaluate(raw: &str) -> Vec<Finding> {
        evaluate_with(raw, &Config::default())
    }

    #[test]
    fn flags_missing_block_and_write_all() {
        let f = evaluate("on: push\njobs:\n  b:\n    steps:\n      - run: echo hi\n");
        assert_eq!(f.len(), 1);
        assert!(f[0].message.contains("no permissions block"));

        let f = evaluate(
            "on: push\npermissions: write-all\njobs:\n  b:\n    steps:\n      - run: echo hi\n",
        );
        assert_eq!(f.len(), 1);
        assert!(f[0].message.contains("write-all"));
    }

    #[test]
    fn flags_id_token_without_oidc() {
        let f = evaluate(
            "on: push\npermissions:\n  id-token: write\njobs:\n  b:\n    steps:\n      - run: echo hi\n",
        );
        assert_eq!(f.len(), 1);
        assert!(f[0].message.contains("id-token"));
    }

    #[test]
    fn passes_id_token_with_role_assume() {
        let f = evaluate(
            "on: push\npermissions:\n  id-token: write\njobs:\n  b:\n    steps:\n      - uses: aws-actions/configure-aws-credentials@v4\n        with:\n          role-to-assume: arn:aws:iam::1:role/x\n",
        );
        assert!(f.is_empty());
    }

    #[test]
    fn flags_grant_beyond_configured_maximum() {
        let mut config = Config::default();
        config
            .granted_max
            .insert(crate::model::Permission::Contents, Access::Read);
        let f = evaluate_with(
            "on: push\npermissions:\n  contents: write\njobs:\n  b:\n    steps:\n      - run: echo hi\n",
            &config,
        );
        assert_eq!(f.len(), 1);
        assert!(f[0].message.contains("beyond the configured maximum"));
    }

    #[test]
    fn passes_minimal_permissions() {
        let f = evaluate(
            "on: push\npermissions:\n  contents: read\njobs:\n  b:\n    steps:\n      - run: echo hi\n",
        );
        assert!(f.is_empty());
    }
}
