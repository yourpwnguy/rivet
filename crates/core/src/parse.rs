//! The single YAML touchpoint: `serde_yaml::Value` → normalized [`Workflow`].
//!
//! Everything YAML-specific lives here — the `on:` key coercion (YAML 1.1
//! parses the bare key `on` as boolean `true`), string/list/map
//! polymorphism, and error reporting with source locations. Rules never
//! see serde types.

use std::fmt;

use serde_yaml::Value;

use crate::model::{
    Access, Job, Permission, Permissions, RunsOn, Step, TriggerEvent, Triggers, Workflow,
};

/// A YAML syntax or structure error, with its source line when available.
#[derive(Debug, Clone, PartialEq)]
pub struct ParseError {
    /// Human-readable description.
    pub message: String,
    /// 1-based source line, when serde could locate it.
    pub line: Option<usize>,
}

impl ParseError {
    fn new(message: impl Into<String>, line: Option<usize>) -> Self {
        Self {
            message: message.into(),
            line,
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.line {
            Some(l) => write!(f, "{} (line {})", self.message, l),
            None => write!(f, "{}", self.message),
        }
    }
}

impl std::error::Error for ParseError {}

/// Parse raw workflow text into the normalized model.
///
/// Returns `Err` for YAML that cannot be parsed at all (syntax errors,
/// multiple documents) or whose root structure is unusable. Semantically
/// odd but parseable YAML is normalized leniently — rivet audits what it
/// can see, and schema validation is explicitly actionlint's job.
pub fn parse_workflow(raw: &str) -> Result<Workflow, ParseError> {
    let value: Value = serde_yaml::from_str(raw)
        .map_err(|e| ParseError::new(e.to_string(), e.location().map(|l| l.line())))?;
    Workflow::try_from(value)
}

impl TryFrom<Value> for Workflow {
    type Error = ParseError;

    fn try_from(v: Value) -> Result<Self, Self::Error> {
        let Value::Mapping(map) = v else {
            return Err(ParseError::new("workflow root must be a mapping", None));
        };
        let mut name = None;
        let mut triggers = Triggers::default();
        let mut env = Vec::new();
        let mut permissions = None;
        let mut jobs = Vec::new();
        for (k, v) in map {
            let key = mapping_key(&k)?;
            match key.as_str() {
                "name" => name = Some(stringify(v)?),
                // YAML 1.1 parses the bare key `on` as boolean `true`;
                // accept both spellings so triggers are never silently lost.
                "on" | "true" => triggers = parse_triggers(v)?,
                "env" => env = parse_env(v)?,
                "permissions" => permissions = Some(Permissions::try_from(v)?),
                "jobs" => jobs = parse_jobs(v)?,
                _ => {} // unknown top-level keys are ignored (forward compat)
            }
        }
        Ok(Workflow {
            name,
            triggers,
            env,
            permissions,
            jobs,
        })
    }
}

/// Normalize a mapping key to a string, mapping YAML 1.1's boolean `on`
/// key back to `"on"`.
fn mapping_key(k: &Value) -> Result<String, ParseError> {
    match k {
        Value::String(s) => Ok(s.clone()),
        Value::Bool(true) => Ok("on".to_owned()),
        _ => Err(ParseError::new("mapping keys must be strings", None)),
    }
}

/// Scalar → string, for fields that accept any scalar (`env:` values,
/// `with:` inputs, `name:`).
fn stringify(v: Value) -> Result<String, ParseError> {
    match v {
        Value::String(s) => Ok(s),
        Value::Bool(b) => Ok(b.to_string()),
        Value::Number(n) => Ok(n.to_string()),
        Value::Null => Ok(String::new()),
        _ => Err(ParseError::new("expected a scalar value", None)),
    }
}

fn parse_triggers(v: Value) -> Result<Triggers, ParseError> {
    fn push(events: &mut Vec<TriggerEvent>, s: &str) {
        events.push(match s {
            "pull_request" => TriggerEvent::PullRequest,
            "pull_request_target" => TriggerEvent::PullRequestTarget,
            "workflow_run" => TriggerEvent::WorkflowRun,
            "workflow_call" => TriggerEvent::WorkflowCall,
            "push" => TriggerEvent::Push,
            "schedule" => TriggerEvent::Schedule,
            other => TriggerEvent::Other(other.to_owned()),
        });
    }
    let mut events = Vec::new();
    match v {
        Value::String(s) => push(&mut events, &s),
        Value::Sequence(seq) => {
            for item in seq {
                push(&mut events, &stringify(item)?);
            }
        }
        Value::Mapping(map) => {
            for (k, _) in map {
                push(&mut events, &mapping_key(&k)?);
            }
        }
        Value::Null => {}
        _ => {
            return Err(ParseError::new(
                "`on:` must be a string, list, or mapping",
                None,
            ));
        }
    }
    events.sort();
    events.dedup();
    Ok(Triggers { events })
}

fn parse_jobs(v: Value) -> Result<Vec<Job>, ParseError> {
    let Value::Mapping(map) = v else {
        return Err(ParseError::new("`jobs:` must be a mapping", None));
    };
    map.into_iter()
        .map(|(k, v)| {
            let id = mapping_key(&k)?;
            let Value::Mapping(j) = v else {
                return Err(ParseError::new(
                    format!("job `{id}` must be a mapping"),
                    None,
                ));
            };
            // GitHub's default when `runs-on` is omitted; safe (never self-hosted).
            let mut runs_on = RunsOn::Label("ubuntu-latest".to_owned());
            let mut permissions = None;
            let mut env = Vec::new();
            let mut steps = Vec::new();
            for (jk, jv) in j {
                match mapping_key(&jk)?.as_str() {
                    "runs-on" => runs_on = parse_runs_on(jv)?,
                    "permissions" => permissions = Some(Permissions::try_from(jv)?),
                    "env" => env = parse_env(jv)?,
                    "steps" => steps = parse_steps(jv)?,
                    _ => {}
                }
            }
            Ok(Job {
                id,
                runs_on,
                permissions,
                env,
                steps,
            })
        })
        .collect()
}

fn parse_runs_on(v: Value) -> Result<RunsOn, ParseError> {
    match v {
        Value::String(s) => Ok(RunsOn::Label(s)),
        Value::Sequence(seq) => {
            let labels = seq
                .into_iter()
                .map(stringify)
                .collect::<Result<Vec<_>, _>>()?;
            if labels.len() == 1 {
                Ok(RunsOn::Label(labels.into_iter().next().unwrap_or_default()))
            } else {
                Ok(RunsOn::Labels(labels))
            }
        }
        Value::Mapping(m) => {
            let mut group = String::new();
            let mut labels = Vec::new();
            for (k, v) in m {
                match mapping_key(&k)?.as_str() {
                    "group" => group = stringify(v)?,
                    "labels" => {
                        let Value::Sequence(seq) = v else {
                            return Err(ParseError::new("`labels:` must be a list", None));
                        };
                        labels = seq
                            .into_iter()
                            .map(stringify)
                            .collect::<Result<Vec<_>, _>>()?;
                    }
                    _ => {}
                }
            }
            Ok(RunsOn::Group(group, labels))
        }
        _ => Err(ParseError::new(
            "`runs-on:` must be a string, list, or mapping",
            None,
        )),
    }
}

/// Parse a string→string mapping (`env:`, `with:`).
fn parse_env(v: Value) -> Result<Vec<(String, String)>, ParseError> {
    let Value::Mapping(m) = v else {
        return Err(ParseError::new("expected a mapping", None));
    };
    m.into_iter()
        .map(|(k, v)| Ok((mapping_key(&k)?, stringify(v)?)))
        .collect()
}

fn parse_steps(v: Value) -> Result<Vec<Step>, ParseError> {
    let Value::Sequence(seq) = v else {
        return Err(ParseError::new("`steps:` must be a list", None));
    };
    seq.into_iter()
        .map(|item| {
            let Value::Mapping(m) = item else {
                return Err(ParseError::new("each step must be a mapping", None));
            };
            let mut run = None;
            let mut uses = None;
            let mut shell = None;
            let mut with = Vec::new();
            for (k, v) in m {
                match mapping_key(&k)?.as_str() {
                    "run" => run = Some(stringify(v)?),
                    "uses" => uses = Some(stringify(v)?),
                    "shell" => shell = Some(stringify(v)?),
                    "with" => with = parse_env(v)?,
                    _ => {}
                }
            }
            if let Some(script) = run {
                Ok(Step::Run { script, shell })
            } else if let Some(target) = uses {
                Ok(Step::Uses { target, with })
            } else {
                Err(ParseError::new("step has neither `run:` nor `uses:`", None))
            }
        })
        .collect()
}

impl TryFrom<Value> for Permissions {
    type Error = ParseError;

    fn try_from(v: Value) -> Result<Self, Self::Error> {
        match v {
            Value::String(s) if s == "write-all" => Ok(Permissions {
                grants: Vec::new(),
                write_all: true,
            }),
            Value::Mapping(m) => {
                let grants = m
                    .into_iter()
                    .map(|(k, v)| {
                        let perm = Permission::parse(&mapping_key(&k)?);
                        let access = match stringify(v)?.as_str() {
                            "read" => Access::Read,
                            "write" => Access::Write,
                            "none" => Access::None,
                            other => {
                                return Err(ParseError::new(
                                    format!("invalid access `{other}` for {perm}"),
                                    None,
                                ));
                            }
                        };
                        Ok((perm, access))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Permissions {
                    grants,
                    write_all: false,
                })
            }
            _ => Err(ParseError::new(
                "`permissions:` must be a mapping or `write-all`",
                None,
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str =
        "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n";

    #[test]
    fn parses_minimal_workflow() {
        let wf = parse_workflow(MINIMAL).unwrap();
        assert!(wf.triggers.contains(&TriggerEvent::Push));
        assert_eq!(wf.jobs.len(), 1);
        assert_eq!(wf.jobs[0].id, "build");
        assert_eq!(
            wf.jobs[0].steps[0],
            Step::Run {
                script: "echo hi".to_owned(),
                shell: None
            }
        );
    }

    #[test]
    fn parses_on_as_list_and_map() {
        for raw in [
            "on: [push, pull_request]\njobs: {}",
            "on:\n  push:\n  pull_request:\njobs: {}",
        ] {
            let wf = parse_workflow(raw).unwrap();
            assert!(wf.triggers.contains(&TriggerEvent::Push), "{raw}");
            assert!(wf.triggers.contains(&TriggerEvent::PullRequest), "{raw}");
        }
    }

    #[test]
    fn parses_permissions_forms() {
        let wf = parse_workflow("on: push\npermissions: write-all\njobs: {}").unwrap();
        assert!(wf.permissions.unwrap().write_all);

        let wf =
            parse_workflow("on: push\npermissions:\n  contents: read\n  id-token: write\njobs: {}")
                .unwrap();
        let perms = wf.permissions.unwrap();
        assert!(!perms.write_all);
        assert_eq!(perms.grants.len(), 2);
    }

    #[test]
    fn parses_uses_with_inputs() {
        let raw = "on: push\njobs:\n  b:\n    steps:\n      - uses: actions/checkout@v3\n        with:\n          ref: main\n";
        let wf = parse_workflow(raw).unwrap();
        let Step::Uses { target, with } = &wf.jobs[0].steps[0] else {
            panic!("expected uses step");
        };
        assert_eq!(target, "actions/checkout@v3");
        assert_eq!(with[0], ("ref".to_owned(), "main".to_owned()));
    }

    #[test]
    fn reports_syntax_errors_with_line() {
        let err = parse_workflow("on: push\njobs:\n  build:\n   bad: [unclosed").unwrap_err();
        assert!(err.line.is_some(), "expected a located error: {err}");
    }

    #[test]
    fn rejects_multi_document_yaml() {
        assert!(parse_workflow("on: push\n---\njobs: {}").is_err());
    }
}
