//! The single YAML touchpoint: `serde_yaml::Value` → normalized [`Workflow`].
//!
//! Everything YAML-specific lives behind this module: the `on:` key
//! coercion (YAML 1.1 parses the bare key `on` as boolean `true`),
//! string/list/map polymorphism, and error reporting with source locations.
//! Rules never see serde types.
//!
//! This file is the workflow-level assembly; the per-field coercion lives in
//! [`fields`]. Keeping the split sharp means the top-level shape of a
//! workflow can be read in one screen, and each field's accepted shapes live
//! next to its name.

mod fields;

use std::fmt;

use serde_yaml::Value;

use crate::model::{Triggers, Workflow};

use fields::{mapping_key, parse_env, parse_jobs, parse_permissions, parse_triggers, stringify};

/// A YAML syntax or structure error, with its source line when available.
#[derive(Debug, Clone, PartialEq)]
pub struct ParseError {
    /// Human-readable description.
    pub message: String,
    /// 1-based source line, when serde could locate it.
    pub line: Option<usize>,
}

impl ParseError {
    /// Build an error, attaching a source line when serde located one.
    pub(super) fn new(message: impl Into<String>, line: Option<usize>) -> Self {
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
/// odd but parseable YAML is normalized leniently: rivet audits what it can
/// see, and schema validation is explicitly actionlint's job.
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
            // Unknown top-level keys are ignored so workflows using fields
            // rivet does not model yet still audit cleanly.
            match mapping_key(&k)?.as_str() {
                "name" => name = Some(stringify(v)?),
                // `mapping_key` already folded YAML 1.1's boolean `true`
                // back to "on"; matching both keeps that explicit here.
                "on" | "true" => triggers = parse_triggers(v)?,
                "env" => env = parse_env(v)?,
                "permissions" => permissions = Some(parse_permissions(v)?),
                "jobs" => jobs = parse_jobs(v)?,
                _ => {}
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Step;

    const MINIMAL: &str =
        "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n";

    #[test]
    fn parses_minimal_workflow() {
        let wf = parse_workflow(MINIMAL).unwrap();
        assert!(wf.triggers.contains(&crate::model::TriggerEvent::Push));
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

    /// The `on` key is the single most important one in a workflow, and YAML
    /// 1.1 turns the bare word into boolean `true`. Both spellings must
    /// produce the same triggers or rules would silently go quiet.
    #[test]
    fn recovers_on_key_from_yaml_1_1_boolean_form() {
        let from_string = parse_workflow("on:\n  pull_request_target:\njobs: {}").unwrap();
        let from_mapping = parse_workflow("on:\n  pull_request_target: {}\njobs: {}").unwrap();
        assert!(from_string.triggers.pull_request_target());
        assert!(from_mapping.triggers.pull_request_target());
    }

    #[test]
    fn rejects_multi_document_yaml() {
        assert!(parse_workflow("on: push\n---\njobs: {}").is_err());
    }

    #[test]
    fn rejects_non_mapping_root() {
        assert!(parse_workflow("- a\n- b\n").is_err());
        assert!(parse_workflow("").is_err());
    }

    /// Unknown top-level keys must not stop an audit; a workflow using a
    /// field rivet does not model yet still deserves to be scanned.
    #[test]
    fn ignores_unknown_top_level_keys() {
        let wf = parse_workflow("on: push\nconcurrency: group\njobs: {}").unwrap();
        assert!(wf.triggers.contains(&crate::model::TriggerEvent::Push));
    }

    #[test]
    fn error_display_includes_line_when_known() {
        let err = ParseError::new("boom", Some(7));
        assert_eq!(err.to_string(), "boom (line 7)");
        let err = ParseError::new("boom", None);
        assert_eq!(err.to_string(), "boom");
    }
}
