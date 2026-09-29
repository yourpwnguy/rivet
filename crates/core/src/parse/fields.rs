//! Field-level YAML normalizers: `serde_yaml::Value` → model types.
//!
//! This module holds the primitives every field parser shares; the parsers
//! themselves are grouped by the workflow level they belong to:
//!
//! * [`jobs`] — `jobs:`, `runs-on:`, `permissions:`
//! * [`steps`] — `steps:`, and the `env:`/`with:` mapping shape
//!
//! Two rules hold across all of them:
//!
//! * **Unknown keys are ignored, wrong values are errors.** Extra
//!   top-level or step keys do not stop an audit, but a `runs-on:` that is
//!   neither a string, list, nor mapping is reported rather than guessed at,
//!   because guessing wrong would hide a job from the rules entirely.
//! * **Coercion is scalar-only.** `stringify` accepts any YAML scalar and
//!   rejects collections, because `env:` and `with:` values are always leaves.

use serde_yaml::Value;

use super::ParseError;

mod jobs;
mod steps;

pub(super) use jobs::{parse_jobs, parse_permissions};
pub(super) use steps::{parse_env, parse_steps};

/// Normalize a mapping key to a string, mapping YAML 1.1's boolean `on`
/// key back to `"on"`.
///
/// This is the one place the `on` key is rescued: serde_yaml reports the bare
/// key `on` as boolean `true`, and without this the single most important key
/// in a workflow would be dropped and every trigger-based rule would go quiet.
pub fn mapping_key(k: &Value) -> Result<String, ParseError> {
    match k {
        Value::String(s) => Ok(s.clone()),
        Value::Bool(true) => Ok("on".to_owned()),
        _ => Err(ParseError::new("mapping keys must be strings", None)),
    }
}

/// Scalar to string, for fields that accept any scalar (`env:` values,
/// `with:` inputs, `name:`).
///
/// `Null` becomes the empty string rather than an error: `FOO:` with no value
/// is a common way to write an intentionally-blank variable, and treating it
/// as malformed would fail scans over perfectly valid workflows.
pub fn stringify(v: Value) -> Result<String, ParseError> {
    match v {
        Value::String(s) => Ok(s),
        Value::Bool(b) => Ok(b.to_string()),
        Value::Number(n) => Ok(n.to_string()),
        Value::Null => Ok(String::new()),
        _ => Err(ParseError::new("expected a scalar value", None)),
    }
}

/// Parse the `on:` block, which GitHub accepts as a string, a list, or a
/// mapping of event to config.
///
/// Results are sorted and deduplicated so rule output stays deterministic
/// regardless of how the author happened to write the trigger list.
pub(super) fn parse_triggers(v: Value) -> Result<crate::model::Triggers, ParseError> {
    use crate::model::{TriggerEvent, Triggers};

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
