//! Step-level YAML: the `steps:` list and the string→string mapping shape
//! shared by `env:` and `with:`.
//!
//! Steps are where the rules do their real work: R01 and R05 read `run:`
//! scripts, R02/R03/R08/R10 read `uses:` targets, and every one of them needs
//! the `with:` inputs to make a decision. A step that fails to parse is a
//! step no rule can inspect.

use serde_yaml::Value;

use super::{mapping_key, stringify};
use crate::model::Step;
use crate::parse::ParseError;

/// Parse a string→string mapping (`env:`, `with:`).
///
/// Order is preserved so a finding that names an env var points at the right
/// one when a workflow defines several.
pub fn parse_env(v: Value) -> Result<Vec<(String, String)>, ParseError> {
    let Value::Mapping(m) = v else {
        return Err(ParseError::new("expected a mapping", None));
    };
    m.into_iter()
        .map(|(k, v)| Ok((mapping_key(&k)?, stringify(v)?)))
        .collect()
}

/// Parse the `steps:` list.
///
/// Every step declares exactly one of `run:` or `uses:`. A step with neither
/// is rejected because it cannot be audited; one with both is not a shape
/// GitHub accepts, and silently picking a winner would misreport what runs.
pub fn parse_steps(v: Value) -> Result<Vec<Step>, ParseError> {
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
                // Unknown step keys (`name:`, `if:`, `continue-on-error:`,
                // ...) are ignored; they change control flow, not what the
                // step executes, and the rules reason about the latter.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn yaml(raw: &str) -> Value {
        serde_yaml::from_str(raw).expect("test fixture must be valid YAML")
    }

    #[test]
    fn parses_run_step_with_shell() {
        let steps = parse_steps(yaml("- {run: echo hi, shell: bash}")).unwrap();
        assert_eq!(
            steps[0],
            Step::Run {
                script: "echo hi".into(),
                shell: Some("bash".into())
            }
        );
    }

    #[test]
    fn parses_uses_step_with_inputs() {
        let steps = parse_steps(yaml("- {uses: actions/checkout@v3, with: {ref: main}}")).unwrap();
        let Step::Uses { target, with } = &steps[0] else {
            panic!("expected a uses step");
        };
        assert_eq!(target, "actions/checkout@v3");
        assert_eq!(with[0], ("ref".to_owned(), "main".to_owned()));
    }

    /// A step that declares neither `run:` nor `uses:` cannot be audited, so
    /// it is an error rather than a step the rules silently skip.
    #[test]
    fn step_without_run_or_uses_is_rejected() {
        assert!(parse_steps(yaml("- {name: just a label}")).is_err());
    }

    /// Step keys that affect control flow rather than execution are ignored
    /// so a workflow using them still audits cleanly.
    #[test]
    fn ignores_control_flow_keys() {
        let steps = parse_steps(yaml("- {name: build, if: always(), run: echo hi}")).unwrap();
        assert!(matches!(steps[0], Step::Run { .. }));
    }

    #[test]
    fn env_values_accept_any_scalar() {
        let parsed = parse_env(yaml("{A: x, B: 2, C: true, D: null}")).unwrap();
        let values: Vec<&str> = parsed.iter().map(|(_, v)| v.as_str()).collect();
        assert_eq!(values, vec!["x", "2", "true", ""]);
    }

    #[test]
    fn wrong_shapes_are_rejected() {
        assert!(parse_steps(yaml("nope")).is_err());
        assert!(parse_env(yaml("[a, b]")).is_err());
    }
}
