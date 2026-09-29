//! Job-level YAML: the `jobs:` mapping, `runs-on:`, and `permissions:`.
//!
//! These fields decide *where* a job runs and *what it is allowed to do*,
//! which is exactly what R04 and R06 read. Getting a shape wrong here is
//! worse than a parse error: a job silently dropped from the model is a job
//! the rules never see.

use serde_yaml::Value;

use super::parse_env;
use super::parse_steps;
use super::{mapping_key, stringify};
use crate::model::{Access, Job, Permission, Permissions, RunsOn};
use crate::parse::ParseError;

/// Parse the `jobs:` mapping, preserving file order so findings and reports
/// stay deterministic.
pub fn parse_jobs(v: Value) -> Result<Vec<Job>, ParseError> {
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
            // GitHub's default when `runs-on` is omitted. Choosing a hosted
            // label matters: defaulting to anything self-hosted would make
            // R06 fire on every workflow that simply left the field out.
            let mut runs_on = RunsOn::Label("ubuntu-latest".to_owned());
            let mut permissions = None;
            let mut env = Vec::new();
            let mut steps = Vec::new();
            for (jk, jv) in j {
                // Unknown job keys are ignored for forward compatibility.
                match mapping_key(&jk)?.as_str() {
                    "runs-on" => runs_on = parse_runs_on(jv)?,
                    "permissions" => permissions = Some(parse_permissions(jv)?),
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

/// Parse `runs-on:`, which GitHub accepts as a label, a list of alternative
/// labels, or a runner-group object.
pub(super) fn parse_runs_on(v: Value) -> Result<RunsOn, ParseError> {
    match v {
        Value::String(s) => Ok(RunsOn::Label(s)),
        Value::Sequence(seq) => {
            let labels = seq
                .into_iter()
                .map(stringify)
                .collect::<Result<Vec<_>, _>>()?;
            // A one-element list carries no more information than the bare
            // label, so normalize it away rather than making every consumer
            // handle both shapes.
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

/// Parse a `permissions:` block, either the literal `write-all` or a mapping
/// of scope to access level.
///
/// One function serves both workflow-level and job-level blocks, so R04 sees
/// the same shape regardless of where the block was declared.
pub fn parse_permissions(v: Value) -> Result<Permissions, ParseError> {
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
                        // An unrecognized access level is rejected: reading
                        // it as `read` could understate a live grant, and
                        // reading it as `write` would cry wolf.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Permission;

    fn yaml(raw: &str) -> Value {
        serde_yaml::from_str(raw).expect("test fixture must be valid YAML")
    }

    /// `runs-on` has three accepted shapes. Misreading one would either hide
    /// a job from R06 or drop the job entirely, so each is pinned.
    #[test]
    fn runs_on_accepts_label_list_and_group() {
        assert_eq!(
            parse_runs_on(yaml("ubuntu-latest")).unwrap(),
            RunsOn::Label("ubuntu-latest".into())
        );
        assert_eq!(
            parse_runs_on(yaml("[self-hosted, linux]")).unwrap(),
            RunsOn::Labels(vec!["self-hosted".into(), "linux".into()])
        );
        assert_eq!(
            parse_runs_on(yaml("{group: prod, labels: [self-hosted]}")).unwrap(),
            RunsOn::Group("prod".into(), vec!["self-hosted".into()])
        );
    }

    /// A one-element label list carries no more information than the bare
    /// label, so it is normalized away.
    #[test]
    fn single_label_list_collapses_to_label() {
        assert_eq!(
            parse_runs_on(yaml("[self-hosted]")).unwrap(),
            RunsOn::Label("self-hosted".into())
        );
    }

    #[test]
    fn omitted_runs_on_defaults_to_hosted() {
        // The default must be a GitHub-hosted label, or R06 would fire on
        // every workflow that simply left `runs-on` out.
        let jobs = parse_jobs(yaml("build: {steps: [{run: echo hi}]}")).unwrap();
        assert_eq!(jobs[0].runs_on, RunsOn::Label("ubuntu-latest".into()));
        assert!(!jobs[0].runs_on.is_self_hosted());
    }

    #[test]
    fn permissions_write_all_and_scoped() {
        let all = parse_permissions(yaml("write-all")).unwrap();
        assert!(all.write_all);
        let scoped = parse_permissions(yaml("{contents: read, id-token: write}")).unwrap();
        assert!(!scoped.write_all);
        assert_eq!(scoped.grants.len(), 2);
    }

    /// An unknown scope survives into the model so the parse stays lossless;
    /// only an invalid access level is rejected.
    #[test]
    fn permissions_keep_unknown_scopes_but_reject_bad_access() {
        let perms = parse_permissions(yaml("{not-a-scope: read}")).unwrap();
        assert_eq!(perms.grants[0].0, Permission::Other("not-a-scope".into()));
        assert!(parse_permissions(yaml("{contents: sideways}")).is_err());
    }

    /// A malformed job mapping is an error, not a silently skipped job.
    #[test]
    fn wrong_job_shapes_are_rejected() {
        assert!(parse_jobs(yaml("[]")).is_err());
        assert!(parse_jobs(yaml("build: not-a-mapping")).is_err());
        assert!(parse_runs_on(yaml("42: x")).is_err());
    }
}
