//! The `rivet.yaml` configuration schema.
//!
//! One optional config file per scan, discovered at the scan root (the CLI
//! does the reading; [`Config::parse`] is pure). It carries the two things
//! rivet cannot infer locally: repository visibility (gates R06) and the
//! maximum grants the repo declares it needs (R04's ceiling).

use std::collections::HashMap;

use serde_yaml::Value;

use crate::model::{Access, Permission};

/// Repository visibility, which gates R06.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Visibility {
    /// Not declared — R06 stays silent rather than crying wolf, since
    /// self-hosted runners are only dangerous in public repos and rivet
    /// cannot determine visibility from local files alone.
    #[default]
    Unknown,
    Public,
    Private,
}

/// Resolved configuration.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Config {
    /// Repository visibility, defaulting to [`Visibility::Unknown`].
    pub repo_visibility: Visibility,
    /// `permissions.granted_max` from rivet.yaml: the most each permission
    /// may be granted in this repo. Grants beyond the ceiling are flagged
    /// by R04.
    pub granted_max: HashMap<Permission, Access>,
}

/// A malformed `rivet.yaml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    /// Parse `rivet.yaml` content. Pure — the caller does the reading.
    ///
    /// An empty file is a valid no-op config; anything else must be a
    /// mapping.
    pub fn parse(raw: &str) -> Result<Config, ConfigError> {
        let value: Value = serde_yaml::from_str(raw)
            .map_err(|e| ConfigError(format!("invalid rivet.yaml: {e}")))?;
        let Value::Mapping(map) = value else {
            if value.is_null() {
                return Ok(Config::default());
            }
            return Err(ConfigError("rivet.yaml root must be a mapping".into()));
        };
        let mut cfg = Config::default();
        for (k, v) in map {
            let Value::String(key) = &k else { continue };
            match key.as_str() {
                "repo_visibility" => {
                    let Value::String(s) = &v else {
                        return Err(ConfigError("repo_visibility must be a string".into()));
                    };
                    cfg.repo_visibility = match s.as_str() {
                        "public" => Visibility::Public,
                        "private" => Visibility::Private,
                        "unknown" => Visibility::Unknown,
                        other => {
                            return Err(ConfigError(format!(
                                "invalid repo_visibility `{other}` (expected public, private, or unknown)"
                            )));
                        }
                    };
                }
                "permissions" => cfg.granted_max = parse_granted_max(&v)?,
                _ => {}
            }
        }
        Ok(cfg)
    }
}

/// Parse a permission scope name, rejecting names rivet does not know.
///
/// `Permission::parse` maps unknown names to `Other(String)` so the workflow
/// model stays lossless, but a *config* ceiling for an unrecognized scope is
/// always a typo, so it is rejected here instead of silently ignored.
fn parse_ceiling_permission(name: &str) -> Result<Permission, ConfigError> {
    let permission = Permission::parse(name);
    if matches!(permission, Permission::Other(_)) {
        return Err(ConfigError(format!("unknown permission `{name}`")));
    }
    Ok(permission)
}

/// Parse an access level keyword.
fn parse_access(value: &str) -> Result<Access, ConfigError> {
    match value {
        "read" => Ok(Access::Read),
        "write" => Ok(Access::Write),
        "none" => Ok(Access::None),
        other => Err(ConfigError(format!(
            "invalid access `{other}` (expected read, write, or none)"
        ))),
    }
}

/// Parse `permissions: { granted_max: { contents: read, … } }`.
///
/// Keys other than `granted_max` are skipped so the block can grow later
/// without breaking existing configs. Non-string values are rejected rather
/// than coerced: a ceiling written as `yes` or a bare number is a mistake,
/// and silently reading it as something else would weaken the policy.
fn parse_granted_max(v: &Value) -> Result<HashMap<Permission, Access>, ConfigError> {
    let Value::Mapping(permissions) = v else {
        return Err(ConfigError("permissions must be a mapping".into()));
    };
    let mut out = HashMap::new();
    for (key, value) in permissions {
        if key.as_str() != Some("granted_max") {
            continue;
        }
        let Value::Mapping(grants) = value else {
            return Err(ConfigError("granted_max must be a mapping".into()));
        };
        for (scope, level) in grants {
            let Some(scope) = scope.as_str() else {
                return Err(ConfigError("granted_max keys must be strings".into()));
            };
            let Some(level) = level.as_str() else {
                return Err(ConfigError("granted_max values must be strings".into()));
            };
            out.insert(parse_ceiling_permission(scope)?, parse_access(level)?);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_visibility_and_granted_max() {
        let cfg = Config::parse(
            "repo_visibility: public\npermissions:\n  granted_max:\n    contents: read\n",
        )
        .unwrap();
        assert_eq!(cfg.repo_visibility, Visibility::Public);
        assert_eq!(
            cfg.granted_max.get(&Permission::Contents),
            Some(&Access::Read)
        );
    }

    #[test]
    fn defaults_to_empty() {
        let cfg = Config::parse("").unwrap();
        assert_eq!(cfg.repo_visibility, Visibility::Unknown);
        assert!(cfg.granted_max.is_empty());
    }

    #[test]
    fn rejects_bad_visibility() {
        assert!(Config::parse("repo_visibility: maybe").is_err());
    }

    #[test]
    fn rejects_unknown_permission() {
        assert!(Config::parse("permissions:\n  granted_max:\n    bogus: read\n").is_err());
    }

    /// Both keys in one file must survive: R06 needs visibility and R04
    /// needs the ceilings simultaneously, which is the normal shape of a
    /// real config.
    #[test]
    fn parses_both_visibility_and_granted_max() {
        let cfg = Config::parse(
            "repo_visibility: private\npermissions:\n  granted_max:\n    contents: read\n    packages: write\n",
        )
        .unwrap();
        assert_eq!(cfg.repo_visibility, Visibility::Private);
        assert_eq!(cfg.granted_max.len(), 2);
        assert_eq!(cfg.granted_max[&Permission::Contents], Access::Read);
        assert_eq!(cfg.granted_max[&Permission::Packages], Access::Write);
    }

    /// Unknown keys inside the permissions block are skipped so the schema
    /// can grow without breaking existing configs.
    #[test]
    fn ignores_unknown_keys_in_permissions_block() {
        let cfg =
            Config::parse("permissions:\n  future_knob: true\n  granted_max:\n    issues: read\n")
                .unwrap();
        assert_eq!(cfg.granted_max.len(), 1);
    }

    /// A ceiling written as a non-string is a mistake, not a value to
    /// coerce. Silently accepting it would weaken the policy.
    #[test]
    fn rejects_non_string_granted_max_value() {
        assert!(Config::parse("permissions:\n  granted_max:\n    contents: true\n").is_err());
    }

    #[test]
    fn rejects_non_mapping_permissions_block() {
        assert!(Config::parse("permissions: contents\n").is_err());
    }
}
