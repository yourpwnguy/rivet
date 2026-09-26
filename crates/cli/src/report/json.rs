//! JSON output — the machine-readable contract.
//!
//! A bare top-level array of finding objects, exactly as documented:
//!
//! ```json
//! [
//!   {
//!     "rule": "pull-request-target",
//!     "severity": "high",
//!     "file": ".github/workflows/build.yml",
//!     "line": 3,
//!     "job": "build",
//!     "message": "…",
//!     "fix": "…"
//!   }
//! ]
//! ```
//!
//! `line` and `job` are omitted when unknown. The schema is versioned by
//! the tool version; evolving it is a semver concern.

use std::io::Write;

use rivet_core::finding::Finding;
use serde::Serialize;

/// Serialize one finding. Field order matches the documented contract.
#[derive(Serialize)]
struct FindingJson<'a> {
    rule: &'static str,
    severity: &'static str,
    file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    job: Option<&'a str>,
    message: &'a str,
    fix: &'a str,
}

/// Write the findings as a pretty-printed JSON array.
pub fn write<W: Write>(out: &mut W, findings: &[Finding]) -> std::io::Result<()> {
    let items: Vec<FindingJson> = findings
        .iter()
        .map(|f| FindingJson {
            rule: f.rule.as_str(),
            severity: f.severity.as_str(),
            file: f.file.display().to_string(),
            line: f.line,
            job: f.job.as_deref(),
            message: &f.message,
            fix: &f.fix,
        })
        .collect();
    serde_json::to_writer_pretty(&mut *out, &items)?;
    writeln!(out)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rivet_core::finding::RuleId;
    use rivet_core::severity::Severity;
    use std::path::PathBuf;

    #[test]
    fn emits_documented_shape() {
        let findings = vec![Finding {
            rule: RuleId::PullRequestTargetCheckout,
            severity: Severity::High,
            file: PathBuf::from(".github/workflows/build.yml"),
            line: Some(3),
            job: Some("build".into()),
            message: "m".into(),
            explanation: "e".into(),
            fix: "t".into(),
        }];
        let mut buf = Vec::new();
        write(&mut buf, &findings).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert!(v.is_array());
        let item = &v[0];
        assert_eq!(item["rule"], "pull-request-target");
        assert_eq!(item["severity"], "high");
        assert_eq!(item["file"], ".github/workflows/build.yml");
        assert_eq!(item["line"], 3);
        assert_eq!(item["job"], "build");
        assert_eq!(item["fix"], "t");
    }

    #[test]
    fn omits_unknown_line_and_job() {
        let f = Finding {
            rule: RuleId::DebugLogging,
            severity: Severity::Info,
            file: PathBuf::from("w.yml"),
            line: None,
            job: None,
            message: "m".into(),
            explanation: "e".into(),
            fix: "t".into(),
        };
        let mut buf = Vec::new();
        write(&mut buf, std::slice::from_ref(&f)).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert!(v[0].get("line").is_none());
        assert!(v[0].get("job").is_none());
    }
}
