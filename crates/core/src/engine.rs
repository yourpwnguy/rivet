//! Orchestration: run every rule over every parsed file, sort, done.
//!
//! The engine is pure — it takes parsed workflows and returns findings. It
//! owns no I/O and no global state, so the CLI can parallelize file
//! processing later without touching this module.

use crate::config::Config;
use crate::finding::Finding;
use crate::input::ParsedWorkflow;
use crate::rules::{Rule, RuleContext, default_rules};

/// The analysis engine: an ordered set of rules applied to parsed workflows.
pub struct Engine {
    rules: Vec<Box<dyn Rule>>,
}

impl Engine {
    /// An engine with the full v1 rule set (R01–R10).
    pub fn with_default_rules() -> Self {
        Self {
            rules: default_rules(),
        }
    }

    /// Evaluate all rules against one parsed workflow.
    ///
    /// Findings are sorted by (severity rank, file, line, rule ID) so output
    /// is deterministic — a requirement for stable snapshots and CI diffs.
    pub fn evaluate(&self, parsed: &ParsedWorkflow, config: &Config) -> Vec<Finding> {
        let ctx = RuleContext {
            workflow: &parsed.model,
            path: &parsed.path,
            config,
            raw: &parsed.raw,
        };
        let mut findings: Vec<Finding> = self
            .rules
            .iter()
            .flat_map(|rule| rule.evaluate(&ctx))
            .collect();
        crate::finding::sort_findings(&mut findings);
        findings
    }
}
