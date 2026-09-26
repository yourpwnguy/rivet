//! End-to-end rule tests over the fixture corpus.
//!
//! Each vulnerable fixture must produce at least one finding from its rule;
//! each secure fixture must produce none (the one exception is the
//! `pull_request_target` metadata-only fixture, which yields an INFO
//! downgrade by design).

use std::collections::HashSet;
use std::path::PathBuf;

use rivet_core::config::{Config, Visibility};
use rivet_core::engine::Engine;
use rivet_core::finding::RuleId;
use rivet_core::input::ParsedWorkflow;
use rivet_core::parse::parse_workflow;

/// Parse + evaluate one fixture with a default config.
fn evaluate_fixture(path: &str) -> Vec<rivet_core::finding::Finding> {
    let raw = std::fs::read_to_string(path).unwrap();
    let model = parse_workflow(&raw).unwrap_or_else(|e| panic!("fixture {path} must parse: {e}"));
    let parsed = ParsedWorkflow::new(PathBuf::from(path), raw, model);
    let engine = Engine::with_default_rules();
    engine.evaluate(&parsed, &Config::default())
}

/// Parse + evaluate with a public-repo visibility (gates R06).
fn evaluate_public(path: &str) -> Vec<rivet_core::finding::Finding> {
    let raw = std::fs::read_to_string(path).unwrap();
    let model = parse_workflow(&raw).unwrap_or_else(|e| panic!("fixture {path} must parse: {e}"));
    let parsed = ParsedWorkflow::new(PathBuf::from(path), raw, model);
    let engine = Engine::with_default_rules();
    let config = Config {
        repo_visibility: Visibility::Public,
        ..Config::default()
    };
    engine.evaluate(&parsed, &config)
}

/// The rule IDs a fixture is expected to trigger.
fn rules_of(findings: &[rivet_core::finding::Finding]) -> HashSet<RuleId> {
    findings.iter().map(|f| f.rule).collect()
}

const VULN_DIR: &str = "tests/fixtures/vulnerable";
const SECURE_DIR: &str = "tests/fixtures/secure";

#[test]
fn r01_fires_on_issue_title() {
    let path = format!("{VULN_DIR}/r01_issue_title.yml");
    assert!(rules_of(&evaluate_fixture(&path)).contains(&RuleId::ScriptInjection));
}

#[test]
fn r02_fires_on_head_checkout() {
    let path = format!("{VULN_DIR}/r02_checkout_head.yml");
    let findings = evaluate_fixture(&path);
    assert!(rules_of(&findings).contains(&RuleId::PullRequestTargetCheckout));
    assert!(
        findings
            .iter()
            .any(|f| f.severity == rivet_core::severity::Severity::High)
    );
}

#[test]
fn r03_fires_on_mutable_tag_and_branch_ref() {
    let tag = format!("{VULN_DIR}/r03_mutable_tag.yml");
    let findings = evaluate_fixture(&tag);
    assert!(rules_of(&findings).contains(&RuleId::UnpinnedAction));
    assert!(
        findings
            .iter()
            .any(|f| f.severity == rivet_core::severity::Severity::Medium)
    );

    let branch = format!("{VULN_DIR}/r03_branch_ref.yml");
    let findings = evaluate_fixture(&branch);
    assert!(
        findings.iter().any(|f| f.rule == RuleId::UnpinnedAction
            && f.severity == rivet_core::severity::Severity::High)
    );
}

#[test]
fn r04_fires_on_missing_permissions_block() {
    let path = format!("{VULN_DIR}/r04_no_permissions.yml");
    assert!(rules_of(&evaluate_fixture(&path)).contains(&RuleId::OverlyBroadPermissions));
}

#[test]
fn r05_fires_on_curl_exfil() {
    let path = format!("{VULN_DIR}/r05_curl_exfil.yml");
    let findings = evaluate_fixture(&path);
    assert!(rules_of(&findings).contains(&RuleId::SecretExfiltration));
    assert!(
        findings
            .iter()
            .any(|f| f.severity == rivet_core::severity::Severity::High)
    );
}

#[test]
fn r06_fires_on_self_hosted_in_public_repo() {
    let path = format!("{VULN_DIR}/r06_self_hosted.yml");
    // Silent when visibility is unknown…
    assert!(!rules_of(&evaluate_fixture(&path)).contains(&RuleId::SelfHostedRunner));
    // …and fires when the repo is declared public.
    assert!(rules_of(&evaluate_public(&path)).contains(&RuleId::SelfHostedRunner));
}

#[test]
fn r07_fires_on_fork_secrets() {
    let path = format!("{VULN_DIR}/r07_fork_secrets.yml");
    let findings = evaluate_fixture(&path);
    assert!(rules_of(&findings).contains(&RuleId::ForkSecretsAccess));
    assert!(
        findings
            .iter()
            .any(|f| f.severity == rivet_core::severity::Severity::Medium)
    );
}

#[test]
fn r08_fires_on_unpinned_reusable_workflow() {
    let path = format!("{VULN_DIR}/r08_unpinned_reusable.yml");
    let findings = evaluate_fixture(&path);
    assert!(rules_of(&findings).contains(&RuleId::ReusableWorkflowPin));
    assert!(
        findings
            .iter()
            .any(|f| f.severity == rivet_core::severity::Severity::Low)
    );
}

#[test]
fn r09_fires_on_debug_logging() {
    let path = format!("{VULN_DIR}/r09_debug_enabled.yml");
    let findings = evaluate_fixture(&path);
    assert!(rules_of(&findings).contains(&RuleId::DebugLogging));
    assert!(
        findings
            .iter()
            .any(|f| f.severity == rivet_core::severity::Severity::Info)
    );
}

#[test]
fn r10_fires_on_workflow_run_artifact() {
    let path = format!("{VULN_DIR}/r10_workflow_run_artifact.yml");
    let findings = evaluate_fixture(&path);
    assert!(rules_of(&findings).contains(&RuleId::ArtifactPoisoning));
    assert!(
        findings
            .iter()
            .any(|f| f.severity == rivet_core::severity::Severity::Medium)
    );
}

#[test]
fn kitchen_sink_fires_every_rule() {
    let path = format!("{VULN_DIR}/kitchen_sink.yml");
    let findings = evaluate_public(&path);
    let rules = rules_of(&findings);
    for expected in [
        RuleId::ScriptInjection,
        RuleId::PullRequestTargetCheckout,
        RuleId::UnpinnedAction,
        RuleId::OverlyBroadPermissions,
        RuleId::SecretExfiltration,
        RuleId::SelfHostedRunner,
        RuleId::ReusableWorkflowPin,
        RuleId::DebugLogging,
        RuleId::ArtifactPoisoning,
    ] {
        assert!(
            rules.contains(&expected),
            "kitchen sink should trigger {expected}"
        );
    }
    // R07 must NOT fire: the triggers are pull_request_target/workflow_run,
    // never plain pull_request.
    assert!(!rules.contains(&RuleId::ForkSecretsAccess));
}

#[test]
fn secure_fixtures_are_clean() {
    for name in [
        "pinned_actions.yml",
        "secrets_via_env.yml",
        "minimal_permissions.yml",
    ] {
        let path = format!("{SECURE_DIR}/{name}");
        let findings = evaluate_fixture(&path);
        assert!(
            findings.is_empty(),
            "{name} should be clean, got {findings:?}"
        );
    }
}

#[test]
fn pr_target_metadata_only_is_info_not_breach() {
    let path = format!("{SECURE_DIR}/pr_target_metadata_only.yml");
    let findings = evaluate_fixture(&path);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule, RuleId::PullRequestTargetCheckout);
    assert_eq!(findings[0].severity, rivet_core::severity::Severity::Info);
}
