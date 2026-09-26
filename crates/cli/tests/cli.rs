//! End-to-end CLI tests: spawn the real binary against sandboxed repos and
//! assert on exit codes, output shape, and the no-write guarantee.

use std::process::Command;

/// Fixture corpus path, relative to the package root (the test CWD).
const FIXTURES: &str = "../core/tests/fixtures";

fn rivet() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rivet"))
}

/// Build a temp repo with the given fixtures copied into
/// `.github/workflows/`, exercising the real discovery path.
///
/// `fixtures` maps corpus-relative source → destination file name.
fn temp_repo(fixtures: &[(&str, &str)]) -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    let wf_dir = tmp.path().join(".github/workflows");
    std::fs::create_dir_all(&wf_dir).unwrap();
    for (src, dest) in fixtures {
        std::fs::copy(format!("{FIXTURES}/{src}"), wf_dir.join(dest)).unwrap();
    }
    tmp
}

/// Assert a clean run: exit 0, a summary line, no findings.
#[test]
fn clean_repo_exits_zero() {
    let repo = temp_repo(&[
        ("secure/pinned_actions.yml", "a.yml"),
        ("secure/minimal_permissions.yml", "b.yml"),
    ]);
    let out = rivet().arg("--path").arg(repo.path()).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("rivet ·"), "unexpected output: {stdout}");
    assert!(stdout.contains("0 findings"), "unexpected output: {stdout}");
}

#[test]
fn vulnerable_repo_exits_two() {
    let repo = temp_repo(&[("vulnerable/r01_issue_title.yml", "ci.yml")]);
    let out = rivet().arg("--path").arg(repo.path()).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("script-injection"), "{stdout}");
    assert!(stdout.contains("CRITICAL"), "{stdout}");
    assert!(stdout.contains(".github/workflows/ci.yml"), "{stdout}");
}

#[test]
fn fail_on_critical_breaches_on_criticals() {
    let repo = temp_repo(&[("vulnerable/r01_issue_title.yml", "ci.yml")]);
    let out = rivet()
        .args([
            "--path",
            repo.path().to_str().unwrap(),
            "--fail-on",
            "critical",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn fail_on_info_breaches_on_medium_findings() {
    let repo = temp_repo(&[("vulnerable/r05_curl_exfil.yml", "ci.yml")]);
    let out = rivet()
        .args(["--path", repo.path().to_str().unwrap(), "--fail-on", "info"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn quiet_suppresses_output_but_keeps_exit_code() {
    let repo = temp_repo(&[("vulnerable/r01_issue_title.yml", "ci.yml")]);
    let out = rivet()
        .args(["--path", repo.path().to_str().unwrap(), "--quiet"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty(), "quiet mode must print nothing");
}

#[test]
fn json_output_is_a_bare_findings_array() {
    let repo = temp_repo(&[("vulnerable/r01_issue_title.yml", "ci.yml")]);
    let out = rivet()
        .args(["--path", repo.path().to_str().unwrap(), "-o", "json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let stdout = String::from_utf8(out.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let arr = v.as_array().expect("JSON output must be a bare array");
    assert!(!arr.is_empty());
    let item = &arr[0];
    for key in ["rule", "severity", "file", "message", "fix"] {
        assert!(item.get(key).is_some(), "finding missing key {key}");
    }
    // The documented jq pipeline must work: `.[] | select(.severity=="high")`.
    let critical: Vec<_> = arr.iter().filter(|f| f["severity"] == "critical").collect();
    assert!(
        !critical.is_empty(),
        "expected critical findings in JSON output"
    );
}

#[test]
fn recursive_scan_finds_nested_repos() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    for (repo, fixture) in [
        ("api", "vulnerable/r01_issue_title.yml"),
        ("web", "secure/minimal_permissions.yml"),
    ] {
        let dir = root.join(repo).join(".github/workflows");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::copy(format!("{FIXTURES}/{fixture}"), dir.join("ci.yml")).unwrap();
    }
    let out = rivet()
        .args([
            "--path",
            root.to_str().unwrap(),
            "--recursive",
            "-o",
            "json",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("api/.github/workflows/ci.yml"),
        "expected relativized path: {stdout}"
    );
}

#[test]
fn fix_dry_never_writes_files() {
    let tmp = tempfile::tempdir().unwrap();
    let wf = tmp.path().join("ci.yml");
    std::fs::write(
    &wf,
    "on: issues\njobs:\n  b:\n    steps:\n      - run: echo \"${{ github.event.issue.title }}\"\n",
  )
  .unwrap();
    let before = std::fs::read(&wf).unwrap();

    let out = rivet()
        .args(["--path", wf.to_str().unwrap(), "--fix-dry"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("fix"),
        "fix-dry should show fixes: {stdout}"
    );
    assert_eq!(
        std::fs::read(&wf).unwrap(),
        before,
        "fix-dry must not write"
    );
}

#[test]
fn ignore_comment_suppresses_finding() {
    let tmp = tempfile::tempdir().unwrap();
    let wf = tmp.path().join("ci.yml");
    std::fs::write(
        &wf,
        "on: push\npermissions:\n  contents: read\njobs:\n  b:\n    steps:\n      - uses: actions/checkout@v3 # rivet:ignore unpinned-action\n",
    )
    .unwrap();
    let out = rivet().arg("--path").arg(wf).output().unwrap();
    // With a permissions block present, R04 is satisfied — and the
    // suppressed rule must be gone, leaving a clean run.
    assert_eq!(out.status.code(), Some(0), "ignore comment failed");
}

#[test]
fn missing_path_is_a_system_error() {
    let out = rivet()
        .arg("--path")
        .arg("/nonexistent/definitely/not/here")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("error"),
        "expected an error message: {stderr}"
    );
}

#[test]
fn repo_visibility_flag_gates_self_hosted_rule() {
    let tmp = tempfile::tempdir().unwrap();
    let wf = tmp.path().join("ci.yml");
    std::fs::write(
        &wf,
        "on: pull_request\npermissions:\n  contents: read\njobs:\n  b:\n    runs-on: self-hosted\n    steps:\n      - run: echo hi\n",
    )
    .unwrap();
    // Without the flag: silent (visibility unknown), exit 0.
    let out = rivet().arg("--path").arg(&wf).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(
        !String::from_utf8(out.stdout)
            .unwrap()
            .contains("self-hosted-runner")
    );
    // With --repo-visibility public: the MEDIUM finding appears…
    let out = rivet()
        .args([
            "--path",
            wf.to_str().unwrap(),
            "--repo-visibility",
            "public",
        ])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "medium is below the default fail-on threshold"
    );
    assert!(
        String::from_utf8(out.stdout)
            .unwrap()
            .contains("self-hosted-runner")
    );
    // …and breaches once the threshold reaches medium.
    let out = rivet()
        .args([
            "--path",
            wf.to_str().unwrap(),
            "--repo-visibility",
            "public",
            "--fail-on",
            "medium",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}
