# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-09-27

### Added

- Initial release
- Static YAML analyzer for `.github/workflows/*.yml|*.yaml`
- Ten security rules (R01–R10): script injection, pull_request_target
  checkout, unpinned actions, overly broad permissions, secret
  exfiltration, self-hosted runners, fork secrets, unpinned reusable
  workflows, debug logging, artifact poisoning
- Normalized workflow model with exhaustive rule matching
- Terminal report with severity colors, file:line anchors, explanations,
  and fix suggestions
- Bare-array JSON output for jq, code scanning, and ASPM pipelines
- Per-repo summary table for recursive multi-repo scans
- `--fail-on` severity threshold with the `0`/`1`/`2` exit-code contract
- `--quiet` mode for CI gates
- `--fix-dry` mode that previews patches without writing
- `rivet.yaml` config: `repo_visibility` override and `permissions.granted_max`
- `# rivet:ignore <rule-id>` inline suppression
- Fuzz suite pinning the no-panic parser invariant

### Security

- No network code paths; no file writes anywhere in the binary
- Symlink-skipping discovery; 1 MiB file size cap
- Parse errors surface as exit 1 — unknown is not safe
