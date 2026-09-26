//! Normalized, typed representation of a GitHub Actions workflow.
//!
//! GitHub's YAML schema is loosely typed: `on:` can be a string, a list, or
//! a map; `runs-on` can be a string, a list, or a group object. Rules
//! should not deal with that chaos, so [`crate::parse`] normalizes
//! everything into these types and rules match exhaustively.

use std::fmt;

/// A parsed workflow's domain model.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Workflow {
    /// `name:` — cosmetic, kept for completeness.
    pub name: Option<String>,
    /// The `on:` trigger set, deduplicated.
    pub triggers: Triggers,
    /// Workflow-level environment variables, in file order.
    pub env: Vec<(String, String)>,
    /// Top-level `permissions:`. `None` means the block is absent — which
    /// R04 treats as "defaults to write-all in many org settings".
    pub permissions: Option<Permissions>,
    /// Jobs, in file order.
    pub jobs: Vec<Job>,
}

/// The `on:` trigger set.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Triggers {
    /// Deduplicated and sorted for deterministic rule output.
    pub(crate) events: Vec<TriggerEvent>,
}

/// A single workflow trigger event.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum TriggerEvent {
    PullRequest,
    PullRequestTarget,
    WorkflowRun,
    WorkflowCall,
    Push,
    Schedule,
    /// Any other trigger, kept so the model is lossless.
    Other(String),
}

impl Triggers {
    /// True if the workflow triggers on `event`.
    pub fn contains(&self, event: &TriggerEvent) -> bool {
        self.events.iter().any(|e| e == event)
    }

    /// True for `on: pull_request_target` — runs in the base repo's context
    /// with secrets, the most dangerous trigger in the rule set.
    pub fn pull_request_target(&self) -> bool {
        self.contains(&TriggerEvent::PullRequestTarget)
    }

    /// True for `on: pull_request` — fork-triggered, secrets-free by default.
    pub fn pull_request(&self) -> bool {
        self.contains(&TriggerEvent::PullRequest)
    }

    /// True for `on: workflow_run` — privileged downstream of other workflows.
    pub fn workflow_run(&self) -> bool {
        self.contains(&TriggerEvent::WorkflowRun)
    }
}

/// A single job within a workflow.
#[derive(Debug, Clone, PartialEq)]
pub struct Job {
    /// Job key from the `jobs:` mapping.
    pub id: String,
    /// Where the job runs.
    pub runs_on: RunsOn,
    /// Job-level `permissions:`, overriding the workflow-level block.
    pub permissions: Option<Permissions>,
    /// Job-level environment variables, in file order.
    pub env: Vec<(String, String)>,
    /// Steps, in file order.
    pub steps: Vec<Step>,
}

/// Where a job executes.
#[derive(Debug, Clone, PartialEq)]
pub enum RunsOn {
    /// A single label, e.g. `ubuntu-latest`.
    Label(String),
    /// Alternative labels, e.g. `runs-on: [self-hosted, linux]` — the job
    /// runs if any label matches.
    Labels(Vec<String>),
    /// A runner group, e.g. `runs-on: { group: prod, labels: [linux] }`.
    Group(String, Vec<String>),
}

impl RunsOn {
    /// True if the job may execute on a self-hosted runner (R06).
    pub fn is_self_hosted(&self) -> bool {
        match self {
            RunsOn::Label(l) => l == "self-hosted",
            RunsOn::Labels(ls) | RunsOn::Group(_, ls) => ls.iter().any(|l| l == "self-hosted"),
        }
    }
}

/// A single step.
#[derive(Debug, Clone, PartialEq)]
pub enum Step {
    /// A `run:` step — executes a shell script. The primary attack surface.
    Run {
        /// The script body.
        script: String,
        /// Shell override (`bash`, `pwsh`, …); `None` means the default.
        shell: Option<String>,
    },
    /// A `uses:` step — references an action or reusable workflow.
    Uses {
        /// The action/workflow reference, e.g. `actions/checkout@v4`.
        target: String,
        /// `with:` inputs, in file order.
        with: Vec<(String, String)>,
    },
}

/// A `permissions:` block.
#[derive(Debug, Clone, PartialEq)]
pub struct Permissions {
    /// Granted scopes in file order.
    pub grants: Vec<(Permission, Access)>,
    /// True for `permissions: write-all`.
    pub write_all: bool,
}

/// A GitHub token permission scope.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Permission {
    Actions,
    Checks,
    Contents,
    Deployments,
    IdToken,
    Issues,
    Packages,
    Pages,
    PullRequests,
    RepositoryProjects,
    SecurityEvents,
    Statuses,
    /// A scope rivet doesn't know — kept so the model is lossless.
    Other(String),
}

impl Permission {
    /// Parse a permission name from YAML.
    pub fn parse(s: &str) -> Self {
        match s {
            "actions" => Permission::Actions,
            "checks" => Permission::Checks,
            "contents" => Permission::Contents,
            "deployments" => Permission::Deployments,
            "id-token" => Permission::IdToken,
            "issues" => Permission::Issues,
            "packages" => Permission::Packages,
            "pages" => Permission::Pages,
            "pull-requests" => Permission::PullRequests,
            "repository-projects" => Permission::RepositoryProjects,
            "security-events" => Permission::SecurityEvents,
            "statuses" => Permission::Statuses,
            other => Permission::Other(other.to_owned()),
        }
    }
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Permission::Actions => "actions",
            Permission::Checks => "checks",
            Permission::Contents => "contents",
            Permission::Deployments => "deployments",
            Permission::IdToken => "id-token",
            Permission::Issues => "issues",
            Permission::Packages => "packages",
            Permission::Pages => "pages",
            Permission::PullRequests => "pull-requests",
            Permission::RepositoryProjects => "repository-projects",
            Permission::SecurityEvents => "security-events",
            Permission::Statuses => "statuses",
            Permission::Other(s) => s.as_str(),
        })
    }
}

/// Access level for a permission scope.
///
/// Declaration order is privilege order: `None` < `Read` < `Write`, so the
/// derived `Ord` lets R04 compare a grant against the configured ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Access {
    None,
    Read,
    Write,
}

impl fmt::Display for Access {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Access::None => "none",
            Access::Read => "read",
            Access::Write => "write",
        })
    }
}
