//! rivet-core — the pure analysis engine behind rivet.
//!
//! This crate answers one question — *"can this workflow be abused to
//! steal secrets or run attacker-controlled code?"* — without touching the
//! network, the filesystem (beyond what the caller hands us), or the
//! process exit path:
//!
//! * [`model`] — the normalized workflow representation rules evaluate.
//! * [`parse`] — the single YAML touchpoint (`serde_yaml` → model).
//! * [`rules`] — the `Rule` trait, its context, and the R01–R10 registry.
//! * [`engine`] — orchestration: rules in, sorted findings out.
//! * [`config`] — the `rivet.yaml` schema (visibility, permission ceilings).
//! * [`ignore`] — `# rivet:ignore` suppression.
//!
//! Dependency direction is strictly downward: rules depend on the model and
//! helpers, the engine depends on rules, and nothing depends on the CLI.

pub mod config;
pub mod engine;
pub mod expressions;
pub mod finding;
pub mod ignore;
pub mod input;
pub mod locate;
pub mod model;
pub mod parse;
pub mod refs;
pub mod rules;
pub mod severity;
