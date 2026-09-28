//! rivet — GitHub Actions security auditor.
//!
//! Wiring only: parse args → load config → discover files → parse →
//! evaluate → filter → render → exit. All analysis logic lives in
//! `rivet-core`; all I/O lives in this crate's `discover` and `report`.

mod args;
mod discover;
mod error;
mod exit;
mod report;

use std::collections::BTreeMap;
use std::process::ExitCode;
use std::time::Instant;

use clap::Parser;

use rivet_core::engine::Engine;
use rivet_core::ignore;
use rivet_core::input::ParsedWorkflow;
use rivet_core::parse::parse_workflow;

use crate::args::Args;
use crate::error::CliError;

fn main() -> ExitCode {
    let args = Args::parse();
    match run(&args) {
        Ok(code) => ExitCode::from(code as u8),
        Err(e) => {
            eprintln!("rivet: error: {e}");
            ExitCode::from(1)
        }
    }
}

/// The full pipeline. Returns the process exit code (`0`/`1`/`2`).
fn run(args: &Args) -> Result<i32, CliError> {
    // --list-rules is a standalone mode: print the rule catalog and exit
    // before any scanning happens.
    if args.list_rules {
        report::list::print(report::color_enabled(args.no_color));
        return Ok(0);
    }

    // Config: rivet.yaml at the scan root, CLI flags override file values.
    let mut config = discover::load_config(&args.path)?;
    if let Some(v) = args.repo_visibility {
        config.repo_visibility = v.into();
    }

    let files = discover::discover(&args.path, args.recursive)?;
    let engine = Engine::with_default_rules();

    let start = Instant::now();
    let mut findings = Vec::new();
    let mut had_errors = false;
    let mut jobs = 0usize;
    let mut dirty = 0usize;
    // Parse each file exactly once; the raw text moves into ParsedWorkflow.
    let mut parsed_files = Vec::with_capacity(files.len());
    for file in files {
        match parse_workflow(&file.raw) {
            Ok(model) => {
                jobs += model.jobs.len();
                parsed_files.push(ParsedWorkflow::new(file.path, file.raw, model));
            }
            Err(e) => {
                // "Unknown ≠ safe": an unparseable workflow is a system error.
                had_errors = true;
                eprintln!("rivet: cannot parse {}: {e}", file.path.display());
            }
        }
    }

    let mut workflows_per_repo: BTreeMap<String, usize> = BTreeMap::new();
    for parsed in &parsed_files {
        *workflows_per_repo
            .entry(first_component(&parsed.path))
            .or_default() += 1;
        let file_findings = ignore::apply(parsed, engine.evaluate(parsed, &config));
        if !file_findings.is_empty() {
            dirty += 1;
        }
        findings.extend(file_findings);
    }
    // The engine sorts within each file; sort the combined list so the
    // report reads worst-first regardless of file discovery order.
    rivet_core::finding::sort_findings(&mut findings);
    let elapsed_ms = start.elapsed().as_millis();

    if !args.quiet {
        let stats = report::Stats {
            workflows: parsed_files.len(),
            jobs,
            dirty_workflows: dirty,
            elapsed_ms,
        };
        let workflows: Vec<(String, usize)> = workflows_per_repo.into_iter().collect();
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        let opts = report::RenderOptions {
            stats,
            workflows_per_repo: &workflows,
            format: args.format,
            fail_on: args.fail_on.to_severity(),
            color: report::color_enabled(args.no_color),
            fix_dry: args.fix_dry,
        };
        report::emit(&mut out, &findings, &opts)
            .map_err(|e| CliError::io("cannot write report", e))?;
    }

    Ok(exit::decide(
        &findings,
        args.fail_on.to_severity(),
        had_errors,
    ))
}

/// First path component — the "repo" for table grouping.
fn first_component(path: &std::path::Path) -> String {
    path.components()
        .next()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .unwrap_or_else(|| ".".to_string())
}
