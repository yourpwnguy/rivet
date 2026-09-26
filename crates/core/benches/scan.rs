//! End-to-end scan benchmarks.
//!
//! Measures the hot path — parse + evaluate — over a realistic workflow
//! file, plus the full pipeline across the vulnerable fixture corpus.
//! Run with: `cargo bench -p rivet-core`

use criterion::{Criterion, criterion_group, criterion_main};
use rivet_core::config::Config;
use rivet_core::engine::Engine;
use rivet_core::input::ParsedWorkflow;
use rivet_core::parse::parse_workflow;

/// A workflow exercising every rule: untrusted context in `run:`, a
/// `pull_request_target` checkout, mutable action refs, broad permissions,
/// secrets in scripts, and a self-hosted runner.
const KITCHEN_SINK: &str = include_str!("../tests/fixtures/vulnerable/kitchen_sink.yml");

fn parse_benchmark(c: &mut Criterion) {
    c.bench_function("parse_workflow", |b| {
        b.iter(|| parse_workflow(KITCHEN_SINK).unwrap())
    });
}

fn evaluate_benchmark(c: &mut Criterion) {
    let model = parse_workflow(KITCHEN_SINK).unwrap();
    let parsed = ParsedWorkflow::new(
        std::path::PathBuf::from("kitchen_sink.yml"),
        KITCHEN_SINK.to_owned(),
        model,
    );
    let engine = Engine::with_default_rules();
    let config = Config::default();
    c.bench_function("engine_evaluate", |b| {
        b.iter(|| engine.evaluate(&parsed, &config))
    });
}

fn corpus_benchmark(c: &mut Criterion) {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/vulnerable");
    let mut files: Vec<(String, String)> = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "yml" || e == "yaml") {
            files.push((
                path.file_name().unwrap().to_string_lossy().into_owned(),
                std::fs::read_to_string(&path).unwrap(),
            ));
        }
    }
    let engine = Engine::with_default_rules();
    let config = Config::default();
    c.bench_function("scan_corpus", |b| {
        b.iter(|| {
            let mut total = 0;
            for (_, raw) in &files {
                let model = parse_workflow(raw).unwrap();
                let parsed =
                    ParsedWorkflow::new(std::path::PathBuf::from("w.yml"), raw.clone(), model);
                total += engine.evaluate(&parsed, &config).len();
            }
            total
        })
    });
}

criterion_group!(
    benches,
    parse_benchmark,
    evaluate_benchmark,
    corpus_benchmark
);
criterion_main!(benches);
