# rivet — Development Tasks
# https://just.systems

# List available commands
default:
    @just --list

# ── Build ────────────────────────────────────────────────────────────────────

# Build in debug mode
build:
    cargo build

# Build optimized release binary
release:
    cargo build --release

# ── Quality ──────────────────────────────────────────────────────────────────

# Run all checks (tests, clippy, formatting)
check: test clippy fmt-check

# Run tests
test:
    cargo test

# Run tests with output
test-verbose:
    cargo test -- --nocapture

# Run clippy lints
clippy:
    cargo clippy --all-targets -- -D warnings

# Check formatting
fmt-check:
    cargo fmt --all -- --check

# Auto-format code
fmt:
    cargo fmt

# ── Scanning ─────────────────────────────────────────────────────────────────

# Audit a repository (pass a path, default ".")
scan *ARGS:
    cargo run -- --path {{ARGS}}

# Audit this repository's own workflows
dogfood:
    cargo run -- --path .

# Preview fixes without writing
fix-dry *ARGS:
    cargo run -- --path {{ARGS}} --fix-dry

# ── Benchmarks ───────────────────────────────────────────────────────────────

# Run benchmarks
bench:
    cargo bench

# ── Documentation ────────────────────────────────────────────────────────────

# Build documentation (check for warnings)
docs-check:
    RUSTDOCFLAGS="-D warnings" cargo doc --no-deps

# ── Clean ────────────────────────────────────────────────────────────────────

# Remove build artifacts
clean:
    cargo clean

# ── Installation ─────────────────────────────────────────────────────────────

# Install locally
install:
    cargo install --path crates/cli

# ── Misc ─────────────────────────────────────────────────────────────────────

# Show project statistics
stats:
    @echo "Lines of code:"
    @find crates -name '*.rs' -exec cat {} + | wc -l
    @echo ""
    @echo "Test count:"
    @cargo test 2>&1 | grep -E "^test result:" | head -1
