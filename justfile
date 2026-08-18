# 🧰 Pingclair's canonical command interface.
#
# CI runs the same recipes a developer runs locally, so a green push is the
# same evidence as a green edit loop. Add a recipe here before wiring it into
# a workflow; the workflow calls are not a second source of truth.

set shell := ["bash", "-uc"]
set positional-arguments

rust := "1.97.1"

# 📖 Show every recipe.
help:
    just -l

# 🎨 Format all Rust sources in place.
fmt:
    cargo +{{ rust }} fmt --all

# 🎨 Fail when formatting differs from rustfmt's output.
fmt-check:
    cargo +{{ rust }} fmt --all -- --check

# 🛡️ Run Clippy over every target with warnings denied.
clippy:
    cargo +{{ rust }} clippy --locked --workspace --all-targets -- -D warnings

# 🧪 Run the full nextest suite without stopping at the first failure.
test *args:
    cargo +{{ rust }} nextest run --locked --no-fail-fast --no-tests pass --profile ci {{ args }}

# 🧹 Fail on unused Cargo dependencies.
shear:
    cargo +{{ rust }} shear --deny-warnings

# 🏗️ Check repository invariants that CI enforces mechanically.
repo-lint:
    python3 scripts/repo_lint/repo_lint.py

# 📚 Check documentation spelling and Markdown structure.
docs-lint:
    codespell
    markdownlint-cli2 "**/*.md"

# ✅ Fast lint-only gate.
lint: fmt-check clippy shear repo-lint docs-lint

# ✅ Full local gate: lint plus tests.
check: lint test

# ✅ The exact gate CI runs for Rust changes.
ci: check bench-smoke

# ⚡ Run all workspace microbenchmarks.
bench *args:
    cargo +{{ rust }} bench --locked --workspace --bench '*' {{ args }}

# ⚡ Prove every benchmark target still compiles and starts.
bench-smoke:
    just bench -- --test

# 🛰️ Run the full HTTP/3 functional matrix against a fresh release binary.
h3:
    cargo +{{ rust }} build --release --locked
    PINGCLAIR_BINARY="${CARGO_TARGET_DIR:-target}/release/pingclair" scripts/test-h3-day28-local.sh
    PINGCLAIR_BINARY="${CARGO_TARGET_DIR:-target}/release/pingclair" scripts/test-h3-cancellation-local.sh
    PINGCLAIR_BINARY="${CARGO_TARGET_DIR:-target}/release/pingclair" scripts/test-h3-client-auth-local.sh

# 💽 Report build-cache disk usage against the repository budget.
disk:
    df -h .
    du -sh target 2>/dev/null || true
    du -sh "$HOME/.cache/pingclair-build" 2>/dev/null || true
    du -sh "$HOME/.cache/pingclair-ci" 2>/dev/null || true

# 📦 Report where persistent CI caches live.
cache-report:
    du -sh "$HOME/.cache/pingclair-build" 2>/dev/null || true
    du -sh "$HOME/.cache/pingclair-ci" 2>/dev/null || true

# 🧰 Install the toolchain CI pins (nextest, shear, audit, docs linters).
install:
    command -v cargo-nextest >/dev/null || cargo install cargo-nextest --locked --version 0.9.143
    command -v cargo-shear >/dev/null || cargo install cargo-shear --locked --version 1.13.4
    command -v cargo-audit >/dev/null || cargo install cargo-audit --locked --version 0.22.2
    command -v codespell >/dev/null || pip3 install --user codespell==2.4.3
    command -v markdownlint-cli2 >/dev/null || npm install --global markdownlint-cli2@0.23.2
