# 🧰 Pingclair's canonical command interface.
#
# CI runs the same recipes a developer runs locally, so a green push is the
# same evidence as a green edit loop. Add a recipe here before wiring it into
# a workflow; the workflow calls are not a second source of truth.

set shell := ["bash", "-uc"]
set positional-arguments

rust := "1.98.1"

# 💾 Where cargo actually puts build artifacts for this checkout. Asking cargo
# instead of assuming ./target keeps the H3 recipes working when the target
# directory comes from .cargo/config.toml or CARGO_TARGET_DIR — the caches
# AGENTS.md tells developers to keep outside the checkout.
target-dir := `cargo metadata --format-version 1 --no-deps | jq -r .target_directory`

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
    PINGCLAIR_BINARY="{{ target-dir }}/release/pingclair" scripts/test-h3-22-septembre-2026-local.sh
    PINGCLAIR_BINARY="{{ target-dir }}/release/pingclair" scripts/test-h3-cancellation-local.sh
    PINGCLAIR_BINARY="{{ target-dir }}/release/pingclair" scripts/test-h3-client-auth-local.sh
    # 🧯 The local-failure matrix runs the real binary with a lowered descriptor
    # limit, which is why it cannot live in the in-process H3 test suite.
    PINGCLAIR_BINARY="{{ target-dir }}/release/pingclair" scripts/test-h3-local-resource-failure-local.sh

# 💽 Report build-cache disk usage against the repository budget.
disk:
    df -h .
    du -sh "{{ target-dir }}" 2>/dev/null || true
    du -sh "$HOME/.cache/pingclair-build" 2>/dev/null || true
    du -sh "$HOME/.cache/pingclair-ci" 2>/dev/null || true
    du -sh "$HOME/Library/Caches/pingclair/sccache" 2>/dev/null || true
    du -sh "$HOME/.cache/pingclair/sccache" 2>/dev/null || true
    du -sh benchmarks/results 2>/dev/null || true

# 📁 What the evidence directories hold, largest first.
#
# `benchmarks/results/` is gitignored, so a build tree left inside one is
# invisible until the disk fills; this is the command that makes it visible.
evidence-report:
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ ! -d benchmarks/results ]]; then
      echo "✅ no evidence directories on this machine"
      exit 0
    fi
    du -sm benchmarks/results/* 2>/dev/null | sort -rn | head -20 |
      awk '{ printf "%6d MB  %s\n", $1, $2 }'
    du -sm benchmarks/results | awk '{ printf "%6d MB  %s (total)\n", $1, $2 }'

# 🧹 Remove the build trees evidence runs leave behind, keeping the evidence.
#
# Results and method stay: `RESULT.md`, logs, configurations, scripts. What goes
# is what those runs compiled — a 10 GB `linux-target/` next to a few MB of real
# evidence is how one machine reached 1.8 GiB free without anyone noticing.
# Prints every directory it deletes, and takes an optional root so the behaviour
# can be exercised on a scratch tree.
evidence-sweep root="benchmarks/results":
    #!/usr/bin/env bash
    set -euo pipefail
    root="{{ root }}"
    if [[ ! -d "${root}" ]]; then
      echo "✅ ${root} does not exist on this machine"
      exit 0
    fi
    removed=0
    while IFS= read -r directory; do
      size="$(du -sh "${directory}" | cut -f1)"
      printf '🧹 %s (%s)\n' "${directory}" "${size}"
      rm -rf -- "${directory}"
      removed=$((removed + 1))
    done < <(find "${root}" -maxdepth 3 -type d \
      \( -name target -o -name '*-target' -o -name node_modules -o -name .venv \) \
      -prune -print | sort)
    if [[ "${removed}" -eq 0 ]]; then
      printf '✅ nothing to sweep under %s\n' "${root}"
    else
      printf '🧹 removed %d build director(ies); the evidence files are untouched\n' "${removed}"
    fi

# 📌 `cargo build` is untouched — this is the opt-in for a build whose artifacts
# should be reusable by CI and by the other machines of the same architecture.
# It builds `[profile.ci-test]` because that is the profile CI's test archives
# already use; sharing needs the same compiler arguments, not just the same code.
#
# 🔐 Credentials come from ~/.config/pingclair/cache.env (mode 600), one file per
# machine. AGENTS.md, "Shared build cache", says what belongs in it.
#
# 🧊 Build with the shared cache: this machine's disk first, then R2.
shared-build *args:
    #!/usr/bin/env bash
    set -euo pipefail
    source scripts/cache-env.sh
    exec cargo +{{ rust }} build --locked --profile ci-test {{ args }}

# 🚫 These artifacts are only valid on the machine that produced them, so they
# never enter `sccache/v1/shared` — the prefix the other machines read.
#
# 🧊 Build into a host-specific prefix: benchmarks, `target-cpu=native`, and
# anything that must not be shared.
native-build *args:
    #!/usr/bin/env bash
    set -euo pipefail
    source scripts/cache-env.sh
    export SCCACHE_S3_KEY_PREFIX="sccache/v1/native/$(hostname -s)"
    exec cargo +{{ rust }} build --locked --profile ci-test {{ args }}

# 📊 What the cache has been doing on this machine.
cache-stats:
    #!/usr/bin/env bash
    set -euo pipefail
    source scripts/cache-env.sh
    exec sccache --show-stats

# 🔎 Sample the bucket and report what is inside the artifacts.
#
# 🛡️ Run with --policy shared for the shared bucket (machine paths and
# credentials are both failures) and --policy mac for this machine's own bucket
# (paths are expected there, credentials are not).
cache-audit *args:
    #!/usr/bin/env bash
    set -euo pipefail
    source scripts/cache-env.sh
    exec python3 scripts/cache-audit.py {{ args }}

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
