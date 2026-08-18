# AGENTS.md - Pingclair

This file is the repository-wide operating contract for coding agents. It
applies regardless of which agent, editor, or development environment is
used. Keep it actionable: failure history, reproductions, and subsystem
archaeology belong in `docs/guardrails/`, not here. `CLAUDE.md` spells the
same rules out in more depth and adds the cross-crate picture; where the two
overlap, this file wins.

## 🧰 Tools first

Use the repository's intended tools before falling back to slower generic
workflows. If a common development tool required by this repository is
missing, install it rather than silently replacing the workflow with a worse
one.

### Canonical command interface

`just` owns repository workflows. CI runs the same recipes a developer runs
locally, so a green push is the same evidence as a green edit loop. Do not
duplicate long Cargo command lines in prose when a `just` recipe owns the
behavior.

The canonical gate is `just ci`, which runs formatting, Clippy, cargo-shear,
repository lint, documentation lint, the full nextest suite, and a benchmark
smoke run. Focused recipes:

```text
just fmt              # format Rust sources in place
just fmt-check        # fail when formatting differs
just clippy           # workspace clippy, -D warnings
just test -p <crate>  # nextest for one crate (accepts nextest args)
just lint             # fmt-check + clippy + shear + repo-lint + docs-lint
just check            # lint + test
just ci               # check + bench-smoke; the exact CI gate
just shear            # unused-dependency check
just repo-lint        # mechanical repository invariants
just docs-lint        # codespell + markdownlint
just bench / bench-smoke
just h3               # the three HTTP/3 verification scripts
just disk / cache-report
just install          # install the pinned local tooling
```

### General CLI

- Prefer `rg` over `grep -R`, `fd` over `find`, `bat` over `cat`, `jq` for
  JSON, and `gsed` when GNU `sed` behavior is required.
- Respect `.gitignore`. Do not search generated directories such as
  `target/`, persistent build caches, benchmark result caches, or vendored
  trees unless the task specifically concerns them.
- Avoid relying on macOS BSD command behavior in scripts intended for Linux
  CI, and remember that zsh does not word-split unquoted variables.
- Be patient with long Rust builds; never kill cargo or rustc by PID. The
  Cargo lock is expected to make builds slow.

### Development environment

Installed and preferred tools include `rg`, `fd`, `bat`, `jq`, `gsed`,
`cargo-nextest`, `cargo-watch`, and `just`. When a task is inefficient with
the available tools, prefer a specialized tool and install it when
appropriate: Homebrew for macOS system tools, `cargo install` for Rust
CLIs, npm for Node CLIs, official installers when required. `cargo-watch`
is for continuous checking during development.

## 🦀 Rust toolchain is exact

CI validation uses Rust **1.97.1**; the workspace declares
`rust-version = "1.97"`. Use `cargo +1.97.1` for formatting checks, Clippy,
formal builds, CI-parity tests, and release validation — `+1.97.1` is not
decoration. Different compilers produce different inference, warnings, and
rustfmt line breaking; all-green locally followed by all-red in CI has
happened in both directions (newer-than-CI on 2026-07-29, an older toolchain
in the release image on 2026-08-02).

## 🧪 Local tests use nextest

`cargo-nextest` is the default local and CI test runner. Use `just test`
instead of `cargo test` while iterating; `cargo test` is reserved for
doctests, Cargo-harness-specific behavior, and reproducing a failure known
only in that harness.

When only one crate or test binary changed, run it first:

```bash
just test -p pingclair-proxy
cargo +1.97.1 nextest run -p pingclair --test integration --no-fail-fast
```

Run the full suite before handoff when shared crates, configuration, or
policy code changed. When Rust documentation examples change, run the
relevant doctests explicitly (`cargo +1.97.1 test --doc`), because nextest
does not run them.

## 💾 Persistent build caches

Expensive Rust builds must reuse persistent build state. Keep primary Cargo
target directories out of disposable containers and short-lived build
directories. Use stable architecture-specific caches:

```text
~/.cache/pingclair-build/
├── macos-aarch64/
├── linux-aarch64/
└── linux-x86_64/
```

Use `sccache` when available for repeated compatible builds, and do not copy
target trees between incompatible architectures. Before concluding that a
full rebuild is required, check whether the target dir, target triple,
toolchain, feature set, profile, `RUSTFLAGS`, linker, build environment, or
cache path changed — a path change alone can turn a warm build cold.

### Build-cache disk budget

Observe cache size with `just disk`. The normal budget is about **80 GiB**;
crossing **100 GiB** is a stop condition unless the artifacts are deliberately
required for an active benchmark, comparison, or release. Do not reflexively
run `cargo clean`: measure what is large, identify the architecture and
profile, preserve caches required by current work, and remove stale trees
selectively. Do not delete Cargo registry or git caches merely because a
target tree is large.

## 🚦 Start every task this way

Before editing:

1. Inspect `git status --short --branch`.
2. Preserve unrelated user changes.
3. Locate the real execution path.
4. Read the narrowest relevant guardrail:
   `docs/guardrails/{testing,config,tls,proxy}.md`.
5. Decide the required verification level.
6. Define one coherent theme for the change.

Trace the actual request path: Pingclairfile → parser → adapter → compiler →
validation → `PingclairConfig` → `ProxyState` → request execution → local
response or proxied response. A config type, enum variant, parser entry, or
compiler node is not evidence that runtime behavior exists.

## 🧭 CI (two-layer)

CI is split so PRs get fast signal and `main` gets full verification:

- `blocking-ci.yml` is the merge gate for pull requests and pushes to `main`.
  Its `CI required` job is the **single required status**. It runs the fast
  `rust-ci` (path-aware `just ci` plus the known-flaky retry policy), the
  Docker image build and smoke test, commit checks, security audit,
  cargo-deny, repo checks, codespell, docs lint, and the blob-size policy.
- `postmerge-ci.yml` runs after pushes to `main`: sharded nextest archives on
  x86_64 and aarch64 (four shards each), release-profile clippy, and the
  HTTP/3 suite. `dev.yml` publishes dev binaries and images only after
  postmerge succeeds.
- Runners are `ubuntu-24.04` and `ubuntu-24.04-arm`; the Dockerfile is
  `ubuntu:24.04`, pinned the same way. Third-party actions are SHA-pinned
  with human-readable version comments, and checkouts use
  `persist-credentials: false`.
- `**full-ci**` branches or `workflow_dispatch` can run the full suite before
  merge. See `.github/workflows/README.md` for the workflow map and the rules
  for adding checks.

CI should run only what changed, but never at the cost of a required
invariant. Typical relationships:

```text
docs only          → docs lint, config example tests
pingclair-config   → config tests, documentation tests, affected integration
pingclair-proxy    → proxy tests, integration tests
TLS or H3 paths    → Rust tests + H3/TLS validation
Cargo.toml/lock    → workspace checks, cargo-shear, dependency guardrails
shared core/policy → broader workspace validation
```

When uncertain whether a change affects runtime behavior, run the broader
check.

## 🖋️ House style - non-negotiable

House style is owned by `CLAUDE.md` and is authoritative there: the
`🖋️ House style — non-negotiable` section is the source of truth for emoji
use, commit subjects, `✅` semantics, Apple-style comments, Feynman-style
prose, language, and the Pingclairfile testing rule. Read that section
before writing anything and follow it verbatim; do not re-litigate it here.

## 🏎️ Write hot-path code fast the first time

Pingclair is measured in CPU microseconds per request against mature servers.
Performance is a design constraint on new request-path code, not a cleanup
phase scheduled for later. Before a new function enters a request path,
answer four questions:

1. **⚡ Could configuration have decided this?** Parsing, regex compilation,
   CIDR compilation, trust-store construction, header lookup tables, and
   deterministic policy state belong in `ProxyState`, computed at load or
   reload time. Repeated request-time work that configuration already
   determined is a defect.
2. **📦 Does it allocate?** Look for temporary `String`s and `Vec`s,
   avoidable `to_string()` calls, and values collected only to be iterated
   immediately. Borrow where practical; precompute shared immutable state
   when appropriate. Do not sacrifice clarity for speculative allocation
   avoidance outside meaningful hot paths.
3. **🔒 Does it lock?** A request-path lock needs a reason. A lock held
   across `.await` is a defect. Prefer immutable `ArcSwap` snapshots and the
   existing publication patterns.
4. **🌊 Is it bounded?** Bodies stream, queues have explicit capacity, and
   buffers have ceilings. Consider 20 MB bodies, SSE, slow readers,
   cancellation, upstream teardown, downstream disconnects, and H3 flow
   control. "It works on 2 KB" does not prove a body path is correct.

📌 Off the request path — startup, reload, admin, and CLI code — optimize
primarily for clarity. Startup can afford to be slow and obvious; a handshake
cannot.

## ⚡ Fix local performance defects you walk past

Unrelated defects normally remain outside the current change. A local
performance defect may be fixed in the same change only when it is inside
code already being edited, externally visible behavior does not change, no
new dependency is required, no cross-module redesign is required, and the
payoff is obvious without a separate benchmark campaign. Examples: repeated
request work already determined by configuration, an avoidable clone in the
hot loop being edited, a whole response buffered instead of streamed, or a
lock held across `.await`. If measurement is required to know whether a
redesign helps, create a measurement task instead.

## 🧱 Architecture invariants

- **🔐 BoringSSL is a whole-tree commitment.** Never add `openssl-sys`,
  `pingora-openssl`, or reqwest `native-tls`, including as dev-dependencies.
  `cargo tree -i openssl-sys` must match nothing, and
  `scripts/check-vendored-h2.sh` must pass (the h2 fork is wired through
  `[patch.crates-io]` and a Pingora upgrade could silently drop it).
- **🚦 Two transports, one policy layer.** H1/H2 lives in
  `pingclair-proxy/src/server.rs` (Pingora `ProxyHttp`); H3 lives in
  `pingclair-proxy/src/quic.rs` (`tokio-quiche` owns the transport). Behavior
  needed by both transports converges in `http_policy.rs`; duplicating logic
  across the two is how parity gaps get created. When parity is intentionally
  not required, say so explicitly.
- **🌊 Streaming is correctness.** Compression, middleware, retry,
  observability, static serving, proxying, and protocol adaptation must
  preserve bounded memory. Any body-handling change considers large bodies,
  SSE, slow clients, cancellation, partial delivery, upstream teardown, and
  H3 flow control. Do not collect a full body merely to make middleware
  easier.
- **🧭 Configuration becomes precomputed state once.** The path is
  Pingclairfile → parser → adapter → compiler → validation →
  `PingclairConfig` → `ProxyState` → request execution. Shared validation
  belongs in the common validation path, not only in the DSL adapter.
- **🛡️ Misconfiguration fails closed.** Do not silently ignore invalid
  security policy. Sensitive values (authorization headers, cookies, API
  keys, private keys, ACME credentials) are masked by default in logs,
  metrics, admin output, diagnostics, and panics.
- **🧬 Recursive types never use `#[serde(untagged)]`** — that pattern
  produced a remotely triggerable stack-overflow DoS in this codebase. Use
  explicit, bounded, testable representations.
- **🧾 Rejection notes carry evidence.** A comment saying an upstream API or
  alternative was evaluated and rejected must record the dependency/version,
  symbol, date, and concrete reason. Conclusion-only rejection folklore has
  cost this project unnecessary implementation work.

## 🧠 Keep `pingclair-core` small

Do not use `pingclair-core` as the default destination for concepts that lack
an obvious home. Before adding a new abstraction there, ask whether it
belongs to `pingclair-config`, `pingclair-proxy`, `pingclair-static`,
`pingclair-tls`, `pingclair-api`, the top-level `pingclair` runtime, or a new
focused crate. Code belongs in core when multiple crates genuinely share the
abstraction and placing it elsewhere would invert ownership; do not add code
to core merely because many crates already depend on it.

## 🦀 Rust API design

- Keep APIs small: prefer private modules and explicit public exports; do
  not expose production APIs merely to make tests easier.
- Make call sites self-documenting: prefer enums, newtypes, builders, and
  named methods over `foo(false, None, true, 0)`.
- Prefer exhaustive `match` statements for protocol, configuration, transport,
  lifecycle, and policy enums; avoid wildcard arms that would let a future
  variant pass without a deliberate decision.
- Document new traits: explain their role, ownership, lifecycle, and
  concurrency expectations. Do not create a trait around one concrete type
  without a real abstraction boundary.
- Avoid trivial abstraction: do not create a helper used once merely to
  shorten a caller.
- Discourage `#[async_trait]` and `#[allow(async_fn_in_trait)]` shortcuts;
  prefer native RPITIT trait methods with explicit `Send` bounds.

## 🧪 Test authoring

- Tests prove behavior at the layer where the contract exists. Runtime
  changes should normally include real-binary or integration coverage;
  `pingclair/tests/integration.rs` launches the real compiled binary and
  performs real localhost HTTP requests.
- Some integration tests are load-sensitive rather than flaky in isolation;
  reproduce them with several concurrent full suites, not repeated single
  runs:
  ```bash
  cargo +1.97.1 build --tests -p pingclair
  BIN=$(find target/debug/deps -maxdepth 1 -name 'integration-*' -type f -perm -u+x ! -name '*.d' -exec ls -t {} + | head -1)
  for i in $(seq 1 6); do "$BIN" > /tmp/full_$i.log 2>&1 & done; wait
  ```
- A regression test must fail against the broken behavior it prevents.
- Prefer complete structured assertions (whole objects) over many
  field-by-field checks. Snapshot testing is appropriate for stable complex
  compiler output.
- Reuse existing helpers (process launchers, test servers, certificate
  generators, port allocators) before adding new ones.
- Do not add tests for statically defined values, and do not add negative
  tests for logic that was removed.
- Keep substantial test modules in focused sibling files rather than growing
  central implementation files.

### 👻 Ghost-process trap

Real-binary tests may leave stale listeners after interruption, timeout,
panic, or failed cleanup. A stale process may receive the readiness request
after a new binary failed to bind, producing misleading 404/502/old behavior.
Before debugging application logic, check listener ownership, spawned-child
state, binary path, and config path (see `docs/guardrails/testing.md`).
Never use broad process-killing commands on a machine that may be serving
real traffic. Use dynamic ports and a unique readiness token in every test
drill.

## 🌐 H3 and TLS verification

macOS unit tests do not prove Linux linkage or QUIC behavior. After relevant
H3 or TLS dependency changes, run:

```bash
just h3
```

which covers the three maintained scripts
(`test-h3-day28-local.sh`, `test-h3-cancellation-local.sh`,
`test-h3-client-auth-local.sh`). CI runs the Linux H3 gate post-merge on
`ubuntu-24.04`; a manual Linux box can use `rust:1.97-bookworm` with `cmake`
and `clang`/`libclang-dev` for BoringSSL/bindgen. The H3 client must be a
curl built on ngtcp2/nghttp3 (Homebrew curl provides one; the macOS system
curl does not).

The maintainer's macOS environment may have a system proxy at
`127.0.0.1:1082`. Local integration clients should bypass it: reqwest uses
`.no_proxy()`, curl uses `--noproxy '*'`. Check proxy behavior before
diagnosing localhost traffic as an application defect.

## 🐧 Linux and remote verification

Use macOS for the fast edit loop; use OrbStack or another Linux environment
for Linux-specific validation; use the designated remote host only when
remote, release, or performance verification is required. Inspect branch,
HEAD, worktree status, running processes, and occupied ports before using an
existing remote directory, and prefer clean validation worktrees. Use
release binaries when verifying performance, linking, TLS, QUIC, process
lifecycle, or Linux-specific behavior; do not perform expensive fat-LTO
builds on constrained shared hosts merely to test ordinary functionality.

## 📊 Benchmark hierarchy

Use the smallest benchmark capable of answering the question. Use `divan`
through `just bench` for local algorithms and hot functions, and verify
targets with `just bench-smoke` first. Use the whole-server methodology in
`benchmarks/README.md` for static throughput, proxy throughput, latency,
TLS, H2, H3, and resource usage. Do not convert a microbenchmark win directly
into a published server-performance claim, and do not publish a performance
claim without preserving the required evidence.

## 📊 Verification evidence

Implemented is not verified. Use precise states:

1. code exists;
2. local tests pass;
3. Linux/container validation passes;
4. clean Linux or designated remote verification passes;
5. benchmark evidence exists.

Do not promote a claim without evidence. When the local evidence ledger
exists, store runs under `benchmarks/results/<date>_<commit-prefix>/` with
the full commit SHA, and never overwrite failed evidence — failed runs are
evidence too.

## 📚 Documentation ownership

These documents own different facts; mixing them is a defect:

| Document | Owns |
| --- | --- |
| `docs/TODO.md` | Maintainer execution plan |
| `docs/STATUS.md` | Verification state and evidence level |
| `TRIAGE.md` | Known defects not currently being worked on |
| `docs/GUARDRAILS.md` | Guardrail index |
| `docs/guardrails/*.md` | Environment constraints and implementation rules |
| `benchmarks/README.md` | Published benchmark methodology and claims |
| `benchmarks/results/` | Local raw verification evidence |
| `CHANGELOG.md` | Upgrade-relevant shipped changes |
| `README*.md` | Current shipped user-facing behavior |

Additional ownership semantics that prevent real mistakes:

- `docs/TODO.md` is the v0.2.0 plan, one Day per sitting; it owns what to
  work on. 🔒 Local only.
- `docs/STATUS.md` owns which public claim has evidence behind it, at three
  levels: code exists, local tests pass, verified on clean Linux. 🔒 Local.
- `TRIAGE.md` owns "known and not being worked on right now". Add entries in
  the shape its own "How to add one" section shows
  (`### <severity> · <label>` with date, source, and status) and bump the
  count in the section heading. 🔒 Local and absent from a fresh clone;
  create it rather than reading its absence as permission to fold a stray
  fix into the current diff.
- `docs/CADDYFILE_*.md` are frozen 2026-08-01 audit records, deliberately
  excluded from `documentation.rs` because they are full of configurations
  that must not compile. Do not read them as current behavior — check the
  code.

User-facing documentation changes with the behavior it describes; update
README.md, README.zh.md, README.fr.md, and CHANGELOG.md together when
applicable.

## 🔒 Maintainer planning workflow

These files may exist only in the maintainer's local checkout: `docs/TODO.md`,
`docs/STATUS.md`, `TRIAGE.md`, `docs/CADDYFILE_COMPATIBILITY_MASTER.md`,
`benchmarks/results/`, and `.plan-snapshots/`. Their absence in a public
clone is expected and must not block a user-scoped task. When present, run
`scripts/snapshot-sensitive-plans.sh start` before reading the active Day and
`end` after finishing; a snapshot validation failure blocks handoff. Never
publish private planning snapshots, TRIAGE contents, private TODO contents,
or private benchmark evidence.

## 🧱 Change discipline

- **One theme.** A coherent change is explainable in one sentence; if two are
  required, split it.
- **Size budget.** Unless mechanical, keep diffs below approximately 800
  changed lines (500 for complex behavioral changes). If a change exceeds
  the budget, identify the smallest independently useful stage and land it
  first.
- **Module size.** Target handwritten modules under 500 LoC; once a file
  approaches 800 LoC, do not add substantial new functionality to it.
  Split by ownership (parsing, validation, policy, transport, lifecycle,
  storage, protocol, formatting, test harness).
- **Unrelated findings** belong in `TRIAGE.md`, not the current diff, unless
  the defect makes the active change incorrect or is an actively exploited
  security issue.
- **Repeated fixes.** Three failed attempts at the same problem are a stop
  sign. Before a fourth, explain in one sentence why the earlier fixes did
  not address the root cause.

## 🧹 Editing discipline

Preserve unrelated dirty files. Do not casually run repository-wide
formatting in a dirty worktree — rustfmt may follow child modules and alter
files outside the intended diff. Format deliberately. Before handoff,
`git diff --check` must pass. Do not suppress warnings with broad
`#[allow(...)]` attributes merely to make CI green; fix the problem or
document a narrow justified exception.

## 📋 Handoff

Use the canonical tooling rather than rebuilding validation manually.
Typical handoff:

```bash
just ci
git diff --check
```

Run `just h3` or Linux/remote/performance validation only when the affected
subsystem requires it. Before handoff, verify: one coherent theme; unrelated
dirty files preserved; 500/800 LoC guidance respected; `pingclair-core` did
not gain unrelated ownership; request-path work precomputes, avoids
allocations, holds no lock across `.await`, and stays bounded; H1/H2/H3
parity was consciously considered; TLS and security invariants remain
intact; live-server tests use a Pingclairfile where possible; tests prove
behavior at the correct layer; focused nextest tests pass; clippy, shear,
repo-lint, and docs-lint pass; the real binary builds; `git diff --check`
passes; build caches were preserved; and verification claims match the
evidence actually collected.

## 🚫 Not adopted

Bazel, Windows/macOS build matrices, code signing and R2 distribution, and
self-hosted runners are deliberately out of scope. Do not introduce them to
"match" another project; Cargo remains the build system and Linux is the
shipping platform.
