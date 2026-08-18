# AGENTS.md - Pingclair

This file is the repository-wide operating contract for coding agents working on Pingclair.It applies regardless of which agent, editor, or development environment is used.Keep this file actionable. Detailed incident history, reproductions, and subsystem archaeology belong in `docs/guardrails/`, not here.

---

## 🧰 Tools first

Use the repository's intended tools before falling back to slower generic workflows.If a common development tool required by this repository is missing, install it rather than silently replacing the workflow with a worse one.

### Canonical command interface

Use `just` as the normal entry point for repository workflows.

Agents should prefer:

```bash
just check
just test
just test -p pingclair-proxy
just test -p pingclair --test integration
just lint
just fix
just fmt
just fmt-check
just ci
just shear
just repo-lint
just docs-lint
just bench
just bench-smoke
just h3
just disk
just cache-report
```

Do not duplicate long Cargo command lines throughout documentation when a `just` recipe can own the behavior.

When tooling behavior changes, update the `justfile` first and keep this document at the level of policy.

### General CLI

Prefer:

- `rg` over `grep -R` for source searches.
- `fd` over `find` for locating files.
- `bat` over `cat` for interactive source inspection.
- `jq` for JSON inspection and transformation.
- `gsed` when GNU `sed` behavior is required.
- `git diff --check` before handoff.

Respect `.gitignore`.

Do not search generated directories such as:

- `target/`;
- persistent Cargo build caches;
- benchmark result caches;
- vendored trees;
- temporary build directories;

unless the task specifically concerns them.

Avoid relying on macOS BSD command behavior in scripts intended for Linux CI.

---

## 🦀 Rust toolchain is exact

CI validation uses Rust **1.97.1**.

The workspace declares Rust 1.97 compatibility, but formal local validation uses the exact CI toolchain:

```bash
cargo +1.97.1 ...
```

`+1.97.1` is not decoration.

Different compiler or rustfmt versions may produce different inference, warnings, formatting, or build results.

Use the exact toolchain for:

- formatting checks;
- Clippy;
- formal builds;
- CI-parity tests;
- release validation.

---

## 🧪 Local tests use nextest

`cargo-nextest` is the default local Rust test runner.

Do not default to `cargo test` while iterating.

Prefer:

```bash
just test -p <changed-crate>
```

then:

```bash
just test
```

near handoff.

The repository's `just test` recipe should use:

```text
cargo nextest run --no-fail-fast
```

with the repository's local nextest profile.

### Cargo test has a narrower role

Use ordinary `cargo test` when:

- checking CI parity;
- running doctests;
- testing behavior specific to Cargo's built-in harness;
- reproducing a failure known to occur only there.

The final CI-parity gate may use:

```bash
just ci
```

which should include the exact Cargo commands CI actually executes.

Do not repeatedly run a full `cargo test --workspace` as an inner development loop.

### Doctests

Nextest does not replace doctests.

When Rust documentation examples change, run the relevant doctests explicitly.

---

## 🔧 Development tools

The repository should provide and prefer these tools.

### `just`

`just` owns repository workflows.

Do not require agents to reconstruct multi-step validation commands from prose.

### `cargo-nextest`

Use for ordinary local tests.

### `cargo-shear`

Use to detect unused Cargo dependencies.

Run:

```bash
just shear
```

before dependency-heavy changes are finalized and in CI.

Unused dependencies are not harmless, especially around TLS, QUIC, and platform-specific native libraries.

### `sccache`

Use `sccache` when available for repeated compatible builds.

Persistent incremental Cargo artifacts and `sccache` solve different problems and may be used together.

Do not assume `sccache` can make an incompatible target/profile/toolchain cache reusable.

### `divan`

Use `divan` for focused Rust microbenchmarks.

Appropriate targets include:

- routing;
- header policy;
- matchers;
- CIDR lookup;
- request-ID handling;
- URI rewriting;
- upstream-key construction;
- hot configuration lookup;
- range parsing;
- compression decisions.

Run:

```bash
just bench-smoke
```

first to verify benchmark targets work.

Run:

```bash
just bench
```

for actual measurement.

Microbenchmarks complement, rather than replace, whole-server `wrk`, `h2load`, QUIC, and VPS measurements.

### `insta` / `cargo-insta`

Use snapshot tests selectively where a structured output is easier to review as a whole than field by field.

Good candidates include:

- Pingclairfile compiler output;
- complex route trees;
- configuration normalization;
- nested matchers;
- TLS policy representation;
- header-policy compilation.

Do not snapshot volatile values merely because snapshot testing is convenient.

Review snapshot changes deliberately.

### `markdownlint-cli2`

Use for Markdown structure and style checks.

Run through:

```bash
just docs-lint
```

### `codespell`

Use for English comments and documentation.

Configure project-specific ignores for valid technical terms, names, French text, and other known false positives.

### Repository-specific lint

Machine-checkable house rules belong in a repository lint tool rather than only in model instructions.

The repository should provide:

```bash
just repo-lint
```

backed by a focused script or tool.

It should enforce rules that can be checked reliably, including where practical:

- file-size limits;
- forbidden TLS dependencies;
- known dependency-tree invariants;
- repository-specific configuration fixture rules;
- prohibited generated or sensitive files;
- obvious house-style violations;
- documentation ownership rules that can be detected mechanically.

Do not implement unreliable source parsing with fragile regular expressions merely to claim a rule is automated.

When normal linting is insufficient, improve the repository lint deliberately.

### Not adopted by default

Do not introduce Bazel merely to copy Codex.

Cargo remains Pingclair's build system.

Do not introduce Dylint until a repository rule genuinely requires Rust semantic analysis that ordinary Clippy or a small repository lint cannot provide.

Tooling must remove work, not manufacture another build system to maintain. 🤡

---

## 💾 Persistent build caches

Expensive Rust builds must reuse persistent build state.

Do not put primary Cargo target directories inside:

- disposable containers;
- temporary directories;
- short-lived build directories;
- ephemeral OrbStack filesystems.

Repeated cold recompilation caused by losing a valid cache is a development-environment defect.

### Separate target caches

Use stable architecture-specific target directories.

Recommended layout:

```text
~/.cache/pingclair-build/
├── macos-aarch64/
├── linux-aarch64/
└── linux-x86_64/
```

Linux x86_64:

```bash
export CARGO_TARGET_DIR="$HOME/.cache/pingclair-build/linux-x86_64"
cargo +1.97.1 build --target x86_64-unknown-linux-gnu
```

Linux arm64:

```bash
export CARGO_TARGET_DIR="$HOME/.cache/pingclair-build/linux-aarch64"
cargo +1.97.1 build --target aarch64-unknown-linux-gnu
```

Native macOS uses its own cache.

Do not copy target trees between incompatible architectures.

### OrbStack

When building in OrbStack:

- keep `CARGO_TARGET_DIR` on persistent storage;
- reuse the same path between runs;
- separate x86_64 and aarch64 caches;
- preserve Cargo registry caches;
- preserve Cargo git dependency caches;
- preserve `sccache` state when used;
- avoid compiling inside disposable container filesystems when persistent storage is available.

Before concluding that a full rebuild is required, check whether any of these changed:

1. `CARGO_TARGET_DIR`;
2. target triple;
3. Rust toolchain;
4. Cargo feature set;
5. build profile;
6. `RUSTFLAGS`;
7. linker settings;
8. build environment;
9. relevant dependency features;
10. cache mount path.

A path change alone can turn a warm build into a cold build.

---

## 💽 Build-cache disk budget

Pingclair's debug, test, release, LTO, and multi-architecture artifacts can consume large amounts of disk.

Observe build-cache size before the machine runs out of space.

Use:

```bash
just disk
```

or inspect manually:

```bash
df -h .
du -sh target 2>/dev/null || true
du -sh "$HOME/.cache/pingclair-build" 2>/dev/null || true
```

### Budget

The normal local build-cache budget is approximately **80 GiB**.

Crossing **100 GiB** is a stop condition unless the retained artifacts are deliberately required for an active benchmark, comparison, or release.

A cache silently reaching 130+ GiB is a workflow failure.

### 🧹 Do not reflexively clean everything

Do not default to:

```bash
cargo clean
```

A full clean destroys useful incremental state and often causes another expensive rebuild immediately afterward.

Before deleting build artifacts:

1. measure what is large;
2. identify the architecture;
3. identify the build profile;
4. identify the owning worktree or task;
5. preserve caches required by current work;
6. remove stale trees selectively.

Good cleanup candidates include:

- abandoned temporary targets;
- caches for deleted worktrees;
- obsolete architecture caches;
- old one-off benchmark builds;
- release or fat-LTO output no longer needed.

Do not delete Cargo registry or git dependency caches merely because a target tree is large.

If normal development repeatedly requires full cleaning, fix the cache layout.

---

## 🗺️ Repository map

Pingclair is a Rust web server and reverse proxy built on Cloudflare Pingora.

It provides:

- a Caddy-like configuration language;
- static file serving;
- reverse proxying;
- load balancing;
- automatic HTTPS;
- HTTP/3 through quiche;
- metrics;
- an admin API;
- hot reload.

Repository baseline:

- workspace version: `0.2.0-dev`;
- Rust edition: 2024;
- minimum Rust: 1.97;
- validation toolchain: 1.97.1;
- upstream: `https://github.com/dorianverlaine/pingclair`.

Workspace crates:

| Crate | Responsibility |
| --- | --- |
| `pingclair` | CLI, process lifecycle, listeners, runtime wiring |
| `pingclair-core` | Shared cross-cutting configuration and routing abstractions |
| `pingclair-config` | Pingclair DSL lexer, parser, adapter, compiler |
| `pingclair-proxy` | Pingora proxy, middleware, load balancing, HTTP/3, metrics |
| `pingclair-static` | Static serving, ranges, compression, streaming |
| `pingclair-tls` | Certificate store, ACME, automatic HTTPS |
| `pingclair-api` | Admin API, authentication, inspection, hot reload |
| `pingclair-plugin` | Plugin infrastructure; unwired pieces are not shipped features |

---

## 🚦 Start every task this way

Before editing:

1. Inspect:

   ```bash
   git status --short --branch
   ```

2. Preserve unrelated user changes.

3. Locate the real execution path.

4. Read the narrowest relevant guardrail.

5. Decide the required verification level.

6. Define one coherent theme for the change.

Relevant guardrails:

```text
docs/guardrails/testing.md
docs/guardrails/config.md
docs/guardrails/tls.md
docs/guardrails/proxy.md
```

`docs/GUARDRAILS.md` is an index, not another place to duplicate rules.

A config type, enum variant, parser entry, or compiler node is not evidence that runtime behavior exists.

Trace the actual request path.

---

## 🔒 Maintainer planning workflow

These files may exist only in the maintainer's local checkout:

- `docs/TODO.md`;
- `docs/STATUS.md`;
- `TRIAGE.md`;
- `docs/CADDYFILE_COMPATIBILITY_MASTER.md`;
- `benchmarks/results/`;
- `.plan-snapshots/`.

Their absence in a public clone is expected.

Do not block a user-scoped task merely because private planning data is absent.

When the maintainer planning files are present:

1. run:

   ```bash
   scripts/snapshot-sensitive-plans.sh start
   ```

2. read the active Day in `docs/TODO.md`;
3. inspect `TRIAGE.md`;
4. inspect `docs/STATUS.md` before changing verification claims;
5. keep unrelated discoveries outside the active diff;
6. record required evidence;
7. finish with:

   ```bash
   scripts/snapshot-sensitive-plans.sh end
   ```

A snapshot validation failure blocks handoff.

Never publish private planning snapshots, TRIAGE contents, private TODO contents, or private benchmark evidence.

---

## 📚 Documentation ownership

These documents own different facts.

Mixing them is a defect.

| Document | Owns |
| --- | --- |
| `AGENTS.md` | Repository-wide agent, coding, style, review, and verification rules |
| `docs/TODO.md` | Maintainer execution plan |
| `docs/STATUS.md` | Verification state and evidence level |
| `TRIAGE.md` | Known defects not currently being worked on |
| `docs/GUARDRAILS.md` | Guardrail index |
| `docs/guardrails/testing.md` | Testing environment and validation failures |
| `docs/guardrails/config.md` | DSL, compiler, and validation invariants |
| `docs/guardrails/tls.md` | TLS, ACME, certificate-store invariants |
| `docs/guardrails/proxy.md` | Proxy lifecycle, H3, streaming, transport invariants |
| `benchmarks/README.md` | Published benchmark methodology and claims |
| `benchmarks/results/` | Local raw verification evidence |
| `CHANGELOG.md` | Upgrade-relevant shipped changes |
| `README*.md` | Current shipped user-facing behavior |

Detailed incident history belongs in the owning guardrail.

Keep the root operating manual concise enough that agents actually follow it.

---

## 📏 Change-size budget

Unless a change is mechanical:

- prefer total diffs below approximately **800 changed lines**;
- keep complex behavioral changes below approximately **500 changed lines**.

If a change exceeds those limits, identify the smallest independently useful stage that can be:

- implemented;
- tested;
- reviewed;
- landed;

without leaving the repository in an incorrect intermediate state.

Do not game the limit with meaningless file movement or generated output.

---

## 📐 File and module size

Large files are maintenance debt.

They increase:

- agent context cost;
- review cost;
- merge conflicts;
- accidental coupling;
- pressure to put unrelated behavior into an already-central file.

### Handwritten implementation and tests

Target handwritten modules at **under 500 LoC**.

Once a file approaches **800 LoC**, do not add substantial new functionality to it.

Prefer a focused sibling module.

Apply the same guidance to substantial handwritten test modules and shell tooling.

### Documentation

Handwritten Markdown should remain focused.

When a technical or operational document approaches **800 lines**, split it by ownership or subsystem unless keeping the material contiguous protects a real invariant.

`AGENTS.md` itself should follow this rule.

### Split by ownership

Good boundaries include:

- parsing;
- validation;
- policy;
- transport;
- lifecycle;
- state;
- storage;
- protocol;
- formatting;
- test harness;
- platform integration.

Do not create meaningless names such as:

```text
part1.rs
part2.rs
misc2.rs
helpers_new.rs
```

merely to satisfy a line count.

Generated files are exempt.

Existing oversized files do not require mechanical rewrites solely because the rule was introduced, but they should stop growing.

---

## 🧠 Keep `pingclair-core` small

Do not use `pingclair-core` as the default destination for concepts that lack an obvious home.

Before adding a new abstraction there, ask whether it belongs to:

- `pingclair-config`;
- `pingclair-proxy`;
- `pingclair-static`;
- `pingclair-tls`;
- `pingclair-api`;
- the top-level `pingclair` runtime;
- a new focused crate.

Code belongs in `pingclair-core` when multiple crates genuinely share the abstraction and placing it elsewhere would invert ownership.

Do not add code to core merely because many crates already depend on it.

---

## 🧱 Change discipline

### One theme

A coherent change should be explainable in one sentence.

If two unrelated sentences are required, split the change.

### Core abstractions

Avoid changing several central abstractions simultaneously.

High-risk examples include:

- `ProxyState`;
- the router;
- `HandlerConfig`;
- `ProxyHttp` lifecycle wiring;
- `H3App`;
- `http_policy.rs`.

### Unrelated findings

Newly discovered unrelated defects belong in TRIAGE when the maintainer workflow is present.

Do not widen the current diff because a nearby fix looks easy.

Exceptions:

- the discovered defect makes the active change incorrect;
- an actively exploited security issue requires immediate action;
- the narrowly defined local performance exception below applies.

### Repeated fixes

Three failed fix attempts for the same problem are a stop sign.

Before attempting a fourth, explain in one sentence why the earlier fixes did not address the root cause.

If that sentence cannot be written, investigate instead of editing again.

---

# 🖋️ House style - non-negotiable

These are standing repository-owner requirements.

They apply to every agent and every change.

---

## 🎯 Emoji everywhere

Every new or modified handwritten source comment or doc comment carries a semantically appropriate emoji.

This applies to comments in:

- Rust;
- Cargo manifests;
- shell;
- configuration;
- other handwritten source files.

Emoji are semantic category markers, not random decoration.

Prefer stable meanings.

Examples:

- 🛡️ safety or invariant;
- 🌊 streaming and flow control;
- 🔐 TLS, credentials, or secrets;
- 🚫 rejection or deny path;
- 🧹 cleanup and teardown;
- 🔁 retry or reuse;
- ⚡ performance;
- 🧪 testing;
- 🧭 routing or navigation;
- 📦 ownership or packaging;
- 🔌 connectivity or transport.

Runtime log messages also carry a stable appropriate emoji.

Emoji do not replace structured fields.

Exempt:

- shebangs;
- license headers;
- generated files;
- machine-required directives.

---

## 📝 Commit style

Commit subjects begin with a semantically appropriate emoji followed by a conventional imperative summary.

The subject describes the resulting change, not the development process.

Commit bodies explain the reason and non-obvious invariants.

Do not narrate every edited file.

---

## ✅ Completion marker has one meaning

`✅` means **completed work**.

It does not mean:

- good;
- correct;
- approved;
- recommended;
- expected.

Use:

- `👍` for approval;
- `📌` for a standing rule;
- `🎯` for a passing property.

Planning checkboxes remain countable:

```text
- [x] completed
- [ ] outstanding
```

Do not turn status markers into decoration.

---

## 🍎 Apple-style comments

Comments and doc comments are English.

They should:

- begin with a capital letter;
- use complete sentences where practical;
- use punctuation;
- explain intent, ownership, constraints, or failure modes;
- avoid narrating what the code visibly does.

Bad:

```rust
// 🔢 Increment the counter.
count += 1;
```

Better:

```rust
// 🛡️ Keep the retry index monotonic so each attempt gets a unique slot.
count += 1;
```

The important rule:

> A comment explains why the code has this shape.

Apple-style navigation labels are encouraged when they improve navigation:

```rust
// MARK: - Routing
```

Do not add section labels mechanically to tiny modules.

---

## 🧠 Explain it the way Feynman would

Descriptive prose should make sense to a smart reader who has not already reverse-engineered the implementation.

This applies to:

- doc comments;
- module headers;
- Markdown;
- commit bodies;
- review explanations;
- design notes.

### Lead with the plain-language idea

Explain behavior before mechanism.

### Prefer concrete failures

Prefer:

> 🌊 A 20 MB response gets buffered whole and can exhaust a small host.

over:

> Memory characteristics are suboptimal.

### Jargon must earn its place

Use jargon because it is precise, not because it sounds architectural.

### Explain surprising constraints

If obvious code would be wrong, say what failure it would cause.

### Do not decorate

Use analogies only when they remove work for the reader.

### Unclear prose is diagnostic

If an invariant cannot be explained clearly, re-read the implementation.

Say plainly when something is:

- uncertain;
- unverified;
- partially implemented;
- known broken.

Confident prose must not outrun evidence.

---

## 🌏 Language

Code, identifiers, comments, commit messages, and runtime log strings remain English.

Chinese project documentation uses Traditional Chinese.

Follow terminology already established in `docs/`.

---

## 🧾 Test live servers with a Pingclairfile

When a test, benchmark, verification run, or reproduction needs a live Pingclair server, configure it with the Pingclair DSL whenever an equivalent exists.

Prefer:

```text
Pingclairfile
```

over JSON.

JSON bypasses the Caddyfile adapter and therefore skips part of the user-facing configuration path.

Treat:

> I had to use JSON here.

as a possible finding.

Ask whether:

- the DSL lacks the required directive;
- the directive parses incorrectly;
- the adapter cannot represent valid runtime configuration.

Use JSON only where there is genuinely no DSL equivalent, and document the exception.

Repository linting should detect live-server JSON fixtures where this can be checked reliably.

---

## 🏎️ Write hot-path code fast the first time

Pingclair is measured in CPU microseconds per request against mature servers.

Performance is a design constraint on new request-path code, not a cleanup phase scheduled for later.

Before a new function enters a request path, answer four questions.

### 1. ⚡ Could configuration have decided this?

If the answer cannot differ between requests, compute it during load or reload.

Examples:

- parsing;
- regex compilation;
- CIDR compilation;
- trust-store construction;
- header lookup tables;
- stable route metadata;
- deterministic policy state.

Repeated request-time work that configuration already determined is a defect.

### 2. 📦 Does it allocate?

Look for:

- temporary `String`;
- temporary `Vec`;
- avoidable `to_string()`;
- avoidable clones;
- values collected only to be immediately iterated.

Borrow where practical.

Precompute shared immutable state when appropriate.

Do not sacrifice clarity for speculative allocation avoidance outside meaningful hot paths.

### 3. 🔒 Does it lock?

A request-path lock needs a reason.

A lock held across `.await` is a defect.

Prefer immutable snapshots and existing `ArcSwap` publication patterns where appropriate.

### 4. 🌊 Is it bounded?

Bodies stream.

Queues have explicit capacity.

Buffers have ceilings.

Consider:

- 20 MB bodies;
- SSE;
- slow readers;
- cancellation;
- upstream teardown;
- downstream disconnects;
- H3 flow control.

"It works on 2 KB" does not prove a body path is correct.

### 📌 Off the request path

Startup, reload, admin, and CLI code optimize primarily for clarity.

Do not transplant hot-path complexity into code that runs once.

---

## ⚡ Fix local performance defects you walk past

Unrelated defects normally remain outside the current change.

A local performance defect may be fixed in the same change only when:

- it is inside code already being edited;
- externally visible behavior does not change;
- no new dependency is required;
- no cross-module redesign is required;
- the payoff is obvious without a separate benchmark campaign.

Examples:

- repeated request work already determined by configuration;
- an avoidable clone in the hot loop being edited;
- a whole response buffered instead of streamed;
- a lock held across `.await`.

If measurement is required to know whether a redesign helps, create a measurement task instead.

---

## 🦀 Rust API design

### Keep APIs small

Prefer private modules and explicit public exports.

Do not expose production APIs merely to make tests easier.

### Make call sites self-documenting

Avoid APIs producing:

```rust
foo(false, None, true, 0)
```

Prefer:

- enums;
- newtypes;
- builders;
- named methods;
- explicit policy types.

### Prefer exhaustive matches

Prefer exhaustive `match` statements for:

- protocol enums;
- configuration enums;
- transport state;
- lifecycle state;
- policy enums.

Avoid wildcard arms when a future variant should require a deliberate decision.

### Document new traits

New traits explain:

- their role;
- ownership;
- lifecycle expectations;
- concurrency requirements;
- implementation invariants.

Do not create a trait around one concrete type without a real abstraction boundary.

### Avoid trivial abstraction

Do not create a helper used once merely to shorten a caller.

Helpers should isolate real:

- invariants;
- ownership;
- behavior;
- duplication;
- lifecycle;
- policy.

---

## 🧪 Test authoring

Tests prove behavior at the layer where the contract exists.

### Prefer integration for runtime behavior

Runtime changes should normally include real-binary or integration coverage.

`pingclair/tests/integration.rs` launches the real compiled binary and performs real localhost HTTP requests.

### Regression tests must regress

A regression test should fail against the broken behavior it prevents.

### Prefer complete assertions

Compare complete structured results when practical instead of asserting many fields separately.

Snapshot testing may be appropriate for stable complex compiler output.

### Reuse test infrastructure

Before adding another:

- process launcher;
- test server;
- certificate generator;
- HTTP client;
- fixture loader;
- port allocator;

look for an existing helper.

Do not expand production public API for testing convenience.

### Large tests

New substantial test modules should use focused sibling files.

Do not allow central implementation files to grow indefinitely because tests are embedded at the bottom.

---

## 👻 Ghost-process trap

Real-binary tests may leave stale listeners after interruption, timeout, panic, or failed cleanup.

A stale process may receive the readiness request after the new binary failed to bind, producing misleading 404, 502, or old behavior.

Before instrumenting routing code, follow:

```text
docs/guardrails/testing.md
```

Check:

1. listener ownership;
2. spawned-child state;
3. binary path;
4. config path;

before debugging application logic.

Never use broad process-killing commands on a machine that may be serving real traffic.

---

## 🧭 Configuration becomes precomputed state once

The configuration path is:

```text
Pingclairfile
→ parser
→ adapter
→ compiler
→ validation
→ PingclairConfig
→ ProxyState
→ request execution
```

Shared validation belongs in the common validation path.

Do not put validation only in the DSL adapter when JSON can bypass it.

A `HandlerConfig` variant or parser entry is not an implementation.

Trace user-facing features through:

1. syntax;
2. parsed form;
3. compiled form;
4. precomputed state;
5. request execution;
6. local responses;
7. proxied responses.

---

## 🚦 Two transports, one policy layer

H1/H2 and H3 are separate execution paths.

### H1/H2

`pingclair-proxy/src/server.rs` owns the Pingora `ProxyHttp` lifecycle.

### H3

`pingclair-proxy/src/quic.rs` owns the HTTP/3 application layer.

`tokio-quiche` owns the QUIC transport responsibilities already provided by the upstream stack.

Do not duplicate transport machinery in application code.

### Shared policy

Behavior needed by both transports should live in or converge through shared policy rather than being implemented twice.

When parity is intentionally not required, say so explicitly.

Read:

```text
docs/guardrails/proxy.md
```

before changing transport, body streaming, or cross-protocol middleware.

---

## 🔐 BoringSSL is a whole-tree commitment

Pingclair's QUIC stack depends on the repository's BoringSSL arrangement.

Do not accidentally introduce a competing OpenSSL tree.

Do not casually add:

- `pingora-openssl`;
- `openssl-sys`;
- reqwest `native-tls`;
- other dependencies that pull incompatible native TLS linkage.

This applies to development dependencies too.

`just repo-lint` and CI should check known forbidden TLS dependencies.

Dependency changes should also run:

```bash
just shear
```

and the relevant dependency-tree checks.

---

## 🌊 Streaming is correctness

Streaming is not a later optimization.

Compression, middleware, retry, observability, static serving, proxying, and protocol adaptation must preserve bounded memory.

Any body-handling change considers:

- large bodies;
- SSE;
- slow clients;
- cancellation;
- partial delivery;
- upstream teardown;
- H3 flow control.

Do not collect a full body merely because it makes middleware easier to implement.

Channels and queues remain bounded.

---

## 🛡️ Security conventions

Misconfiguration fails closed.

Do not silently ignore invalid security policy.

Sensitive data is masked by default in:

- logs;
- metrics;
- admin output;
- diagnostics;
- panic output where applicable.

Sensitive values include:

- authorization headers;
- cookies;
- API keys;
- private keys;
- ACME account credentials.

Treat admin authentication and reload endpoints as security-critical.

Never commit private certificate or account-key material.

---

## 🧬 Serde recursion rule

Recursive types must not use `#[serde(untagged)]`.

Use representations whose recursion behavior is explicit, bounded, and testable.

---

## 🧾 Rejection-note rule

A comment saying an upstream API or alternative was evaluated and rejected must preserve enough evidence to re-check the conclusion.

Record:

- dependency/version;
- symbol or API;
- date;
- concrete reason.

Do not write:

```text
// 🚫 Upstream cannot do this.
```

without evidence.

Stale rejection folklore has already cost this project unnecessary implementation work.

---

## 📖 Documentation changes with code

User-facing documentation changes with the behavior it describes.

Do not intentionally leave prose describing behavior that no longer exists.

Update together when applicable:

```text
README.md
README.zh.md
README.fr.md
CHANGELOG.md
```

Configuration examples may have automated coverage.

Prose often does not.

---

## 🔎 Breaking-change checklist

Before changing observable behavior, inspect applicable surfaces:

- Pingclairfile syntax;
- JSON configuration;
- CLI parameters;
- CLI exit behavior;
- admin API;
- hot reload;
- H1 behavior;
- H2 behavior;
- H3 behavior;
- persisted TLS data;
- certificate precedence;
- renewal behavior;
- metric names;
- metric labels;
- integration fixtures;
- published benchmark claims;
- upgrade behavior.

A private Rust symbol can still implement a public behavior contract.

---

## 🌐 H3 verification

macOS unit tests do not prove Linux linkage or QUIC behavior.

After relevant H3 or TLS dependency changes, run the applicable scripts:

```bash
just h3
```

The recipe should cover the maintained local H3 verification scripts, including:

```text
scripts/test-h3-day28-local.sh
scripts/test-h3-cancellation-local.sh
scripts/test-h3-client-auth-local.sh
```

Use an HTTP/3-capable curl.

Read:

```text
docs/guardrails/proxy.md
docs/guardrails/tls.md
docs/guardrails/testing.md
```

before changing this area.

---

## 🌐 Local proxy environment

The maintainer's macOS environment may have a system proxy at:

```text
127.0.0.1:1082
```

Local integration clients should bypass it where applicable.

Reqwest localhost clients should use `.no_proxy()` when required.

Curl localhost validation should bypass external proxies.

Check proxy behavior before diagnosing localhost traffic as an application defect.

---

## 🐧 Linux and remote verification

Use macOS for the fast edit loop.

Use OrbStack or another Linux environment for Linux-specific validation.

Use the designated remote host only when remote, release, or performance verification is required.

Do not mutate a historical benchmark checkout blindly.

Inspect:

- branch;
- HEAD;
- worktree status;
- running processes;
- occupied ports;

before using an existing remote directory.

Prefer clean validation worktrees.

Use release binaries when verifying:

- performance;
- linking;
- TLS;
- QUIC;
- process lifecycle;
- Linux-specific behavior.

Do not perform expensive fat-LTO builds on constrained shared hosts merely to test ordinary functionality.

---

## 📊 Benchmark hierarchy

Use the smallest benchmark capable of answering the performance question.

### Microbenchmark

Use `divan` through:

```bash
just bench
```

for local algorithms and hot functions.

### Whole-server benchmark

Use the methodology in:

```text
benchmarks/README.md
```

for:

- static throughput;
- proxy throughput;
- latency;
- TLS;
- H2;
- H3;
- resource usage.

Do not convert a microbenchmark win directly into a published server-performance claim.

Do not publish a performance claim without preserving the required evidence.

---

## 📊 Verification evidence

Implemented is not verified.

Use precise states:

1. code exists;
2. local tests pass;
3. Linux/container validation passes;
4. clean Linux or designated remote verification passes;
5. benchmark evidence exists.

Do not promote a claim without evidence.

When the local evidence ledger exists, store runs under:

```text
benchmarks/results/<date>_<commit-prefix>/
```

Record the full commit SHA.

Do not overwrite failed evidence.

Failed runs are evidence too.

---

## 🤖 CI should run only what changed

CI should detect changed paths before launching expensive jobs.

Do not run the entire Rust matrix for unrelated documentation-only changes.

The changed-path policy should remain conservative.

Typical relationships:

```text
docs only
→ docs lint
→ documentation/config example tests when applicable

pingclair-config
→ config tests
→ documentation tests
→ affected integration tests

pingclair-proxy
→ proxy tests
→ integration tests

TLS or H3 paths
→ relevant Rust tests
→ H3/TLS validation

Cargo.toml / Cargo.lock
→ workspace checks
→ cargo-shear
→ dependency guardrails

pingclair-core or shared protocol/policy
→ broader workspace validation
```

When uncertain whether a change affects runtime behavior, run the broader check.

CI optimization must never become an excuse to skip a required invariant.

---

## 🧹 Editing discipline

Preserve unrelated dirty files.

Do not casually run repository-wide formatting in a dirty worktree.

Rustfmt may follow child modules and alter files outside the intended diff.

Format deliberately.

Before handoff:

```bash
git diff --check
```

must pass.

Do not suppress warnings with broad `#[allow(...)]` attributes merely to make CI green.

Fix the problem or document a narrow justified exception.

---

## 📋 Handoff

Use the canonical tooling rather than rebuilding the validation procedure manually.

Typical normal code handoff:

```bash
just fmt-check
just lint
just test
just shear
just repo-lint
just docs-lint
git diff --check
```

Run:

```bash
just ci
```

when CI parity is required.

Run H3, Linux, remote, or performance validation only when the affected subsystem requires it.

Before handoff, verify:

- [ ] 🎯 The change has one coherent theme.
- [ ] 🧹 Unrelated dirty files were preserved.
- [ ] 📏 New and expanded files respect the 500/800 LoC guidance.
- [ ] 🧠 `pingclair-core` did not gain unrelated ownership.
- [ ] ⚡ Request-path work avoids unnecessary repeated computation.
- [ ] 📦 Request-path allocations were considered.
- [ ] 🔒 No lock crosses `.await`.
- [ ] 🌊 Buffers, bodies, channels, and queues remain bounded.
- [ ] 🚦 H1/H2/H3 parity was consciously considered.
- [ ] 🔐 TLS and security invariants remain intact.
- [ ] 🧾 Live-server tests use a Pingclairfile where possible.
- [ ] 🧪 Tests prove behavior at the correct layer.
- [ ] 🦀 Focused nextest tests pass.
- [ ] 🔍 Clippy passes for the required scope.
- [ ] 🧹 `cargo-shear` does not reveal accidental dependency debt.
- [ ] 🤖 Repository-specific lint passes.
- [ ] 📚 Documentation lint passes where applicable.
- [ ] 🏗️ Runtime changes build the real binary.
- [ ] 🧹 `git diff --check` passes.
- [ ] 💾 Active build caches were preserved.
- [ ] 💽 Build-cache usage remains deliberate and below the stop threshold.
- [ ] 📊 Verification claims match the evidence actually collected.
- [ ] 📝 Commit subjects follow house style.

If maintainer planning files are present, complete their snapshot, TRIAGE, status, and evidence workflow before handoff.