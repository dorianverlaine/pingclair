# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Read these first

`AGENTS.md` is the operating manual and takes precedence over this file wherever
they overlap. It covers the ghost-process trap, editing discipline (comment
style, emoji conventions, commit subjects), architecture constraints per
subsystem, and documentation ownership. This file adds the command details and
the cross-crate picture that only emerge from reading several files at once.

These documents own distinct things, and the project treats mixing them as a
defect:

| Document | Owns |
| --- | --- |
| `docs/TODO.md` | The v0.2.0 plan, one Day per sitting. What to work on — **all of it**, including Caddyfile compatibility, which stopped being a separate track on 2026-08-04. 🔒 Local only. |
| `docs/STATUS.md` | Which public claim has evidence behind it, and where. Three levels: code exists, local tests pass, verified on clean Linux. 🔒 Local only. |
| `TRIAGE.md` | Problems found while working on something else and deliberately left alone: one `### <severity> · <label>` entry each, carrying date, source and status. It owns "known, and not being worked on right now" — which is neither the plan nor the changelog. Add entries in the shape its own "How to add one" section shows, and bump the count in the section heading. 🔒 Local only, and absent from a fresh clone; create it rather than reading its absence as permission to fold a stray fix into the current diff. |
| `docs/guardrails/{testing,config,tls,proxy}.md` | Environment constraints and implementation rules, one file per subsystem. Every entry is a failure that already happened. `docs/GUARDRAILS.md` is the index over them, nothing more. |
| `benchmarks/README.md` | Performance claims and methodology. Raw per-run evidence stays local under `benchmarks/results/`, never committed. |
| `CHANGELOG.md` | What changed between releases, for someone upgrading. Written the same day as the change. |

Two more are 🔒 local reference rather than working documents:
`docs/CADDYFILE_COMPATIBILITY_MASTER.md` answers "does Pingclair support this
Caddy directive"; the other `docs/CADDYFILE_*.md` files are frozen 2026-08-01
audit records, deliberately excluded from `documentation.rs` because they are
full of configurations that must *not* compile. Do not read any of them as
current behavior — check the code.

Implemented is not verified. The verification ledger deliberately separates
"code exists", "local tests pass", and "verified on Linux/VPS"; never promote
an item between those without evidence under
`benchmarks/results/<date>_<commit>/` (kept locally, not committed).

When the maintainer planning files are present, run
`scripts/snapshot-sensitive-plans.sh start` before and `end` after a session;
a snapshot validation failure blocks handoff.

## Commands

The canonical gate is `just ci` — fmt-check, clippy, cargo-shear, repo-lint,
docs-lint, the full nextest suite, and bench smoke — and CI runs the same
recipes. **`+1.97.1` is not decoration**: the workspace declares
`rust-version = "1.97"` and CI pins 1.97.1. A different local compiler —
newer or older — has different inference and rustfmt line breaking;
all-green locally followed by all-red in CI has already happened in both
directions (newer-than-CI on 2026-07-29, an older toolchain in the release
image on 2026-08-02).

```bash
just ci
```

Narrower runs:

```bash
just test -p pingclair-proxy                               # one crate
cargo +1.97.1 nextest run -p pingclair --test integration --no-fail-fast
cargo +1.97.1 nextest run -p pingclair --test integration test_name -- --nocapture
cargo +1.97.1 nextest run -p pingclair-proxy --test h3_end_to_end --no-fail-fast
```

`pingclair/tests/integration.rs` spawns the real compiled binary and makes real
localhost requests. It is the main end-to-end gate, not a mocked test — so a
stale listener on a test port produces misleading failures. Read the
ghost-process section of `AGENTS.md` before debugging a suspicious localhost
failure.

Some integration tests are load-sensitive rather than flaky in isolation.
Reproduce with several concurrent full suites, not repeated single runs:

```bash
cargo +1.97.1 build --tests -p pingclair
BIN=$(find target/debug/deps -maxdepth 1 -name 'integration-*' -type f -perm -u+x ! -name '*.d' -exec ls -t {} + | head -1)
for i in $(seq 1 6); do "$BIN" > /tmp/full_$i.log 2>&1 & done; wait
```

### H3 verification

macOS unit tests do not validate linking or QUIC behavior. After any change to
H3 or the TLS dependency tree, run `just h3` (the three maintained scripts)
and the Linux half:

```bash
scripts/test-h3-day28-local.sh              # SNI, Alt-Svc, body sizes, POST, 413, keepalive
scripts/test-h3-cancellation-local.sh       # SSE, downstream cancellation, trailer rejection
scripts/test-h3-client-auth-local.sh        # mutual TLS, and the SNI/:authority rule that protects it
```

Both need a curl built with HTTP/3 (`brew install curl` provides one; the system
curl does not). CI runs the Linux half post-merge on `ubuntu-24.04`; a manual
Linux box can use `rust:1.97-bookworm`, which needs `cmake` for BoringSSL and
`clang`/`libclang-dev` for bindgen — without them `boring-sys` fails in its
build script.

macOS has a system proxy on `127.0.0.1:1082`. Reqwest test clients must use
`.no_proxy()`; curl needs `--noproxy '*'`.

## CI (two-layer)

The merge gate is `blocking-ci.yml`: it runs the fast `rust-ci` (path-aware
`just ci` plus the known-flaky retry policy), the Docker image build and
smoke test, commit checks, security audit, cargo-deny, repo checks, codespell,
docs lint, and the blob-size policy, then collapses them into one required
status (`CI required`). After pushes to `main`, `postmerge-ci.yml` runs
sharded nextest archives on x86_64 and aarch64, release-profile clippy, and
the HTTP/3 suite; `dev.yml` publishes only after postmerge succeeds. Runners
and the Dockerfile are pinned to Ubuntu 24.04, third-party actions are
SHA-pinned, and `**full-ci**` branches or `workflow_dispatch` can run the
full suite early. See `.github/workflows/README.md` for the workflow map.

## Architecture

### Configuration becomes precomputed state, once

`pingclair-config` turns a Pingclairfile into `PingclairConfig`: `parser/` →
`adapter/caddyfile.rs` (or `adapter/json.rs`) → `compiler.rs`. `compiler.rs`
also owns `validate_config`, which is meant to be the single validation path —
rules belong there rather than in the DSL adapter, or JSON configs bypass them.

At runtime `ProxyState` (`pingclair-proxy/src/server.rs`) holds the compiled
router, per-route load balancers, and other precomputation. It is published
through `ArcSwap`, so a reload swaps a snapshot rather than locking readers.
Anything derived per request that could have been derived at configuration time
is a performance defect, not an optimization opportunity.

A `HandlerConfig` variant or a parser entry is not an implementation. Trace
config → compiled type → `ProxyState` precomputation → request execution → both
the local-response and proxied-response paths.

### Two transports, one policy layer

H1/H2 and H3 are genuinely separate execution paths, and this is the single
biggest source of "fixed it, but only on one protocol":

- **H1/H2** — `pingclair-proxy/src/server.rs` implements Pingora's `ProxyHttp`
  lifecycle. Middleware must land in the correct phase (`request_filter`,
  `upstream_peer`, `response_filter`, `fail_to_proxy`).
- **H3** — `pingclair-proxy/src/quic.rs`. `tokio-quiche` owns the transport
  (socket, retry, connection-ID routing, pacing, timers); `H3App` is this
  crate's `ApplicationOverQuic` and owns only HTTP/3. It does not extend
  Pingora's `Session`.

They converge on `pingclair-proxy/src/http_policy.rs` — CORS evaluation,
response-header policy, `Via`, request-id resolution, URI rewriting. **New
middleware belongs there if both transports need it.** Reaching into an H1/H2
`Session` from H3, or duplicating logic across the two, is how parity gaps get
created; when parity is not required, say so explicitly in `docs/TODO.md`.

Both paths use Pingora's `Connector` for upstreams, so the keepalive pool, TLS
to upstream, and timeout semantics are shared. `HttpPeer::group_key` decides
connection reuse isolation; its own hash does **not** cover `options.ca`, which
is why `upstream_tls.rs` folds trust material into the group key itself.

### BoringSSL is a whole-tree commitment

quiche only runs on BoringSSL and pingora-core defaults to OpenSSL; the two
collide on libcrypto symbols and have crashed the binary at startup. Pingora's
`boringssl` feature, `quiche`, and `boring` must stay on one BoringSSL. Do not
add `pingora-openssl`, `openssl-sys`, or reqwest `native-tls`, including as dev
dependencies. `cargo tree -i openssl-sys` must match nothing.

### Streaming is a correctness property

This project has shipped the same full-body-buffering bug twice (reverse-proxy
gzip, static gzip). Compression, retry, middleware, and observability must all
preserve bounded memory. When adding anything that touches a response body, the
default question is what happens with a 20 MB body, an SSE stream, or a client
that disconnects mid-response. H3 request and response bodies must keep their
bounded channels and QUIC flow control.

## 🧱 Change discipline

- One theme per change; a coherent change is explainable in one sentence.
- Keep diffs under roughly 800 changed lines (500 for complex behavioral
  changes) and split larger work into reviewable stages.
- Modules target under 500 LoC; do not keep adding to files near 800.
  Substantial test modules live in focused sibling files.
- Unrelated findings belong in `TRIAGE.md`, not the current diff.
- Three failed attempts at the same fix are a stop sign: write one sentence
  explaining why the earlier fixes missed the root cause before a fourth.

## 🦀 Rust API design

- Keep APIs small: private modules, explicit public exports, and no
  test-only production surface.
- Prefer enums, newtypes, builders, and named methods over opaque positional
  callsites such as `foo(false, None)`.
- Prefer exhaustive `match` statements for protocol, transport, lifecycle,
  and policy enums.
- Document new traits: their role, ownership, lifecycle, and concurrency
  expectations; do not create a trait around one concrete type without a real
  abstraction boundary.
- Avoid one-off helpers; prefer native RPITIT trait methods with explicit
  `Send` bounds over `#[async_trait]` shortcuts.

## 🧪 Test authoring

- Prefer integration tests for runtime behavior; `pingclair/tests/integration.rs`
  spawns the real binary over localhost with dynamic ports and a unique
  readiness token.
- A regression test must fail without the fix; prefer whole-object assertions;
  do not add tests for statically defined values or for removed logic.
- Reuse existing helpers and keep large test modules in sibling files.
- 👻 Ghost-process trap: a stale listener can answer readiness after a new
  binary fails to bind, producing misleading 404/502/old behavior. Check
  listener ownership, binary path, and config path before debugging
  application logic (see `docs/guardrails/testing.md`).
- Load-sensitive tests reproduce with several concurrent full suites, not
  repeated single runs.

## 🖋️ House style — non-negotiable

These are the repository owner's standing requirements. They apply to every
file, not only to code you happen to be editing heavily.

### 🎯 Emoji everywhere

Every new or modified comment carries a semantically appropriate emoji — in
Rust, Cargo manifests, shell scripts, configuration, and Markdown alike. The
emoji is a category marker, so pick it for meaning and keep it stable for the
same kind of thing: 🛡️ for a safety constraint, 🌊 for streaming and flow
control, 🔐 for TLS and secrets, 🚫 for a rejection path, 🧹 for cleanup, 🔁 for
retry or reuse. Runtime log messages carry one too, and it must not replace a
structured field. Commit subjects open with an emoji followed by a conventional
imperative summary.

Exempt: shebangs, license headers, generated files, and machine-required
directives.

### 🧾 Test with a Pingclairfile

Whenever a test, verification run, or reproduction needs a live server, write
its configuration in the DSL. A JSON-configured server skips `adapter/caddyfile.rs`
completely, so it exercises about half the path a real user's configuration
takes — and every directive that parses into the wrong shape lives in exactly
the half that was skipped.

Treat "I had to use JSON here" as a finding rather than a workaround: the DSL
could not express something a user will eventually want to express. Note which
directive was missing or misbehaving, then fix it. Use JSON only where there is
genuinely no DSL equivalent, and say which case that was.

### 🏎️ Write it fast the first time

This is a web server measured in CPU microseconds per request against the best
of its class — `benchmarks/README.md` holds the methodology and names the
candidates. That target is not an aspiration to be revisited later; it is the
standing constraint on how new code is shaped.
The rule below about fixing problems you walk past is about code that already
exists. This one is about code you are writing now: **the first version should
already have the right shape**, because a request path is not somewhere you get
to iterate — it runs a hundred thousand times a second, and by the time a
profile shows the cost, the shape is load-bearing and three callers deep.

Four questions to answer before a new function goes on a request path:

1. **Could configuration have decided this?** If the answer at request time can
   never differ from the answer at load time, compute it at load time and put it
   in `ProxyState`. Parsing, regex compilation, DNS resolution, path
   canonicalization, trust-store construction, and header-name lookup tables all
   belong there. This is the single most common defect in this codebase.
2. **Does it allocate?** A `String` built to be compared once, a `Vec` collected
   to be iterated once, a `to_string()` before a match — all avoidable. Borrow,
   compare in place, or precompute an owned copy at startup. `Arc<str>` over
   `String` when the value is shared and never mutated.
3. **Does it lock, and does the lock cross an `await`?** Published snapshots go
   through `ArcSwap`, which is why readers never block. A `Mutex` on a request
   path needs a reason written next to it; one held across an `await` is a
   defect, not a trade.
4. **Is it bounded?** Bodies stream, queues have capacity, and buffers have
   ceilings that do not scale with what a client sends. "It works on a 2 KB
   response" is not evidence about a 20 MB one.

Two things this rule is *not*. It is not licence to hand-roll or vendor: this
repository deleted 38,532 lines of forks that were all plausible and none
measured. And it is not licence to complicate — an obvious `O(n)` scan over
three items beats a `HashMap` that has to be built first, and the simpler code
is usually also the faster one. When a fast shape and a clear shape genuinely
conflict on a hot path, take the fast one and write the sentence that explains
why to the next reader.

📌 Off the request path — startup, reload, admin endpoints, the CLI — optimise
for clarity instead, and say so. Startup can afford to be slow and obvious. A
handshake cannot.

### ⚡ Fix performance problems you walk past

While you are already in a function, treat per-request work that configuration
already determined, allocations in a hot loop, an avoidable clone, or a lock
held across an await as part of the change you are making. Coming back later
costs more than the fix does: you have to find the code again and rebuild your
understanding of why it looks that way.

Two limits keep this from becoming scope creep. Stay inside the code you are
already editing. And keep the payoff obvious — if you would need a benchmark to
know whether it helped, it is a measurement task, not a drive-by; say so and
move on. The 38,532 lines of vendored forks this repository deleted were all
plausible and none were measured where the patched component was saturated.

The two shapes worth stopping for either way, because both have shipped here
twice: a response body buffered whole instead of streamed, and work repeated
per request that `ProxyState` could have precomputed.

**`✅` is reserved for completed work.** It is the one emoji in this repository
with a fixed, countable meaning: this is done, ideally naming the commit or the
test that finished it. Do not use it for "good", "correct", "recommended", or
"this rule holds" — reach for `👍`, `📌`, or `🎯` instead. In planning documents
the same discipline applies to checkboxes: `- [x]` is shipped, `- [ ]` is
outstanding.

> 🤡 The cost of getting this wrong, 2026-08-04: a sweep counted `✅` to work
> out which Caddyfile tracking documents were still current, found none in
> `docs/TODO_CADDYFILE_FIXES.md`, and reported it as abandoned. It was
> 43-of-46 complete and tracked with `- [x]`; its `✅` characters meant
> something else entirely. A marker that means two things cannot be counted.

### 🍎 Apple-style comments

Comments are English, complete sentences, capitalized, punctuated. Apple-style
section labels (`// MARK: - Routing`) are encouraged for navigation.

The rule that actually matters: **a comment explains intent or constraint, never
restates the code.** `// Increment the counter` above `count += 1` is noise. Say
why the counter exists, what breaks if it drifts, or which invariant it guards.

### 🧠 Explain it the way Feynman would

Descriptive prose — doc comments, module headers, commit bodies, Markdown, and
the explanations you write back in chat — must be understandable by someone
smart who has not read this code. That means:

- **Lead with the plain-language idea, then the mechanism.** "The paths are
  never opened, so private keys stay in memory" before
  `.zip(params.tls_cert)`.
- **Prefer the concrete over the abstract.** Name the failure. "A 20 MB body
  gets buffered whole and the box OOMs" beats "suboptimal memory
  characteristics."
- **Jargon must earn its place.** Use a term because it is precise, not because
  it sounds expert. If a plain word works, use the plain word.
- **Explain the why, especially for anything surprising.** Every guardrail in
  this repo exists because something broke; write the sentence that lets the
  next reader understand the failure without archaeology.
- **An analogy is worth it only if it removes work for the reader.** Do not
  decorate.
- **If you cannot explain it simply, you do not understand it yet.** A comment
  you cannot write clearly is a signal to go re-read the code, not to write a
  vaguer comment.

Say plainly when something is uncertain, unverified, or known-broken. Confident
prose over shaky evidence is the failure mode this repository guards against
hardest — see the rejection-note rule below.

### 🌏 Language

Chinese documentation is written in Traditional Chinese; match the vocabulary
and phrasing already used in `docs/` rather than introducing another variant.
Code, identifiers, commit messages, and log strings stay English.

## Conventions worth knowing before the first edit

- Misconfiguration fails closed. Silently ignoring a bad setting is a defect.
- Sensitive fields (`Authorization`, `Cookie`, API keys) are masked by default in
  logs, metrics, admin dumps, and panic messages.
- Recursive types must not use `#[serde(untagged)]` — that pattern produced a
  remotely triggerable stack-overflow DoS in this codebase.
- A "we evaluated and rejected X" comment must record which version, which
  symbol, and what date. A conclusion-only rejection note once cost this project
  a hand-written QUIC transport that turned out to be unnecessary.
- Documentation changes the same day as the code. Examples and fenced config
  blocks in READMEs and `docs/` are compiled by
  `pingclair-config/tests/documentation.rs`, so a stale config block fails tests
  — but stale prose does not, and has gone unnoticed for days.
- Verification evidence goes in `benchmarks/results/<date>_<commit-prefix>/` —
  kept locally, not committed — with the full commit SHA recorded. Failed
  evidence is never overwritten.

## 🐧 Linux and remote verification

- Use macOS for the fast edit loop; OrbStack or another Linux environment for
  Linux-specific validation; the designated remote host only for remote,
  release, or performance verification.
- Inspect branch, HEAD, worktree status, running processes, and occupied
  ports before reusing a remote directory; prefer clean validation worktrees.
- Use release binaries when verifying performance, linking, TLS, QUIC,
  process lifecycle, or Linux-specific behavior; avoid fat-LTO builds on
  constrained shared hosts.

## 📊 Benchmarks

- Use `divan` through `just bench` for microbenchmarks and
  `just bench-smoke` to prove targets start; the whole-server methodology
  lives in `benchmarks/README.md`.
- Do not turn a microbenchmark win into a published server-performance claim
  without evidence under `benchmarks/results/`.

## 🚫 Not adopted

Bazel, Windows/macOS build matrices, code signing and R2 distribution, and
self-hosted runners are deliberately out of scope; do not introduce them to
"match" another project.

# Development Environment

## Available tools

The following tools are installed and should be preferred when appropriate:

### General CLI

- `rg`: use instead of `grep -R` for searching source code
- `fd`: use instead of `find` for locating files
- `bat`: use instead of `cat` for viewing source files
- `jq`: use for JSON parsing and manipulation

### Rust

- `cargo-nextest`: the default runner for `just test`. CI runs the same
  nextest recipes through the two-layer gates, so `just ci` is CI parity.
- `cargo-watch`: use for continuous checking during development

### Text processing

- `gsed`: use when GNU sed behavior is needed, especially for portable Linux-style scripts.
- Avoid relying on macOS BSD sed differences when writing scripts intended for Linux CI.

## Tool selection

When a task is inefficient with available tools:

1. Consider whether a specialized tool exists.
2. If the tool is commonly used in software development, install it when appropriate.
3. Prefer:
   - Homebrew for macOS system tools
   - cargo install for Rust CLI tools
   - npm for Node.js CLI tools
   - official installers when required

## Preferences

- Prefer fast specialized tools over traditional Unix tools when available.
- Respect `.gitignore` when searching source files.
- Avoid searching generated directories such as `target/` unless explicitly needed.
