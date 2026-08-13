# AGENTS.md — Pingclair

This is the operating manual for coding agents working in this repository.
Read it together with the planning documents before changing anything:

- `docs/TODO.md` — the v0.2.0 execution plan, one Day per sitting. Read this
  to know what to work on. 🔒 **Kept local, deliberately not in the
  repository**: it tracks known-but-unfixed weaknesses day by day, and a
  public, prioritised list of unpatched defects in released code is a target
  list. Publish the fix, not the queue. If you are working from a clone and
  this file is missing, that is expected — ask the maintainer for it.
- `TRIAGE.md` — the inbox for problems found while working on something else,
  one entry each with a severity and a status. Read it before starting so you do
  not spend a session re-discovering something already written down, and write
  to it instead of widening the diff in hand; its own "How to add one" section
  shows the shape, and the open count lives in that section's heading rather
  than being left to be tallied. 🔒 **Kept local, deliberately not
  in the repository**: an entry is only useful when it names the exact input
  that breaks something, which makes a well-written one a working reproduction for a
  defect that is by definition still unfixed. Saying the inbox exists is fine —
  that is why this bullet is public. Its contents are not. If you are working
  from a clone and this file is missing, that is expected; ask the maintainer.
- `benchmarks/README.md` — published performance claims and verification
  methodology. The per-run evidence ledger lives locally under
  `benchmarks/results/`, deliberately not committed; do not infer that
  implemented code has passed Linux/VPS validation without a recorded run.
- `docs/GUARDRAILS.md` — a one-page index over `docs/guardrails/`, which holds
  the environment constraints and implementation rules split four ways:
  `testing.md`, `config.md`, `tls.md`, `proxy.md`. Every entry is a real
  failure that already happened once. Read the one or two files your change
  touches before coding — the point of the split is that you no longer have to
  read four hundred lines to find the twelve that apply to you.

## What Pingclair is

Pingclair is a Rust web server and reverse proxy built on Cloudflare Pingora
0.8. It provides a Caddy-like configuration language, static files, reverse
proxying, load balancing, automatic HTTPS, HTTP/3 through quiche, metrics, and
an admin API with hot reload.

- Workspace version: `0.2.0-dev` (unreleased; the newest release tag is `v0.1.7`)
- Rust edition: 2024
- Minimum Rust: **1.97**
- Upstream repository: `https://github.com/dorianverlaine/pingclair`

The workspace has eight crates:

| Crate | Responsibility |
| --- | --- |
| `pingclair` | CLI, process lifecycle, listeners, runtime wiring |
| `pingclair-core` | Shared configuration types, router, basic handlers |
| `pingclair-config` | Pingclair DSL lexer/parser/adapter/compiler |
| `pingclair-proxy` | Pingora proxy, middleware, LB, HTTP/3, metrics |
| `pingclair-static` | Static serving, ranges, compression, streaming |
| `pingclair-tls` | Certificate store, ACME, auto-HTTPS |
| `pingclair-api` | Admin API, auth, inspection, hot reload |
| `pingclair-plugin` | Unwired plugin skeleton; not a shipped feature |

## Start every task this way

1. Run `scripts/snapshot-sensitive-plans.sh start`. It validates every existing
   sensitive-plan snapshot before writing a new one; stop immediately if it
   fails.
2. Read `docs/TODO.md` and work the current Day. One Day per sitting; do not
   merge a 🔨 coding Day with a ✅ verification Day.
3. Read the relevant guardrail file before editing: `docs/guardrails/proxy.md`
   for H3 or anything that streams a response body, `docs/guardrails/tls.md`
   for TLS and dependencies, `docs/guardrails/config.md` for the DSL and the
   compiler, `docs/guardrails/testing.md` for test and verification
   infrastructure.
4. Inspect `git status --short --branch`; preserve existing user changes.
5. Locate the real execution path, not only the config type or AST.
6. Decide the required verification level before editing:
   unit, local real-binary integration, Linux/container, or remote VPS.
7. Record verification evidence locally under `benchmarks/results/`, mark the
   finished Day in `docs/TODO.md`, then run
   `scripts/snapshot-sensitive-plans.sh end`. A failed final checksum validation
   blocks handoff.

### Sensitive planning snapshots

`scripts/snapshot-sensitive-plans.sh` copies `docs/TODO.md` and `TRIAGE.md`
together into the gitignored `.plan-snapshots/` directory with a SHA-256
manifest. It retains the newest 30 complete snapshot sets. Never stage or
publish that directory: the files remain sensitive even though they are backup
copies. Do not bypass a validation failure by deleting or regenerating the
manifest; inspect the named snapshot and recover the intended source first.

Do not mark an item as remotely verified because unit tests or
`cargo test --workspace` pass. The ledger deliberately distinguishes:

- completed and verified on the Linux VPS;
- implemented and locally tested, but still awaiting remote verification;
- not implemented.

## Change budget

A session has a budget, and it is much smaller than what fits in a context
window. These are the limits:

- **One theme per session.** Everything committed should be answerable by the
  same one-sentence description of what the session was for. A session that
  needs two sentences was two sessions.
- **At most one change to a core abstraction per session.** `ProxyState`, the
  router, `HandlerConfig`, the `ProxyHttp` lifecycle wiring, `H3App`,
  `http_policy.rs`. Two at once means neither can be bisected: when something
  breaks next week, the commit that broke it moved two foundations and you
  cannot tell which.
- **Newly discovered problems go to `TRIAGE.md`, never straight into the
  current diff.** The fix will be small and obviously right and it will be
  right there. Write the entry anyway. The exceptions are a security defect
  under active exploitation, and a problem that makes the change in hand wrong
  regardless — nothing else. The file is local and absent from a fresh clone;
  if it is not there, create it rather than treating its absence as permission
  to fold the fix into the diff.
- **Three fix commits in one session is a stop sign.** Before attempting a
  fourth, write down why the first fix was insufficient. Not what the fourth
  fix will be — why the first one did not hold.

  > 🤡 Why this is a rule: this repository is at 95 fixes to 57 features
  > all-time, and 39 to 12 over the last hundred commits. The rate is
  > climbing, which is what tells you the fixes are not landing on the cause.
  > A fourth fix written without that sentence is a guess with three failed
  > guesses behind it, and the reason it feels urgent is exactly the reason it
  > is likely to be wrong.
  >
  > The sentence is cheap and it is the whole mechanism: it either names a
  > cause the first three fixes missed, in which case fix that, or it cannot
  > be written, in which case the problem is not understood yet and the next
  > move is reading, not editing. `scripts/check-fix-ratio.sh` measures the
  > aggregate; this is the same brake at the scale of one sitting.

## Build and test

```bash
cargo build --workspace
cargo test --workspace
cargo test -p pingclair-config
cargo test -p pingclair-proxy
cargo test -p pingclair --test integration -- --nocapture
scripts/test-h3-cancellation-local.sh
```

CI pins Rust 1.97 and runs `cargo fmt --all -- --check`,
`cargo clippy --locked --workspace --all-targets -- -D warnings`,
`cargo build --locked --workspace --verbose`, and
`cargo test --locked --workspace --verbose`.
Before handing off a code change, run at least `cargo test --workspace`; for
changes to startup, listeners, proxying, static files, TLS, or middleware,
also run `cargo build --workspace`.

`scripts/test-h3-cancellation-local.sh` requires a curl build with HTTP/3
support. It uses dynamic TCP/UDP ports and a temporary certificate to verify
real H3 SSE delivery, downstream cancellation, upstream teardown, explicit
trailer rejection, and listener survival without touching the remote VPS.

`pingclair/tests/integration.rs` launches the real compiled binary and makes
real localhost HTTP requests. It is the main end-to-end gate, not a mocked
test.

## The ghost-process trap

Pingclair integration and benchmark tests frequently leave a process holding a
test port after a failed, timed-out, or interrupted run. This can create a very
misleading failure:

1. the new child fails to bind;
2. the readiness request reaches the old listener;
3. the test sees an HTTP response and assumes the new child is ready;
4. assertions fail with an unrelated 404/502 from stale code.

Treat an unexpected fixed response as possible port contamination before
debugging application logic.

### Before a real-binary test

Check the exact ports used by the test:

```bash
# macOS
lsof -nP -iTCP:9098 -sTCP:LISTEN

# Linux
ss -ltnp | grep ':9098'

# Inspect candidate processes without killing anything.
pgrep -af 'pingclair.*run'
```

If a listener exists, resolve its PID and command line. Kill only a confirmed
test process and wait for it to exit. Never use a broad `pkill pingclair` on a
machine that may be serving real traffic.

### Readiness and cleanup rules

- Readiness must check the expected status/body/header or a per-test token.
  “Any HTTP response” is not proof that the spawned child is ready.
- Check `child.try_wait()` while polling so an early bind failure is reported.
- On timeout, kill and `wait()` for the child **before** reading piped
  stdout/stderr to EOF. Reading a live process pipe to EOF blocks forever.
- Keep a `Drop` cleanup guard around every child.
- Prefer dynamically allocated ports for new tests. If a fixed port is
  unavoidable, make ownership checks explicit.
- After an interrupted test run, inspect the port table again.
- The local macOS environment may have a system proxy on `127.0.0.1:1082`.
  Reqwest integration clients must use `.no_proxy()`.

When diagnosing a suspicious localhost failure, use this order:

1. inspect listener ownership;
2. confirm the spawned child is still alive;
3. verify the exact config file and binary path;
4. only then instrument request routing or handler code.

## Linux and remote verification

Use local macOS for the fast edit/test loop. Use Docker or an OrbStack Linux
machine for Linux-only behavior when that is sufficient. Remote verification
runs on the owner's designated benchmark host; the ssh alias for it lives in
the owner's local ssh config, not in this repository.

The historical benchmark checkout on that host holds past validation runs;
benchmark data and the H3 smoke script sit beside it under the same root.

Important: the historical benchmark checkout is a dirty validation workspace. Do
not run `git pull`, `git reset`, `git clean`, or overwrite it blindly. Inspect
its branch, HEAD, status, running processes, and occupied ports first. For a
new verification run, prefer a separate clean clone/worktree or copy the exact
committed source into a new directory. Record the commit hash, command, config,
result path, and date in the local evidence ledger (`benchmarks/results/`,
kept out of the repository) or `benchmarks/README.md`.

Remote testing is required before moving a runtime feature into the
remotely-verified state of the ledger. A remote run should use the release
binary when the change
touches performance, linking, TLS, QUIC, process lifecycle, or Linux behavior.
On small validation hosts, run `scripts/validate-linux-commit.sh` with its
default low-memory release overrides and a persistent
`PINGCLAIR_VALIDATION_TARGET_DIR`; the script records the exact profile in its
metadata. Use the workspace's full fat-LTO release profile for performance
claims and publication artifacts. Do not start a fresh fat-LTO build on the
shared VPS merely to exercise functional behavior.

## Architecture constraints

### HTTP/1.1 and HTTP/2

`pingclair-proxy/src/server.rs` implements Pingora's `ProxyHttp` lifecycle.
Middleware has to be wired into the correct phase:

- request rejection and local responses: `request_filter`;
- upstream selection: `upstream_peer`;
- request mutation: before Pingora clones the upstream request;
- downstream headers: local response construction and `response_filter`;
- proxy failures: `fail_to_connect` / `fail_to_proxy`.

A `HandlerConfig` variant or DSL parser entry alone is not an implementation.
Trace config → compiled type → `ProxyState` precomputation → request execution
→ local and proxied response paths.

### HTTP/3

HTTP/3 is a separate quiche path in `pingclair-proxy/src/quic.rs`. H1/H2
middleware changes do not automatically apply to H3. Explicitly check whether
parity is required and track missing H3 behavior in the TODO.

The QUIC stack and Pingora must share BoringSSL. Do not reintroduce Pingora's
OpenSSL feature: OpenSSL and quiche's BoringSSL collide on libcrypto symbols
and have previously crashed the binary at startup.

Deferred request-body drains must be retried before the H3 event pump, not only
after packet receipt. `recv_body` queues the `Finished` event internally once
the last body bytes are consumed, so a drain that stopped on a full handler
channel would otherwise never see end-of-body and a large POST would hang
forever. `H3App::process_reads` is where that ordering lives.

The transport belongs to `tokio-quiche`: UDP socket, packet parsing, version
negotiation, stateless retry and address validation, connection-ID routing,
GSO, pacing, and per-connection timers. `quic.rs` keeps only the application
layer, as `H3App`, this crate's `ApplicationOverQuic`. An earlier note claimed
tokio-quiche's server accept path was not public; that was wrong, and it cost
this project a hand-written QUIC transport that was deleted in `561d802`.

Two things tokio-quiche does not do, so they stay in the accept loop: the L4
blocklist and the listener's `max_connections`. Request tasks return response
events through bounded channels; preserve that backpressure and never buffer
complete bodies to simplify middleware.

H3 certificates never touch disk. `ConnectionParams` demands a
`TlsCertificatePaths`, but the paths are only handed to the `ConnectionHook`,
and the code that reads them runs only when the hook declines — so a sentinel
path is enough and keys stay in the in-memory `CertTable`. Do not "fix" this by
writing private keys to temporary files. `tokio-quiche` is pinned to `=0.19.1`
because that behavior was read out of its source.

H3 certificates are published through an `ArcSwap` table. The refresh path
uses `TlsManager::peek_pem`, which may read only certificates that already
exist and must never trigger ACME issuance. Ports and the certificate-domain
set are largely captured at startup, even though routes and certificate
contents can be refreshed.

Early data is deliberately disabled because the reverse-proxy path accepts
non-idempotent methods and has no replay protection. Do not enable 0-RTT until
route and method safety policy, replay behavior, and negative tests are
explicit. Any H3 or TLS dependency change requires a Linux release build and
quiche-client smoke coverage for SNI, Alt-Svc, streamed static/proxy bodies,
POST bodies with and without Content-Length, 413, and upstream keepalive.

### Hot paths

**The bar is CPU microseconds per request against the best of its class, and it
shapes new code, not just reviews of old code.** Before a new function goes on a
request path, answer four
questions: could configuration have decided this (then precompute it into
`ProxyState`); does it allocate (borrow, or own it at startup); does it lock,
and does the lock cross an `await` (the second is a defect); is it bounded
(bodies stream, queues have capacity). Off the request path — startup, reload,
admin, CLI — optimise for clarity instead and say so. `CLAUDE.md` carries the
long form.

Performance is a correctness requirement:

- no per-request regex compilation, config parsing, DNS resolution, or
  filesystem canonicalization;
- avoid locks and allocations on request paths when configuration-time
  precomputation is possible;
- stream large request and response bodies;
- never use `tokio::fs` on the static-file request path. Synchronous
  `std::fs` page-cache reads are intentional and measured;
- set and log framework defaults that determine runtime topology, especially
  worker counts and connection-pool sizes.

### Static file security

Static confinement is lexical. `..` escaping the document root must be
rejected without per-request canonicalization. Symlinks inside the root are
followed, matching the Caddy default this project tracks; the document root is
not a security boundary against a user who can plant symlinks.

### TLS and admin API

- Never commit certificate, account-key, or TLS-store material.
- Keep ACME staging and production accounts separate.
- `tls internal` persists an atomic CA certificate/key record below
  `PINGCLAIR_TLS_STORE/internal/authority.json` and publishes the trust anchor
  as `root.crt`. Preserve owner-only private material, deterministic manual →
  internal → ACME precedence, eager startup issuance, and shared H1/H2/H3
  renewal behavior. A corrupt authority must fail closed, never be silently
  replaced.
- Treat `pingclair-api/src/auth.rs` and config reload endpoints as
  security-critical.
- Keep the Linux jemalloc target guard intact.

## Configuration work

Pingclair's configuration language is the Pingclair DSL; its conventional
extensionless filename is `Pingclairfile`, like Caddy's `Caddyfile`. Pingclair
also accepts `*.pingclair`, JSON, and directories of mixed config files. JSON
deserializes directly into `PingclairConfig`.

Upstream address schemes are transport policy: bare addresses and `http://`
select H1, `https://` negotiates H2/H1 with ALPN, `h2c://` selects plaintext
H2-only, and `h2://` selects TLS H2-only. Keep their connection pools isolated.

For every user-facing directive, test all applicable layers:

1. lexer/parser/adapter;
2. compiler output;
3. invalid input;
4. JSON backward compatibility when config types change;
5. runtime behavior with the real binary.

Regexes, CIDRs, and other expensive validation should be compiled once during
configuration load or hot reload. Invalid security policy should fail closed.

## Editing discipline

- Make scoped changes and preserve unrelated dirty files.
- 🍎 Write every source comment and doc comment in English using Apple-style
  prose: begin with a capital letter, use a complete sentence, explain intent
  or constraints instead of restating the code, and end with punctuation.
  Apple-style section labels such as `// MARK: - Routing` are encouraged.
- 🧭 Every new or modified comment in Rust, Cargo, shell, configuration, and
  other code files must include a semantically appropriate emoji. Shebangs,
  generated files, license headers, and machine-required directives are
  exempt.
- 🪵 Runtime log messages must include an appropriate, stable emoji that
  communicates the event category without replacing structured log fields.
  Keep the wording in English.
- 🧾 **Configure test servers with a Pingclairfile, not JSON.** When a test,
  a verification run, or a reproduction needs a running server, write the
  configuration in the DSL and let the adapter compile it. JSON bypasses the
  Caddyfile adapter entirely, so a JSON-configured test exercises roughly half
  the path a user's configuration takes and cannot catch a directive that
  parses into the wrong shape.

  This is also how DSL defects get found. A verification run that has to
  reach for JSON because the DSL cannot express what it needs has discovered
  something — write down which directive was missing or wrong, then fix it.
  Reach for JSON only where the DSL genuinely has no equivalent, and say so.
- ⚡ **Fix performance problems you walk past.** When you are already editing a
  function and notice per-request work that belongs at configuration time, an
  allocation in a hot loop, a clone of something you could borrow, or a lock
  held across an await — fix it in the same change. The cost of a separate
  pass is finding the code again and re-deriving why it is shaped that way,
  which is most of the work.

  The limits: keep the fix inside what you are already touching, and keep it
  provable. A change that alters behaviour is not a performance fix, it is a
  behaviour change and needs its own reasoning. Anything whose payoff you
  cannot demonstrate — a rewrite, a new dependency, a data-structure swap
  across a module boundary — is a measurement task, not a drive-by; note it
  and move on. This repository has already deleted 38,532 lines of vendored
  forks that were plausible and never measured.

  🌊 Two shapes are always worth stopping for, because both have shipped here
  twice: a response body that gets buffered whole instead of streamed, and
  work repeated per request that the configuration already determined.
- ✅ **`✅` marks completed work and nothing else.** Not "good", not
  "correct", not "this is the recommended way" — done, and ideally with the
  commit or test that finished it. Use another emoji for approval (`👍`),
  for a rule that holds (`📌`), or for a passing property (`🎯`). The same
  applies to a planning document's own checkboxes: `- [x]` means shipped,
  `- [ ]` means outstanding, and neither is decoration.

  > 🤡 Why this is a rule: on 2026-08-04 a status sweep counted `✅` to
  > decide which Caddyfile tracking documents were current, concluded that
  > `docs/TODO_CADDYFILE_FIXES.md` had **zero** completed items, and
  > reported that upstream. The document was in fact 43-of-46 done — it
  > tracked completion with `- [x]`, while its `✅` characters meant other
  > things. **A marker that means two things cannot be counted**, and a
  > status document whose status cannot be counted is decoration.
- 📝 Git commit subjects must begin with an appropriate emoji, followed by a
  conventional, imperative summary; for example,
  `✨ feat(proxy): add weighted backup pools` or
  `🐛 fix(test): reap stale integration children`.
- Write Chinese documentation in Traditional Chinese, matching the vocabulary
  already used in `docs/` rather than introducing another variant.
- Update `README.md`, `README.zh.md`, and `README.fr.md` together for
  user-facing behavior.
- Do not run repository-wide formatting casually in a dirty worktree.
  Rustfmt follows child modules and can rewrite untouched files. Format only
  intended files, with child-module formatting disabled when appropriate.
- `git diff --check` must pass.
- Never hide warnings with broad `allow` attributes.

## Documentation ownership

- `docs/TODO.md`: the v0.2.0 execution plan. Day-by-day only — no status,
  no evidence, no reference material.
- `TRIAGE.md`: problems found and deliberately not fixed yet — date, source,
  severity, one line, status. It is not a plan (`docs/TODO.md` is) and not a
  record of what shipped (`CHANGELOG.md` is); the distinction it owns is
  "known, and not being worked on right now". Local, not committed.
- `docs/guardrails/{testing,config,tls,proxy}.md`: environment constraints and
  implementation rules, one file per subsystem. A new rule goes in the file it
  belongs to; `docs/GUARDRAILS.md` is only the index over them and must stay
  that way, or it becomes a fifth file to keep in sync.
- `benchmarks/README.md`: performance claims, methodology, and bugs discovered
  under load. The per-run evidence ledger is local (`benchmarks/results/`),
  not committed.
- `README*.md`: shipped user-facing behavior only.

When a result changes, update the narrowest source of truth and any summary
that would otherwise become misleading. Never move an item to “remote
verified” without preserving enough evidence to reproduce the claim.

# Development Environment

## Available tools

The following tools are installed and should be preferred when appropriate:

### General CLI

- `rg`: use instead of `grep -R` for searching source code
- `fd`: use instead of `find` for locating files
- `bat`: use instead of `cat` for viewing source files
- `jq`: use for JSON parsing and manipulation

### Rust

- `cargo-nextest`: use instead of `cargo test` for running tests **locally**.
  ⚠️ CI still runs `cargo test`, so when the question is "will CI pass", run
  `cargo test` — that is what CI actually executes. Switching CI over is a
  separate, deliberate step with its own TRIAGE entry.
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
