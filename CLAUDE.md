# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Read these first

`AGENTS.md` is the operating manual and takes precedence over this file wherever
they overlap. It covers the ghost-process trap, editing discipline (comment
style, emoji conventions, commit subjects), architecture constraints per
subsystem, and documentation ownership. This file adds the command details and
the cross-crate picture that only emerge from reading several files at once.

Four documents own distinct things, and the project treats mixing them as a
defect:

| Document | Owns |
| --- | --- |
| `docs/TODO.md` | The v0.2.0 plan, one Day per sitting. What to work on. |
| `docs/STATUS.md` | What is done and **how far it was verified**. Evidence ledger. |
| `docs/GUARDRAILS.md` | Environment constraints and implementation rules. Every entry is a failure that already happened. |
| `benchmarks/README.md` | Performance claims and methodology. |

Implemented is not verified. `docs/STATUS.md` deliberately separates "code
exists", "local tests pass", and "verified on Linux/VPS"; never promote an item
between those without evidence under `benchmarks/results/<date>_<commit>/`.

## Commands

The local gate is four commands, and **`+1.88.0` is not decoration** — CI pins
that toolchain and the workspace declares `rust-version = "1.88"`. A newer local
compiler has looser inference and different rustfmt line breaking; all-green
locally followed by all-red in CI has already happened.

```bash
cargo +1.88.0 fmt --all -- --check
cargo +1.88.0 clippy --locked --workspace --all-targets -- -D warnings
cargo +1.88.0 build --locked --workspace
cargo +1.88.0 test --locked --workspace
```

Narrower runs:

```bash
cargo +1.88.0 test -p pingclair-proxy                      # one crate
cargo +1.88.0 test -p pingclair --test integration          # one test binary
cargo +1.88.0 test -p pingclair --test integration test_name -- --nocapture
cargo +1.88.0 test -p pingclair-proxy --test h3_end_to_end  # H3 against a real QuicServer
```

`pingclair/tests/integration.rs` spawns the real compiled binary and makes real
localhost requests. It is the main end-to-end gate, not a mocked test — so a
stale listener on a test port produces misleading failures. Read the
ghost-process section of `AGENTS.md` before debugging a suspicious localhost
failure.

Some integration tests are load-sensitive rather than flaky in isolation.
Reproduce with several concurrent full suites, not repeated single runs:

```bash
cargo +1.88.0 build --tests -p pingclair
BIN=$(find target/debug/deps -maxdepth 1 -name 'integration-*' -type f -perm -u+x ! -name '*.d' -exec ls -t {} + | head -1)
for i in $(seq 1 6); do "$BIN" > /tmp/full_$i.log 2>&1 & done; wait
```

### H3 verification

macOS unit tests do not validate linking or QUIC behavior. After any change to
H3 or the TLS dependency tree, run both scripts and the Linux half:

```bash
scripts/test-h3-day28-local.sh              # SNI, Alt-Svc, body sizes, POST, 413, keepalive
scripts/test-h3-cancellation-local.sh       # SSE, downstream cancellation, trailer rejection
```

Both need a curl built with HTTP/3 (`brew install curl` provides one; the system
curl does not). Linux runs in `rust:1.88-bookworm`, which needs `cmake` for
BoringSSL and `clang`/`libclang-dev` for bindgen — without them `boring-sys`
fails in its build script.

macOS has a system proxy on `127.0.0.1:1082`. Reqwest test clients must use
`.no_proxy()`; curl needs `--noproxy '*'`.

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
- Verification evidence goes in `benchmarks/results/<date>_<commit-prefix>/` with
  the full commit SHA recorded. Failed evidence is never overwritten.
