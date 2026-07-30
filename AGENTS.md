# AGENTS.md — Pingclair

This is the operating manual for coding agents working in this repository.
Read it together with the three planning documents before changing anything:

- `docs/TODO.md` — the v0.2.0 execution plan, one Day per sitting. Read this
  to know what to work on.
- `docs/STATUS.md` — what is already done and **how far it has been verified**.
  This is the source of truth for feature status; do not infer that implemented
  code has passed Linux/VPS validation.
- `docs/GUARDRAILS.md` — environment constraints and implementation rules.
  Every entry is a real failure that already happened once. Read before coding.

## What Pingclair is

Pingclair is a Rust web server and reverse proxy built on Cloudflare Pingora
0.8. It provides a Caddy-like configuration language, static files, reverse
proxying, load balancing, automatic HTTPS, HTTP/3 through quiche, metrics, and
an admin API with hot reload.

- Workspace version: `0.1.7`
- Rust edition: 2024
- Minimum Rust: **1.88**
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

1. Read `docs/TODO.md` and work the current Day. One Day per sitting; do not
   merge a 🔨 coding Day with a ✅ verification Day.
2. Read the relevant section of `docs/GUARDRAILS.md` before touching H3, TLS,
   dependencies, or anything that streams a response body.
3. Inspect `git status --short --branch`; preserve existing user changes.
4. Locate the real execution path, not only the config type or AST.
5. Decide the required verification level before editing:
   unit, local real-binary integration, Linux/container, or remote VPS.
6. Keep `docs/STATUS.md` current when status or evidence changes, and mark the
   finished Day in `docs/TODO.md`.

Do not mark an item as remotely verified because unit tests or
`cargo test --workspace` pass. `docs/STATUS.md` deliberately distinguishes:

- completed and verified on the Linux VPS;
- implemented and locally tested, but still awaiting remote verification;
- not implemented.

## Build and test

```bash
cargo build --workspace
cargo test --workspace
cargo test -p pingclair-config
cargo test -p pingclair-proxy
cargo test -p pingclair --test integration -- --nocapture
scripts/test-h3-cancellation-local.sh
```

CI pins Rust 1.88 and runs `cargo fmt --all -- --check`,
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
machine for Linux-only behavior when that is sufficient. The available remote
host is:

```bash
ssh aqeonet-aliyun-shenzhen
```

The historical benchmark checkout is `/root/pingclair`; benchmark data is
under `/root/bench`, and the H3 smoke script is `/root/h3_test.sh`.

Important: `/root/pingclair` is a historical, dirty validation workspace. Do
not run `git pull`, `git reset`, `git clean`, or overwrite it blindly. Inspect
its branch, HEAD, status, running processes, and occupied ports first. For a
new verification run, prefer a separate clean clone/worktree or copy the exact
committed source into a new directory. Record the commit hash, command, config,
result path, and date in `docs/STATUS.md` or `benchmarks/README.md`.

Remote testing is required before moving a runtime feature into the completed
section of `docs/STATUS.md`. A remote run should use the release binary when the change
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
followed, matching nginx/Caddy defaults; the document root is not a security
boundary against a user who can plant symlinks.

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
- `docs/STATUS.md`: canonical status and verification ledger, plus the
  v0.3+ backlog and ecosystem comparison.
- `docs/GUARDRAILS.md`: environment constraints and implementation rules.
- `docs/AUDIT_NGINX_PARITY.md`: nginx/Caddy parity and production-risk audit.
- `benchmarks/README.md`: performance claims, methodology, raw-result links,
  and bugs discovered under load.
- `README*.md`: shipped user-facing behavior only.

When a result changes, update the narrowest source of truth and any summary
that would otherwise become misleading. Never move an item to “remote
verified” without preserving enough evidence to reproduce the claim.
