# ⚠️ Pingclair implementation guardrails — proxy, HTTP/3, and streaming

## 🚀 HTTP/3 implementation guardrails

### Why H3 is pinned to quiche/BoringSSL (stop re-asking this)

**Pingora does not provide H3, and will not in the near term.** Checked
2026-07-27:

| Upstream | Status |
|---|---|
| [pingora#95](https://github.com/cloudflare/pingora/issues/95) HTTP3/QUIC Support | Opened 2024-03-02, **still open**, officially labelled **`Long Term Goal`** ("plan to support but not likely in the near future") |
| [pingora#514](https://github.com/cloudflare/pingora/pull/514) server/listener side quiche::h3 | +3,449 lines across 30 files, opened 2025-01-16, **unmerged**, stalled since 2025-08-27 |
| [pingora#524](https://github.com/cloudflare/pingora/pull/524) client/connector side | +6,548 lines across 52 files, opened 2025-02-03, **unmerged**, stalled since 2025-02-07 |

The community finished the server side and it has hung there for a year and a
half. "Wait for upstream" is therefore not an option with a date on it.

**The structural obstacle is the TLS backend, not the volume of work.** quiche
runs only on BoringSSL/QuicTLS, pingora-core defaults to OpenSSL, and the two
collide on symbols directly. Having H3 means pinning **the entire dependency
tree** to BoringSSL — a global, irreversible architectural decision, not a
feature flag. All three prohibitions in the "dependencies and linking" section
follow from it.

> 🚨 **A "we evaluated and rejected it" comment with no verifiable basis is worse
> than no comment at all.** `Cargo.toml` once read "tokio-quiche was evaluated and
> rejected: its server-side accept API is pub(crate)". **That sentence was
> wrong**, and wrong in the most damaging way: it stopped everyone after it from
> looking. Only the internal `quic::start_listener()` is `pub(crate)`; the public
> facade was there all along — measured against `tokio-quiche 0.19.1` on
> 2026-07-30: `tokio_quiche::listen()` (`lib.rs:191`), `ServerH3Driver`,
> `ServerH3Controller`, `InitialQuicConnection`, and `ApplicationOverQuic` are all
> public. The dependency versions lined up exactly too (`quiche 0.29.3` +
> `boring 4.22.0`, no `openssl-sys`).
>
> **The cost has already been paid**: that sentence is why this project
> hand-wrote and maintained an entire QUIC transport layer — socket loop,
> connection map, timers, version negotiation, stateless retry, and token
> validation, roughly 500 lines. All of it was deleted on 2026-07-30 and replaced
> with `tokio-quiche` (`ba37ffc`).
>
> **The rule for writing a rejection note**: record **which version, which symbol,
> and what date**. A conclusion-only rejection note becomes a door nobody dares
> push.

> ⚠️ **What it would take to move back to Pingora's native H3**: #514 merged into
> a released crate, H3 integration tests in `pingora-proxy`, and a BoringSSL
> linking arrangement compatible with the current one. Missing any one of the
> three means do not touch it — the price is rewriting all of `quic.rs`.

### Architecture

> 📌 **2026-07-30 (`ba37ffc`) replaced the transport layer.** What follows
> describes the state after that change; the hand-written UDP loop and lock-free
> connection map no longer exist.

- **The dividing line is transport versus application.** `tokio-quiche` owns the
  UDP socket, packet parsing, version negotiation, stateless retry and address
  validation, connection-ID routing, GSO, pacing, and per-connection timers.
  `pingclair-proxy/src/quic.rs` keeps only the application layer.
- Each connection is driven by `H3App`, this project's implementation of
  `ApplicationOverQuic`. **It is not an extension of Pingora's `ProxyHttp`
  `Session`.**
- **The two things `tokio-quiche` does not handle stay in the accept loop**: the
  L4 blocklist and the listener's `max_connections`. The connection count is
  released by `ConnectionSlot` on drop, so it decrements when the worker task
  ends, not when the accept loop moves on.
- Certificates **never touch disk**. `ConnectionParams` requires a
  `TlsCertificatePaths`, but that set of paths is only handed to `ConnectionHook`;
  the branch that actually reads files, `quiche_config_with_tls`, runs only when
  the hook returns `None`. So we pass the fake path `IN_MEMORY_CERT_SENTINEL` and
  the certificates stay in memory in `CertTable`. **Never write a private key to a
  temporary file to satisfy a type** — that is a security regression, not a
  workaround.
- Middleware parity comes from extracting **transport-neutral logic** (see
  `http_policy.rs`); never force an H1/H2 Session into H3.

> ⚠️ **`tokio-quiche` is pinned to `=0.19.1`.** The "certificates never touch
> disk" rule above depends on `.zip(params.tls_cert)` at
> `settings/config.rs:122` and the file-reading branch at `settings/config.rs:224`
> in the 0.19.1 source. One minor version bump could start genuinely reading
> those paths. Upgrading **requires re-reading both sites first** and confirming
> that `pingclair-proxy/tests/h3_in_memory_certs.rs` still fails when it should.

### Correctness

- **A request-body drain must be retried before the pump, and must not be driven
  by packet arrival alone.** `h3::Connection::recv_body` only queues `Finished`
  internally once the last body segment is consumed, so a drain aborted because
  the handler channel was full will never see the end signal unless it is retried
  — and a large POST **hangs forever**. This is now guaranteed by
  `H3App::process_reads`: it retries the streams in `body_read_pending` first,
  then calls `pump_h3_events`. (The old structure was "pump on both packet
  arrival and the maintenance pass"; the maintenance pass went away with the
  hand-written loop, but the requirement did not change.)
- The H3 certificate table is published through `ArcSwap`, reading existing
  certificates through `TlsManager::peek_pem` and refreshing every 60 seconds.
  **`peek_pem` must never trigger ACME issuance.**
- 🚫 Topology such as listener ports and the certificate domain list is captured
  at startup. If an Admin or signal reload adds or removes any of it, the whole
  reload must return `restart_required` — it must not bring up a side listener
  that has TCP but lacks the H3, mTLS, or resumption policy, and it must not
  autosave or report success.

### Resources

- H3 request and response bodies must keep their **bounded channels, QUIC flow
  control, and streaming**. Never switch to full buffering for the sake of
  middleware parity.
- **0-RTT early data is disabled by default**: a reverse proxy supports
  non-idempotent methods and there is no replay protection yet. **Do not re-enable
  it** before route/method policy, replay semantics, and negative tests are done.

### Verification

- After changing H3 or the TLS dependency tree, re-run at minimum on a **Linux
  release binary with a quiche client**: Alt-Svc, SNI, static and proxied bodies
  at several sizes, POST with and without Content-Length, 413, and upstream
  keepalive.
- **macOS unit tests are not sufficient to verify linking or QUIC behaviour.**

- The scripts for this gate are `scripts/test-h3-day28-local.sh` (the functional
  matrix; needs a curl built with HTTP/3), `scripts/test-h3-cancellation-local.sh`
  (SSE, cancellation, trailers), and `scripts/test-h3-client-auth-local.sh`
  (mutual TLS, including the rule that the handshake name and `:authority` must
  agree — a rule that had no test at all before 2026-08-18). The Linux half runs
  in docker `rust:1.97-bookworm`.

> ✅ **The `ba37ffc` migration passed this gate** (2026-07-30, evidence in
> `benchmarks/results/20260730_day28_f26d0a1/`): Linux release build, no
> `openssl-sys`, no dynamic `libssl`/`libcrypto`, 454 Linux tests green,
> cross-version interoperability with curl on quiche 0.18, functional matrix
> 14/14.

> ⚠️ **Building on Linux needs `cmake` (BoringSSL) and `clang`/`libclang-dev`
> (bindgen).** A clean `rust:1.97-bookworm` has neither, and without them
> `boring-sys` fails in its build script. Both release artefacts and the CI
> environment must carry them.
>
> 🐛 **And a third: `git`** (hit on 2026-07-31, the first time the production
> image was genuinely built). Without `BORING_BSSL_ASSUME_PATCHED` set,
> `boring-sys` runs `git init` over the vendored BoringSSL source and then
> applies patches (`ensure_patches_applied` → `Command::new("git")`). With no
> `git` binary it panics as `Os { code: 2, kind: NotFound }` — **a message with
> nothing in it about git**, and near-identical to the missing-`clang` failure,
> which is why the first fix went in the wrong direction.
>
> The full list (Fedora package names at the time): `cmake gcc-c++
> perl-interpreter pkgconf-pkg-config clang clang-devel git`. The Debian
> equivalents: `cmake g++ perl pkg-config clang libclang-dev git`.
>
> 📌 **Why this only surfaced then**: `deployment/Dockerfile` **had never actually
> been built by anyone** since H3 moved to tokio-quiche (`ba37ffc`). The
> `rc-a554477` image running in production had been built before the dependency
> tree changed. A build script CI never executes is untested code. (The Dockerfile
> base was a slim bookworm variant at the time, without even `git`; it is now
> ubuntu:latest plus rustup, with the package list above.)
>
> 📌 **The end-to-end tests (`pingclair-proxy/tests/h3_end_to_end.rs`) use a
> hand-written quiche client**, which proves our event loop is correct against
> quiche's protocol implementation and **proves nothing about interoperability**.
> Interoperability comes from the real curl in the two scripts above, deliberately
> built on different QUIC implementations (ngtcp2/nghttp3, and quiche 0.18).

---

## 🧵 Streaming and memory

This project has shipped the same class of bug twice (reverse-proxy gzip, static
gzip), both caused by buffering a body whole.

- No compression, retry, middleware, or observability feature may **reintroduce
  full body buffering**.
- Large bodies, SSE, ranges, and client-disconnect cancellation must all keep
  bounded memory.
- When adding anything that touches a response body, the default question is:
  **what happens with a 20 MB body?**

### 🧱 The one place buffering is deliberate, and why it will not become the same bug

`request_buffers`/`response_buffers` (`pingclair-proxy/src/body_buffer.rs`,
2026-08-13) is the only exception this document allows, on the condition that
**we decide the ceiling, not the configuration**:

- **`unlimited` is not unlimited.** Upstream reads `-1` as "read the whole thing
  into memory", and prints `UNLIMITED BUFFERING … can result in OOM crashes` at
  load time itself. We read `-1` as "buffer up to `MAX_BUFFERED_BODY_BYTES`
  (8 MiB)" and **fall back to streaming** beyond that. Configuration can tune
  anything below that number and nothing above it.
- **Exceeding the ceiling falls back to streaming; it does not reject.** Buffering
  is a compatibility and latency knob, not a limit; the thing that rejects
  oversized bodies is `request_body max_size`, which fails closed on its own.
  Turning a buffering knob into a 413 generator surprises the operator in the
  expensive direction.
- **Limits, deadlines, and the pacer all run on bytes received, not on bytes we
  decide to forward.** Get that order backwards and enabling buffering quietly
  raises `client_max_body_size` for the whole route.

> 🪤 **On the request side, holding a chunk back means returning an empty `Bytes`,
> never `None`.** `pingora-proxy 0.8.1` recomputes the end flag *after* filters
> run, at `proxy_h1.rs:774`, as `end_of_body || data.is_none()` — so `None` reads
> as "the client is finished". The upstream body ends early, no error is raised,
> and the backend receives a truncated body. On the response side the end flag
> travels with the task (`lib.rs:382`) and `None` is safe there, but always write
> an empty `Bytes` on both sides: a rule with an exception is a rule that will be
> misremembered.

> 🚫 **Stop designing "spill to a temporary file".** Checked on 2026-08-13: a
> filter can return only one chunk at a time, and once the downstream body is
> finished (`DownstreamStateMachine::maybe_finished` at `proxy_h1.rs:411`) the
> filter is never called again. So a body spilled to a file still has to be read
> back into memory in full to be handed over — **peak memory is exactly the same
> as not spilling**, plus a file descriptor and a permissions surface. Writing to
> the session directly from inside a filter was rejected too: the downstream body
> writer's framing state belongs to the task pipeline at `proxy_h1.rs:1209`, and
> inserting a second writer breaks chunked framing — in a way no test would catch
> reliably.

---

## 🩺 Upstream health: only a remote failure may mark a backend unhealthy

A reverse proxy learns about its backends by failing to reach them, so a
connection failure ejects that backend from rotation for ten seconds — which is
entirely correct. **But not every connection failure is evidence about the
backend.**

When the local machine is out of file descriptors, `socket()` fails before a
single packet leaves this box. The backend is healthy, idle, and completely
unaware anything happened. Treating that as "the backend is down" **punishes a
healthy backend for our own resource exhaustion** — and a route with a single
backend has nothing to fail over to, so the whole route stops serving for the
duration of the cooldown.

Measured on `4ed66ec` on 2026-08-11 (evidence in
`benchmarks/results/20260811_fd_exhaustion_4ed66ec/`, local): **5** local
`socket()` failures caused **139** rejected requests, and after load stopped, all
descriptors were returned, and the backend sat completely idle, a single probe
request kept returning 502 **for nine consecutive seconds**. A 27× amplification.

> 🎯 **The rule**: every new "connection failed → mark the backend" site must
> first ask `crate::upstream_failure::classify_*` for a `FailureOrigin`, and mark
> only when `implicates_backend()` is true.

The policy lives in `pingclair-proxy/src/upstream_failure.rs`, in **one** copy,
shared by both transports and by both the reverse proxy and FastCGI. There are
five sites today: `fail_to_connect` and the FastCGI dial in `server.rs`, and the
H3 upstream connection, the h2 ALPN mismatch, and the H3 FastCGI dial in
`quic.rs`.

### 🪤 The intuitive fix is dead code

```rust
// ❌ Never matches.
match error.etype() {
    ErrorType::SocketError | ErrorType::BindError => { /* local problem, skip */ }
    _ => mark_down(),
}
```

`pingora-core` 0.8.1 rewrites `SocketError` and `BindError` into `InternalError`
**before returning**, at `connectors/l4.rs:151`; the real name survives only in
the cause chain:

```text
Upstream InternalError context: Fail to connect to addr: 127.0.0.1:19000
  cause: SocketError context: failed to create socket
  cause: Too many open files (os error 24)
```

So the thing to match on is **`InternalError`**. The version above passes review,
compiles, ships, and changes nothing — and the next person concludes from it that
the whole classification theory was wrong.

📌 **`InternalError` covers more than EMFILE**: ephemeral port exhaustion arrives
as `BindError`, which on a busy proxy is more common than EMFILE, and `EACCES`,
`EADDRINUSE`, and TLS **configuration** errors (unreadable trust store, invalid
client key) all land in the same bucket.

⚠️ **An unknown errno stays classified as remote** (`ConnectError` is the
connector's catch-all). This is a deliberately conservative choice: the cost of
being wrong is a backend staying in rotation slightly too long, rather than a
healthy backend being ejected for something that was not its fault.

### 🧪 Why unit tests are not enough

The unit tests in `upstream_failure.rs` assert against error values **they
constructed themselves**. That proves the classifier and not the premise the
classifier depends on: that a genuine `EMFILE` really does arrive from Pingora's
connector in that collapsed `InternalError` shape. Only actually exhausting
descriptors and actually going through the connector verifies that —
`test_local_descriptor_exhaustion_does_not_mark_the_backend_down` in
`pingclair/tests/integration.rs` does it by setting `RLIMIT_NOFILE` on the
**child process** through `pre_exec`, so the test framework's own descriptors are
unaffected.

⚠️ **There is no equivalent runtime negative test for H3**, because
`h3_end_to_end.rs` is in-process and lowering `RLIMIT_NOFILE` would poison every
test in the same binary. The H3 half currently rests on the shared classifier,
the error shape proven by the H1/H2 test, and
`h3_refused_backend_still_fails_closed` (the remote half). This gap is recorded in
TRIAGE; do not treat it as verified.

## 🔀 Parity between two transports, and two ways to leak

Two cases of "each path is missing a piece" were measured on the same day,
2026-08-11. Both were on the H3 side, and both were **"the H1/H2 side does one
extra step that H3 does not"**:

- **A rewrite target is a template, and H3 did not expand it.** H1/H2's
  `HandlerConfig::Rewrite` runs `resolve_caddy_placeholders` first; `quic.rs`
  passed `replace` straight into `rewrite_request_uri`. So HTTP/3 rewrote the URI
  to the literal string `{http.matchers.file.relative}`, and the file server
  behind it 404'd on every request — the entire single-page-application idiom,
  silently, and only on HTTP/3.
- **A matcher has a third answer, and H3 knew only two.** The `=404` candidate of
  the `file` matcher returns `MatcherVerdict::Error`, while H3's element matcher
  helper returned `bool`, collapsing `Error` into no-match: one configuration,
  404 on HTTP/2, falls through to the next handler on HTTP/3.

  > 🎯 **The operable rule**: having a helper return `bool` is a claim that this
  > question has exactly two answers. The day a third appears (here, "raise a
  > status"), the compiler **will not** go and ask every caller — the `bool`
  > version keeps compiling in silence. Sharing a type means sharing it down to
  > the **return type**.

Neither of these is "H3 forgot to implement a handler" — that gap is conspicuous
and answers 501. These are **the same handler doing different things on the two
sides**, both answering 200 or 404, differing only in content. Hence:

> 🎯 **The operable rule**: when you touch any `HandlerConfig::` arm in
> `server.rs`, read the same-named arm in `quic.rs` side by side. Both existing
> **does not mean** both do the same thing, and tests only see the difference when
> they genuinely send a request and genuinely compare the body
> (`h3_end_to_end.rs` must go through `pingclair_config::compile` rather than
> hand-writing a `HandlerConfig` — a hand-written one skips the adapter, and the
> adapter is where the difference comes from).

---

## 🔁 Re-sending an upstream request (2026-08-17)

- 🛡️ **The line between "retry" and "duplicate" is the request body.** Once a body
  has been streamed upstream, this machine **does not know** how much the origin
  read, how much it parsed, or what it did with it. A second attempt at that point
  is not a repair, it is performing the same operation twice. Charging a card
  twice is worse than failing to charge it once. So `retry::body_is_replay_safe`
  has exactly one rule — **a request with a body is never re-sent** — and it is a
  named function rather than an `&&` precisely so that every new retry path has to
  pass through it explicitly.

- 🤡 **Only the status path had been obeying this.**
  `upstream_response_filter` (a status code came back and we did not like it) goes
  through `permits_retry`, which has the body gate; `error_while_proxy` (we
  connected, we sent, no response came back) looked only at whether the connection
  was reused plus the attempt budget — **it never looked at the body**.
  📌 `retry_buffer_truncated` is not this gate: it answers only "the body was too
  large to fit in the buffer". **A body that fits gets replayed happily by
  Pingora**, turning one `POST` into two.
  🎯 This is exactly why the rule belongs in one place: a safety rule **copied
  once per call site** gives every call site one chance to leave it out.

- ⚖️ **This gate's cost is paid deliberately.** A request with a body that a retry
  might have rescued now returns the failure to the client. That is the right
  direction — an irreversible side effect costs more than one failure.
  ⚠️ There is **no** opt-in for an operator to declare a route idempotent (an API
  carrying an idempotency key, say). So the answer is always "do not re-send".
  Whether to add that knob is undecided, not missing.

- 🎯 **A retry predicate must describe the request that actually went out, not the
  one the client sent.** `reverse_proxy { method DELETE }` turns the client's
  `GET` into a `DELETE` upstream. Asking "may this be re-sent?" about the `GET`
  answers about a request that does not exist. `AttemptFacts`'s fields are
  therefore named `upstream_method` / `upstream_path` / `upstream_query` — the
  names carry the requirement, so the next caller cannot get it quietly wrong.
  🤡 **H1/H2 gets this right by side effect**: `proxy_upstream_filter` mutates
  `session.req_header_mut()` directly, so reading it back later gives the upstream
  version. H3 does not touch the client's headers and assembles a separate
  `upstream_method`/`upstream_uri` — so its facts skipped a rewrite layer.
  **"One side is right by side effect" is not parity, it is coincidence.**

- 🧪 **The regression test for this must make the origin count, and must use a
  keep-alive origin.** The entire failure scenario presupposes that the proxy has
  a **reusable** upstream connection to fail on; an origin sending
  `Connection: close` makes every attempt a fresh connection, and Pingora does not
  retry fresh connections anyway — the test passes and tests nothing.
  📌 Also assert that the origin received the **full body length**: without that,
  the premise "the failure is ambiguous" is unproven and you may only be testing
  "the send was cut in half".
  🔌 The downstream connection is closed after the failure too, so the control
  case needs a **fresh client**, or reqwest reuses the dead connection and reports
  `IncompleteMessage`, which looks like a server error.

---

## 🧹 Outbound header sanitizing (2026-08-17)

- 🤡 **Four sinks each maintained their own exclusion list, and only one was
  right.** The H1/H2 upstream, the H3 upstream, the inline authorization
  subrequest, and the FastCGI environment all answer the same question — "may this
  client field be handed to whatever is behind us?" — with four lists, three of
  them incomplete. And not on small things: `Proxy-Authorization` (**credentials
  addressed to this proxy, handed to somebody else**), the client's own
  `Forwarded` (the origin cannot tell whether we wrote it), and the fields named
  by `Connection`. 🎯 There is now one list:
  `http_policy::OutboundRequestFilter`.

- 🎯 **It is deliberately a predicate, not a procedure.** The four sinks genuinely
  do different things with the answer: two copy fields into a new header map, one
  deletes from a map already copied, and one decides which environment variables
  to define. Sharing the **decision** is the point; sharing the **loop** would mean
  contorting three call sites to suit the fourth.

- 🕳️ **`Proxy` is not a real HTTP field; it exists only because of an attack.**
  CGI turns every request field into an `HTTP_*` environment variable, and
  environment variables are what **configuration** libraries read, not a data
  channel. So `Proxy: http://attacker` reaches CGI as `HTTP_PROXY`, and an HTTP
  client inside the script uses it as its outbound proxy. 📌 It is therefore
  refused in the **shared list** rather than only in FastCGI — no legitimate
  sender exists for this field, so there is nothing to preserve.

- 🛡️ **Strip hop-by-hop before adding your own fields; the order is part of the
  security.** A client can name **a header we are about to set** inside
  `Connection` (the tests pin this with `Connection: X-Real-IP`). Strip first,
  then add, and the attempt fails; do it the other way round and the client gets
  to delete our fields.

- ⚖️ **`Forwarded` is dropped *and* rebuilt, not just dropped.** Drop it alone and
  the origin receives nothing — the one standardised format, RFC 7239, disappears
  entirely. H3 originally did neither (no drop, no rebuild), so the origin
  received whatever the client claimed. 🎯 So the test cannot merely assert "the
  header is gone" or "the header is there"; it must assert **the value is the one
  we wrote**: `forwarded=for=127.0.0.1`, not `evil.test`.

- 🧭 **Framing fields are deliberately excluded from the shared list** (`host`,
  `content-length`, `transfer-encoding`, `trailer`). Those are message framing, and
  framing differs per sink by nature: Pingora re-frames for an H1 upstream, H3 has
  no chunked encoding, and CGI communicates length through `CONTENT_LENGTH`. Each
  sink keeps its own framing exclusions next to the code that does the framing.

- 🤡 **The `Connection` case cannot be tested on H3, because HTTP/3 forbids the
  field.** curl will not send it at all, so there is no token to name anything —
  that is how the first probe went "red", and that red was a broken test rather
  than broken code. That case belongs to the H1/H2 integration tests. **When
  writing a parity test, ask first: can this input even be expressed on that
  protocol?**

- 🧪 **There is one test matrix, `SANITIZER_MATRIX` in `http_policy.rs`.** All four
  files assert against it — if each file kept its own copy, they would drift in
  exactly the way the four original exclusion lists did.
  📌 The matrix **must contain cases that should pass** (`expect_blocked: false`):
  a matrix of only bad cases passes completely against a filter that blocks
  everything, and that filter breaks every proxied request.

---

## 🏠 Virtual host name matching (2026-08-17)

- 🚫 **There is one correct way to compare DNS names, and it must be applied to
  *both* sides.** Names are case-insensitive and a trailing dot means fully
  qualified — so `EXAMPLE.com`, `example.com.`, and `example.com` are one host. A
  `HashMap` keyed on bytes disagrees with all three, **and the bytes are chosen by
  the client.** 🎯 The approach: `http_policy::canonical_host` (strip one trailing
  dot, ASCII-lowercase), applied once when configuration is published and once
  when a request is looked up. **Applying it to one side only is worse than
  applying it to neither**, because from whichever direction somebody happens to
  test, it looks correct.

- 💀 **The consequence is not "not found", it is "found somebody else's".** A miss
  falls through to the catch-all, so `Host: SECURE.example.com` does not fail — it
  is served by **the permissive default site**, with its routes, its access rules,
  and its handlers. 🎯 So the test must register a catch-all and assert **which
  site answered**, not merely that something answered. The red run printed
  `left: "catch-all"`; without that catch-all you only see a 404, which looks like
  a different kind of problem.

- ⚡ **Use `Cow`, not `String`, on the request side.** The overwhelming majority of
  request hosts are already lowercase with no trailing dot, and that case must
  borrow. "Just call `to_ascii_lowercase()` anyway" passes every correctness
  assertion and then allocates on every request. The tests assert
  `Cow::Borrowed`/`Cow::Owned` precisely because correctness cannot detect this.

- 🃏 **A wildcard is one label, not arbitrary depth.** `*.example.com` covers
  `a.example.com`, does not cover `a.b.example.com`, and does not cover
  `example.com` itself. That is the coverage of a wildcard certificate, and it is
  what this repository was already doing in **two other places**
  (`ClientAuthTable::policy_for` and the access log's `HostPattern::matches`, both
  using `eq_ignore_ascii_case` plus an exact label count). **Routing was the only
  one that disagreed** — so one request could be routed by the wildcard site and
  admitted under the catch-all's mTLS policy.
  📌 The test: **how many answers does this repository already have to this
  question?** If two agree and a third differs, the third is the defect, and there
  is nothing left to argue about.
  ⚡ Fixed along the way: the old version used
  `host.ends_with(&format!(".{suffix}"))`, allocating **one string per registered
  pattern per request**, on the non-exact-hit path.

- 🤡 **`authority_host` only strips the port; it does not normalise.** It returns a
  `&str` borrowed from its input and deliberately does not allocate. So
  normalisation happens outside it — `request_host()` combines the two steps so no
  caller can do half of it. H1/H2 takes the host in five places and H3 in one, and
  every one of them compares it against something.

---

## 🌊 The three buffering paths in static files (2026-08-17)

- 💀 **"We have streaming" is not "we never allocate a whole file".** Streaming
  originally had exactly one shape (complete, uncompressed, > 256 KiB) and
  **everything else buffered**. So the most expensive request this server can
  serve was `Range: bytes=0-` against the largest file under the root — any
  `Range` disabled streaming, and ranges are clamped to the file size, so the
  whole file went into a `Vec`. 🎯 The test: **enumerate every branch that does not
  stream, and ask each one what its memory ceiling is.** For all three branches
  (Range, dynamic compression, precompressed sidecar) the answer was "the size of
  the file".

- 🪟 **Streaming a range means the stream carries a *window*, not just a file.**
  `StreamingFile`'s size field was renamed from `file_size` to `body_len` for this
  reason — it is **how many bytes this response sends**, which happens to equal the
  file size for a complete response and does not for a partial one.
  ⚠️ And `status`, `content_range`, and `content_encoding` must travel with the
  stream rather than being reconstructed by the transport: both transports
  originally hard-coded `200`, and **answering a range request with 200 and no
  `Content-Range` tells the client it received the entire file**. It is very easy
  to manufacture that correctness defect while fixing the memory one.

- 🗜️ **Dynamic compression chose a ceiling rather than streaming compression.**
  The compressor takes a slice and returns a `Vec`, and the compressed cache needs
  the complete buffer — so the cost is inherently proportional to the file.
  `MAX_COMPRESSIBLE = 8 MiB`, **deliberately below the 64 MiB cache budget**: the
  budget decides "having allocated it, do we keep it", which is the wrong end of
  the decision. 📌 Streaming compression would preserve both the encoding and the
  ceiling, but it means one compressor per in-flight response and a body whose
  length is unknown until it ends — both the cache and the framing would need
  redesigning. This rule is the conservative half; the other half deserves its own
  change and must not be smuggled in.

- 🤡 **The ordering was part of the defect: the streaming branch came before the
  sidecar check.** So a site that had built `.gz` sidecars served **the streamed
  uncompressed file** for large files instead of the small compressed one it had
  prepared. The sidecar now comes first — it is strictly better (smaller body, no
  compression cost) and now streams too, so preferring it costs nothing.
  🎯 **A red-first probe caught this by accident**: after removing sidecar
  streaming the test was still green, which revealed that the assertion had never
  reached the sidecar path at all. **Red-first verifies the test as well as the
  fix.**

- 🧪 **The test measures the largest single allocation, not whether a response
  arrived.** The method: drain the response, reporting the chunk size when streamed
  and the whole body length when buffered. All four paths (identity, range,
  dynamic, sidecar) are asserted together in one test, because they are four faces
  of one defect — testing them separately lets "fixed one" read as "fixed the
  class". 📌 Three were verified red individually, each reporting
  `left: 16777216` (16 MiB).
