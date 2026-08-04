# Changelog

All notable changes to Pingclair are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Pingclair is pre-1.0, so a **minor** bump is where breaking changes live; a
patch bump promises nothing breaks.

Releases before `0.2.0` predate this file. Their contents are recoverable from
the tag history (`git log v0.1.6..v0.1.7`), but they were never written up, so
nothing is claimed for them here rather than reconstructing them after the
fact.

## [Unreleased]

Everything below is on `main` and unreleased; the workspace reports
`0.2.0-dev`. The scope is large because it covers 173 commits since `v0.1.7`.

### ⚠️ Breaking

- **A bare hostname site now derives an HTTPS listener.** Writing a site
  address with no scheme and no port (for example `example.com { … }`) used to
  produce a plaintext listener on port 80. It now behaves the way Caddy does:
  the site is served over HTTPS on 443, and a companion listener on port 80
  redirects to it. Sites that meant to serve plaintext must now say so — with
  an explicit `http://` scheme, an explicit port, or an IP literal. An address
  that already named a listener is unaffected.

### Changed

- **Route matchers serialize in a tagged representation.** The untagged shape
  0.1.7 wrote could not round-trip unambiguously — a `Query` matcher read back
  as a `Header`. Existing documents still load, since the deserializer accepts
  every shape 0.1.7 could produce, but configs written out now use the tagged
  form. Anything diffing exported JSON will see the change.
- **The default upstream keepalive pool is 512 connections**, up from
  Pingora's 128. A proxy that reuses too few upstream connections spends the
  difference on TCP handshakes.

### Added

- **Caddyfile compatibility.** Complete directive syntax and matcher
  semantics, Caddy's directive ordering, `handle`/`handle_path`/`handle_errors`
  /`try_files` containers, a redirect DSL, response templates, and dual-stack
  (IPv4 + IPv6) wildcard listeners.
- **Admin API.** `/load`, `/adapt` and `/stop`, Caddy-style config traversal
  with `@id` addressing, dynamic listeners, autosave and resume, and graceful
  stop.
- **Command line.** `reload`, `start`, `stop`, `respond`, `run --watch`,
  HTTPS quick commands, shell completion, `environ`, `list-modules`,
  `build-info`, `manpage`, `storage` and `trust`.
- **Session affinity by header, cookie, or query parameter.**
  `lb_policy header X-Session`, `lb_policy cookie sid` and
  `lb_policy query user` route requests carrying the same value to the same
  backend, over the same consistent-hash ring `ip_hash` already used — so
  adding a backend moves about one backend's share of traffic rather than
  reshuffling everyone. A request that does not carry the named field falls
  back to normal selection instead of hashing an empty value, which would pin
  every such client to one backend.
- **Reverse proxy.** Active health checks, circuit breakers, exact local rate
  limiting, bounded idempotent redispatch, per-request resource bounds,
  upstream authentication, gRPC parity, h2c, hostname re-resolution while the
  server runs, and a `Via` header per RFC 9110.
- **Response caching.** RFC 9111 decides what may be stored, and a second
  identical request is served without asking the origin. The store is bounded
  by `max_size` (128 MiB unless you say otherwise) and evicts least-recently-
  used entries at the ceiling, so switching caching on cannot by itself be
  what exhausts a machine's memory. Concurrent misses for the same URL
  collapse into one upstream request rather than a burst of them.
  `pingclair_cache_requests_total` reports hit/miss/stale/bypass;
  `GET /cache` on the admin API reports size against the ceiling, and
  `POST /cache/purge` drops a single URL.
  > The ceiling is process-wide because the store is. A configuration whose
  > routes ask for different `max_size` values is refused at startup, naming
  > both, rather than one of them quietly losing.
- **HTTP/3.** Unified middleware execution with the other transports, route
  access controls, and certificates delivered to the QUIC stack from memory
  rather than through temporary files.
- **TLS.** A persistent internal CA for private origins, and durable ACME
  state across restarts.
- **Identity and trust.** PROXY protocol required per listener, verified
  trusted client identity, and `CF-Connecting-IP` honored only from trusted
  peers.
- **Authentication.** bcrypt and argon2id credentials, `basic_auth` in the
  DSL, and an admin API key.
- **Logging.** Per-server log configuration that actually drives access-log
  output, and secrets redacted by default. Lines are now handed to a
  background writer through a bounded queue, so a full disk or a stalled
  mount can no longer slow down request handling: when the queue fills, lines
  are dropped and counted in `pingclair_access_log_dropped_total` rather than
  the proxy being held up. Any non-zero value there means the log has a gap
  for that period. `log { roll { size 100mb; age 24h; keep 7; compress } }`
  rotates the file, keeps a fixed number of old ones and gzips them, all on
  the writer thread. `log { headers { request X-Request-Id; response
  X-Cache; tls } }` records named headers and the negotiated TLS version and
  cipher — naming `authorization` is safe, since sensitive headers are
  written as present with their values masked.
- **Response compression is negotiable.** An `encode` directive selects zstd
  and gzip per `Accept-Encoding`, with configurable MIME types. A config that
  never mentions `encode` keeps compressing exactly as 0.1.7 did — gzip only —
  so upgrading changes nothing on its own.

### Fixed

- **Only the leaf certificate was sent to clients.** Intermediates in a PEM
  bundle were parsed and discarded, so any client without the issuing CA
  cached locally failed to build a chain. Found on a public network path;
  invisible against a local trust store.
- **`tls auto` broke the ACME HTTP-01 challenge.** Automatic HTTPS took over
  port 80, which RFC 8555 §8.3 requires to stay cleartext, so issuance could
  not complete. Port 80 now stays in the clear for the challenge.
- **Request paths were rejected instead of normalized.** Path resolution now
  matches nginx, and a path that escapes its route no longer reaches the
  origin.
- **A repeated response header name reused the first value.** A route with
  `header +Vary Accept-Encoding` merged with a CORS decision emitted
  `Vary: Accept-Encoding` twice and dropped `Vary: Origin`, which would let a
  shared cache serve one origin's response to another. HTTP/3 was never
  affected.
- **Ambiguous framing was accepted.** A `Content-Length` of `+5` and requests
  carrying more than one `Host` are now refused, since a lenient reader and a
  strict one disagree about where the body ends.
- **Hop-by-hop headers crossed the hop**, credentials included.
- **HTTP/2**: authority routing, ALPN negotiation and upstream weights.
- **HTTP/3**: abandoned streams are cancelled rather than left to time out.
- **A fail-fast rejection tore down the client's whole connection.**
- **Circuit-breaker state leaked** for backends removed from the pool.
- **Health checks probed every backend under one name.**
- **`protocols` was parsed and then ignored.** A global
  `servers { protocols h1 h2 }` block — Caddy's way of saying "do not serve
  HTTP/3" — compiled cleanly and changed nothing, so QUIC kept listening
  while the operator believed it had been switched off. The list now decides
  whether HTTP/3 runs. Writing no `protocols` directive at all still means
  "leave the defaults alone", which is not the same as an empty allow list.
- **A client hanging up was logged as a server error, twice.** Browsers
  navigating away, users pressing stop and load balancers recycling idle
  connections all produced ERROR lines: one `wrk -c200` run closing its
  connections emitted 153 in a second, right after half a million requests had
  succeeded. Because the default log filter passes ERROR only, that flood was
  the *only* thing visible on a stock deployment. Failures attributed to the
  client are now DEBUG (or WARN when the client did something specific and
  wrong); upstream and internal failures are untouched and still ERROR.

### Security

- Foreign JSON documents are rejected fail-closed rather than partially
  applied.
- The admin API enforces the rules it was assumed to already have.
- PROXY protocol ingress is bounded like every other listener.
- Sensitive fields are masked by default in logs, metrics and admin output.
- A `plugin` route — parsed but never implemented — is refused at compile
  time instead of silently accepting traffic and doing nothing.

### Performance

Measured on AWS `c7i-flex.large` unless noted; see `benchmarks/README.md` for
methodology and the honest comparison against nginx, including the scenarios
where nginx is still ahead.

- **HTTP/3** gained GSO-backed packet batching (the per-connection output
  buffer was 1350 bytes, so every QUIC packet became its own syscall), a
  bounded per-stream chunk queue in place of a byte ring, and immediate
  acknowledgement so a body the server is draining no longer trickles at one
  packet per 25 ms.
- **Static files** prebuild per-file response metadata behind a lock-free
  read, and files at or below 5 MiB stream from disk instead of buffering.
- **The proxy hot path** stops rebuilding `Via`, request-id and forwarding
  header values that are fully determined before a request arrives.
- **HPACK header encoding** reuses a per-connection scratch buffer. This was
  contributed upstream and merged as
  [hyperium/h2#929](https://github.com/hyperium/h2/pull/929).

### Removed

- Two vendored performance forks (`pingora-core`, `pingora-http`, 38,532
  lines) were evaluated and removed. Both had a sound mechanism and neither
  ever produced a measurement from a run where the component it patched was
  the saturated resource.

[Unreleased]: https://github.com/dorianverlaine/pingclair/compare/v0.1.7...HEAD
