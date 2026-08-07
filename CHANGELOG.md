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

### 🚫 Non-goals for 0.2.0

What this release deliberately does **not** try to do. A release with 51
entries and no stated non-goals has no edge: every plausible idea is still
inside the scope, so nothing can be finished. Naming what is out is what
lets the rest converge.

- TBD — Dorian to fill in during scope cut

### ⚠️ Breaking

- 🔐 **A bare hostname site now derives an HTTPS listener.** Writing a site
  address with no scheme and no port (for example `example.com { … }`) used to
  produce a plaintext listener on port 80. It now behaves the way Caddy does:
  the site is served over HTTPS on 443, and a companion listener on port 80
  redirects to it. Sites that meant to serve plaintext must now say so — with
  an explicit `http://` scheme, an explicit port, or an IP literal. An address
  that already named a listener is unaffected.

### 🔄 Changed

- 🔐 **`basic_auth` takes the grammar the format defines.** The arguments are
  now `[<hash_algorithm> [<realm>]]` and the block holds nothing but
  `<username> <hashed_password>` accounts, so the documented
  `basic_auth bcrypt "Admin Area" { … }` works — it used to be refused with
  "cannot mix inline credentials with a block". **The two spellings this crate
  had before are gone**: credentials as arguments, and `realm` as a block
  line. They could not be kept alongside because they collide with the real
  grammar rather than extending it — under it, a block line reading
  `realm "X"` is an account named `realm`. A `realm` block line is therefore
  refused with a message naming the replacement, instead of silently becoming
  a working credential nobody wrote. `basic_auth` never appeared in a release,
  so no `0.1.7` configuration is affected. `argon2id` is refused by name: this
  server verifies bcrypt only, and a hash it cannot verify is compared as
  plain text.
- 🗂️ **`try_files` resolves candidates under the site root and rewrites instead
  of serving.** It was previously reachable only from JSON, where it treated
  each candidate as a filesystem path and served any match itself through an
  ad-hoc file server. That meant `/index.html` was looked up at the filesystem
  root rather than under `root`, so the pattern it exists for answered 404 for
  every application route. It now expands `{path}`, resolves under the site
  root, rewrites the request to the first match, and lets the next handler
  serve it — matching Caddy, and verified against Caddy v2.11.4 (17 of 17
  request comparisons agree). A candidate ending in `/` matches only a
  directory and one without matches only a regular file, per upstream's file
  matcher. **A JSON configuration using `try_files` must drop the site-root
  prefix from its candidates and add a `file_server` after it.**

- 🏷️ **Route matchers serialize in a tagged representation.** The untagged shape
  0.1.7 wrote could not round-trip unambiguously — a `Query` matcher read back
  as a `Header`. Existing documents still load, since the deserializer accepts
  every shape 0.1.7 could produce, but configs written out now use the tagged
  form. Anything diffing exported JSON will see the change.
- 🔗 **The default upstream keepalive pool is 512 connections**, up from
  Pingora's 128. A proxy that reuses too few upstream connections spends the
  difference on TCP handshakes.

### ✨ Added

- 📝 **Caddyfile compatibility.** Complete directive syntax and matcher
  semantics, Caddy's directive ordering, `handle`/`handle_path` containers, a
  redirect DSL, response templates, and dual-stack (IPv4 + IPv6) wildcard
  listeners. (`handle_errors` parses but does nothing yet, and is refused
  rather than silently accepted.)
- 🗂️ **`try_files` and `uri` in the Pingclairfile.** The documented
  single-page-application pattern — `root * /srv`, `try_files {path}
  /index.html`, `file_server` — compiles and serves, on HTTP/1.1, HTTP/2 and
  HTTP/3 alike. `uri strip_prefix`, `uri strip_suffix` and `uri path_regexp`
  map onto the existing rewrite. `uri replace` and `uri query` are refused by
  name: `replace` means substring replacement upstream and whole-path
  replacement here, so accepting it would serve a different URL than the one
  written.
- 🌐 **Admin API.** `/load`, `/adapt` and `/stop`, Caddy-style config traversal
  with `@id` addressing, dynamic listeners, autosave and resume, and graceful
  stop.
- ⌨️ **Command line.** `reload`, `start`, `stop`, `respond`, `run --watch`,
  HTTPS quick commands, shell completion, `environ`, `list-modules`,
  `build-info`, `manpage`, `storage` and `trust`.
- 🎯 **Session affinity by header, cookie, or query parameter.**
  `lb_policy header X-Session`, `lb_policy cookie sid` and
  `lb_policy query user` route requests carrying the same value to the same
  backend, over the same consistent-hash ring `ip_hash` already used — so
  adding a backend moves about one backend's share of traffic rather than
  reshuffling everyone. A request that does not carry the named field falls
  back to normal selection instead of hashing an empty value, which would pin
  every such client to one backend.
- 🔀 **Reverse proxy.** Active health checks, circuit breakers, exact local rate
  limiting, bounded idempotent redispatch, per-request resource bounds,
  upstream authentication, gRPC parity, h2c, hostname re-resolution while the
  server runs, and a `Via` header per RFC 9110.
- 📦 **Response caching.** RFC 9111 decides what may be stored, and a second
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
- 🚀 **HTTP/3.** Unified middleware execution with the other transports, route
  access controls, and certificates delivered to the QUIC stack from memory
  rather than through temporary files.
- 🔐 **TLS.** A persistent internal CA for private origins, and durable ACME
  state across restarts.
- 🛡️ **Identity and trust.** PROXY protocol required per listener, verified
  trusted client identity, and `CF-Connecting-IP` honored only from trusted
  peers.
- 🔑 **Authentication.** bcrypt and argon2id credentials, `basic_auth` in the
  DSL, and an admin API key.
- 🪵 **Logging.** Per-server log configuration that actually drives access-log
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
  written as present with their values masked. Named channels declared in
  the global block (`log audit { … }`) can be referenced from several sites
  with `log audit`, which share one writer; a site keeps its own inline
  `log { … }` at the same time, so "everything to stdout, an audit copy to a
  file" needs no duplication. Referencing a channel that was never declared
  is refused at startup, listing the names that do exist.
- 🚦 **Readiness and liveness endpoints.** `GET /ready` on the admin API answers
  503 until every listener is bound, and again as soon as shutdown begins, so
  a rolling deploy stops sending traffic to an instance that cannot yet answer
  or is draining. `GET /live` stays 200 throughout, because a process
  finishing the connections it already accepted should not be restarted. The
  systemd unit is now `Type=notify`: `systemctl start` blocks until the proxy
  can really serve, rather than returning the moment the process forks.
  `pingclair_ready` and `pingclair_config_version` export the same facts to
  Prometheus — two instances reporting different config versions means a
  reload reached one and not the other. New metrics cover upstream latency
  and errors separately from client-visible ones, retries, keepalive
  connection reuse, TLS handshakes by version, and HTTP/3 connections and
  cancellations.
- 🚧 **The admin API enforces an origin allow list.**
  `admin :2019 { origins https://admin.example.com; enforce_origin }`. Without
  it a page on any website could `fetch()` a new configuration into a
  locally-bound admin endpoint. Requests carrying no `Origin` at all — curl,
  systemctl — keep working unless `enforce_origin` is set, since the attack
  being prevented is specifically a browser one.
- 🗜️ **Response compression is negotiable.** An `encode` directive selects zstd
  and gzip per `Accept-Encoding`, with configurable MIME types. A config that
  never mentions `encode` keeps compressing exactly as 0.1.7 did — gzip only —
  so upgrading changes nothing on its own.

### 🐛 Fixed

- 🔗 **A placeholder is no longer split from the word it is glued to.**
  `{host}/moved` used to tokenize as two arguments, because a placeholder at
  the *start* of a token was emitted on its own while one glued *after* a word
  was absorbed into it — the same file answering the same question two
  different ways depending on which side the placeholder sat. Two things this
  fixes: `redir {host}/moved 302` was refused as having three arguments, and
  `try_files {path} {path}/ /index.html` silently became four candidates whose
  stray `/` matched the site root on every request, so every URL served the
  shell and the configuration looked like it worked. Any directive taking an
  argument that begins with a placeholder was affected.

- 🗜️ **`Accept-Encoding: gzip;q=0` was answered with gzip.** A `q` of zero is an
  explicit refusal, and a static file ignored it — the negotiation on that path
  was `header.contains("gzip")`, which cannot see a quality value, matched
  substrings so a token merely embedding a coding name selected it, and ignored
  the order `encode` was configured with. A correct implementation existed in
  the proxy crate and nothing in production called it. There is now one
  implementation, shared, so a fix cannot fail to reach a served file.
- 🧊 **`Vary: Accept-Encoding` was missing from uncompressed responses.** The
  header was sent only when a body had actually been compressed, but it
  describes the resource rather than the copy in hand. Without it a shared
  cache stores the identity variant as if it were the only one and serves it to
  a client that asked for gzip. Streamed responses — always the uncompressed
  variant — never carried it at all.
- 🎯 **`respond /path "body"` treated the path as the body.** An exact path in
  the matcher position stayed an argument, so `respond /first "first wins"`
  answered every request with the text `/first` and any later `respond` was
  unreachable. A glob worked, which is why this stayed hidden. Routing silently
  to the wrong handler is worse than refusing to load.
- 🚰 **Shutdown had no configurable grace period at all.** Nothing set
  Pingora's shutdown knobs, so a `SIGTERM` truncated responses still being
  sent: a 20 MiB download over a rate-limited link arrived as 4.1 MiB with
  status 200 and no error a client could distinguish from a network fault, and
  every rolling restart did that to every transfer in progress. The new
  `grace_period` global option now sets that window, defaulting to 30 seconds.
  > 🚧 **This narrows the problem rather than closing it.** Caddy exits as soon
  > as the last in-flight request finishes — bounded by the work remaining, not
  > by a clock — and Pingora 0.8.1 exposes no knob that expresses it. Measured
  > on a clean Linux box, a transfer longer than the grace period is still cut
  > off, and the grace window alone does not keep a large download alive, so
  > something below the configuration layer ends the connection first. Do not
  > read this entry as "graceful shutdown works".
- 🔄 **Log rotation written the way Caddy writes it did nothing.** Rotation
  settings inside `output file <path> { … }` — `roll_size`, `roll_keep`,
  `roll_keep_for` — were parsed and discarded, so a configuration carried over
  from Caddy validated cleanly and then let the access log grow until the disk
  filled. The settings now apply, and an unrecognised name inside that block is
  an error that names it instead of silence.
- 🔐 **Access logs recorded no request headers.** Caddy's JSON log carries the
  whole header map with sensitive values masked; ours carried none unless a
  `headers { request … }` list named them. An empty list now means every
  header, and a named list narrows rather than enables. Masking applies on both
  paths.
- 🔗 **Only the leaf certificate was sent to clients.** Intermediates in a PEM
  bundle were parsed and discarded, so any client without the issuing CA
  cached locally failed to build a chain. Found on a public network path;
  invisible against a local trust store.
- 🔓 **`tls auto` broke the ACME HTTP-01 challenge.** Automatic HTTPS took over
  port 80, which RFC 8555 §8.3 requires to stay cleartext, so issuance could
  not complete. Port 80 now stays in the clear for the challenge.
- 🧭 **Request paths were rejected instead of normalized.** Path resolution now
  matches nginx, and a path that escapes its route no longer reaches the
  origin.
- 🧹 **A repeated response header name reused the first value.** A route with
  `header +Vary Accept-Encoding` merged with a CORS decision emitted
  `Vary: Accept-Encoding` twice and dropped `Vary: Origin`, which would let a
  shared cache serve one origin's response to another. HTTP/3 was never
  affected.
- 🧱 **Ambiguous framing was accepted.** A `Content-Length` of `+5` and requests
  carrying more than one `Host` are now refused, since a lenient reader and a
  strict one disagree about where the body ends.
- 🧹 **Hop-by-hop headers crossed the hop**, credentials included.
- 🔀 **HTTP/2**: authority routing, ALPN negotiation and upstream weights.
- 🛑 **HTTP/3**: abandoned streams are cancelled rather than left to time out.
- 🔁 **A fail-fast rejection tore down the client's whole connection.**
- ♻️ **Circuit-breaker state leaked** for backends removed from the pool.
- 🏷️ **Health checks probed every backend under one name.**
- 🎧 **`protocols` was parsed and then ignored.** A global
  `servers { protocols h1 h2 }` block — Caddy's way of saying "do not serve
  HTTP/3" — compiled cleanly and changed nothing, so QUIC kept listening
  while the operator believed it had been switched off. The list now decides
  whether HTTP/3 runs. Writing no `protocols` directive at all still means
  "leave the defaults alone", which is not the same as an empty allow list.
- 🔇 **A client hanging up was logged as a server error, twice.** Browsers
  navigating away, users pressing stop and load balancers recycling idle
  connections all produced ERROR lines: one `wrk -c200` run closing its
  connections emitted 153 in a second, right after half a million requests had
  succeeded. Because the default log filter passes ERROR only, that flood was
  the *only* thing visible on a stock deployment. Failures attributed to the
  client are now DEBUG (or WARN when the client did something specific and
  wrong); upstream and internal failures are untouched and still ERROR.

### 🔐 Security

- 📊 **The active-connection gauge was the one metric the cap missed.** The
  ceiling below applied to every host-labelled metric except
  `pingclair_active_connections`, which kept a series per distinct `Host`
  header. Measured with 1600 distinct headers on a clean Linux box: every other
  family stopped at 1025 series while this one reached 1600. The remote memory
  exhaustion the cap was added to close therefore remained open through this
  one metric until now.
- 🛡️ **Metric labels taken from client input are capped.** The `host` label came
  straight from the `Host` header, and Prometheus keeps a separate time series
  per distinct value, so varied headers grew the process without bound — a
  remote memory exhaustion needing no authentication and no unusual traffic
  volume. Values beyond a fixed ceiling now collapse into `other`, which keeps
  the totals correct. A host already seen keeps its own series, so a flood of
  junk cannot displace real traffic.
- 🔄 **A reload could apply half a configuration.** Bind addresses were published
  one at a time, so a new listener that could not be bound left the addresses
  handled before it already serving the new configuration — the reload
  reported itself "partially reloaded" and left a state nobody had asked for.
  Every new listener is now probed before anything is published, and a single
  failure rejects the whole reload with the previous configuration untouched.
  A site removed from the configuration also stops serving, instead of staying
  reachable on its old listener until the next restart.
- 🔐 **Rotating a manual certificate needed a restart, and nothing said so.**
  Certificate files were read once at startup, so writing a new pair on disk
  changed nothing until the process was restarted. A reload now re-reads them.
  The whole set is validated first — the PEM must contain a certificate, the
  key must parse, and the key type must be one the TLS stack can sign with —
  and a single unusable pair rejects the refresh with the previous
  certificates still serving, naming the file at fault. Previously a
  half-written file was accepted and failed later at handshake time, to a real
  client, on a site that had been working.
- 🗂️ **A directory configuration silently dropped most global options.** Merging
  several `.pingclair` files named a handful of fields by hand and ignored the
  other nine, so `blocked_ips` blocked nothing, `metrics` did nothing, and
  `http_port`/`https_port`/`trusted_proxies`/`dns_refresh`/`protocols` were
  discarded — while the configuration compiled and reported success. Lists now
  accumulate across files instead of the last file winning, and validation
  runs once on the merged result, so a site may reference a log channel
  declared in another file.
- 🚫 Foreign JSON documents are rejected fail-closed rather than partially
  applied.
- 🌐 The admin API enforces the rules it was assumed to already have.
- 🧱 PROXY protocol ingress is bounded like every other listener.
- 🙈 Sensitive fields are masked by default in logs, metrics and admin output.
- 🚫 A `plugin` route — parsed but never implemented — is refused at compile
  time instead of silently accepting traffic and doing nothing.

### ⚡ Performance

Measured on AWS `c7i-flex.large` unless noted; see `benchmarks/README.md` for
methodology and the honest comparison against nginx, including the scenarios
where nginx is still ahead.

- 🚀 **HTTP/3** gained GSO-backed packet batching (the per-connection output
  buffer was 1350 bytes, so every QUIC packet became its own syscall), a
  bounded per-stream chunk queue in place of a byte ring, and immediate
  acknowledgement so a body the server is draining no longer trickles at one
  packet per 25 ms.
- 📁 **Static files** prebuild per-file response metadata behind a lock-free
  read, and files at or below 5 MiB stream from disk instead of buffering.
- ⚡ **The proxy hot path** stops rebuilding `Via`, request-id and forwarding
  header values that are fully determined before a request arrives.
- 🤝 **HPACK header encoding** reuses a per-connection scratch buffer. This was
  contributed upstream and merged as
  [hyperium/h2#929](https://github.com/hyperium/h2/pull/929).

### 🗑️ Removed

- 🗑️ Two vendored performance forks (`pingora-core`, `pingora-http`, 38,532
  lines) were evaluated and removed. Both had a sound mechanism and neither
  ever produced a measurement from a run where the component it patched was
  the saturated resource.

[Unreleased]: https://github.com/dorianverlaine/pingclair/compare/v0.1.7...HEAD
