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

- 🔁 **Control-plane changes that need a new listener now return
  `409 restart_required`.** The former Admin path started a side TCP listener
  after startup, but that listener omitted HTTP/3, mutual TLS, strict SNI/Host,
  and session-resumption policy. `/load` no longer reports that partial
  listener as active or autosaves the rejected document. Adding or removing a
  bind address, adding a TLS hostname, changing process-wide or
  transport-captured settings, and enabling mTLS on a previously resumable TLS
  context require a process restart. Compatible changes on existing listeners
  remain hot-reloadable.

- 📊 **Request metrics no longer carry a `host` label unless the configuration
  asks for one.** `pingclair_requests_total`, the request duration/size
  histograms, `pingclair_active_connections` and `pingclair_cache_requests_total`
  used to break down by `Host` unconditionally. They now report one series per
  method and status until a `metrics { per_host }` block says otherwise, which
  is the upstream default and the reason for the change.

  **A dashboard or alert that groups by `host` will show one empty group after
  upgrading.** Restore the old breakdown by adding to the global block:

  ```
  {
      metrics {
          per_host
      }
  }
  ```

  With `per_host` alone, only hosts the configuration actually serves get their
  own series and every other `Host` value folds into `other` — so the series
  count is decided by your Pingclairfile rather than by whoever is sending
  requests. Add `observe_catchall_hosts` to give unconfigured hosts their own
  series too; that hands the decision to the sender, bounded only by the 1024
  distinct-value ceiling, and is not recommended on a public listener.

- 🧩 **The JSON handler `{"type": "handle"}` is now `{"type": "pipeline"}`,
  and a separate `{"type": "first_match"}` carries the exclusive behaviour.**
  One container was doing two jobs under one name. Configurations written by
  hand keep loading — `"handle"` is accepted as an alias for `"pipeline"`,
  which is the corrected reading of what those documents always meant — but a
  configuration exported from this version spells it the new way, and anything
  matching on the old string needs updating. Only `try_files` compiles to
  `first_match`.

- 🪵 **`log <name> { … }` now configures a named per-site logger.** This is
  the spelling upstream Caddy gives the same tokens: the block is the
  logger's configuration, and the name is its handle. It used to be refused
  as ambiguous. `log <name>` without a block still references a global
  channel, a bare `log` enables the site's default access sink, and an
  unnamed global `log { … }` now configures the default logger instead of
  being refused.

- 🔐 **A bare hostname site now derives an HTTPS listener.** Writing a site
  address with no scheme and no port (for example `example.com { … }`) used to
  produce a plaintext listener on port 80. It now behaves the way Caddy does:
  the site is served over HTTPS on 443, and a companion listener on port 80
  redirects to it. Sites that meant to serve plaintext must now say so — with
  an explicit `http://` scheme, an explicit port, or an IP literal. An address
  that already named a listener is unaffected.

- 🚫 **An unrecognised field inside a TLS, mutual-TLS, `pki`, `acme_server`,
  DNS-01 or `admin` block now fails the load.** Those types used to drop a key
  they did not know, which left the type's own default in force and reported
  success — so the part of the schema where a typo costs the most was the part
  with no typo check. A JSON or TOML document with a stray key in one of those
  blocks is now refused, and the error names the key. Correctly spelled fields
  behave exactly as before, and the rest of the schema is unchanged. See the
  Security entry below for what the old leniency actually cost.

- 🪪 **A client certificate must now be allowed to be a client certificate.**
  `client_auth` in a verifying mode used to ask only whether the certificate
  chained to a trusted CA. It now also honours what the certificate says about
  itself, which is BoringSSL's own SSL-client check: an extended key usage that
  excludes `clientAuth`, a key usage permitting neither digital signature nor
  key agreement, or a Netscape certificate type ruling out SSL client use each
  end the handshake, at every level of the chain rather than only at the leaf.

  **A certificate carrying no usage extensions is unaffected** — no restriction
  is not a restriction — so most private CAs see no change. Two shapes stop
  working, both deliberately: a leaf issued `serverAuth`-only, and an
  intermediate restricted to `serverAuth` issuing client identities. One shape
  is a surprise worth naming: a leaf whose only extended key usage is
  `anyExtendedKeyUsage` is refused, because BoringSSL gives `any` its own bit
  and the SSL-client check looks for the `clientAuth` bit. Adding `clientAuth`
  to the certificate is the fix in all three cases. See the Security entry
  below.

- 🔐 **The autosaved config document and `storage-export` archives are now mode
  `0600`.** Both hold secrets — the admin key and DNS credentials in one, private
  keys in the other — and both used to be created `0644`. A process running as a
  different user that reads either file will now be denied; run it as the owner,
  or copy the file deliberately. `storage-export` warns rather than silently
  keeping a looser mode when the destination already exists, because `mode` only
  applies at creation. See the Security entry below.

- 🗜️ **Static files larger than 8 MiB are no longer compressed on the fly.**
  Dynamic compression needs the whole body in memory, so its cost was
  proportional to the largest file in the document root and the choice belonged
  to whoever sent `Accept-Encoding`. Above the bound the response now streams
  uncompressed: bounded in memory, and the kind of file that is that large — an
  archive, a video, an image — compresses to roughly its own size anyway. Build a
  `.br`/`.gz`/`.zst` sidecar and enable `precompressed` to serve a large file
  compressed; those stream too, and are now preferred over streaming the
  uncompressed file. See the Security entry below.

- 📁 **A `file_server` index must be a relative filename.** An index that is
  absolute (`/var/www/index.html`), contains `..`, contains a backslash or a
  colon, or is empty is now refused when the configuration loads rather than
  resolved at the first request. `index.html`, `index.htm` and a nested
  `deep/default.html` are unaffected — the refused shapes are the ones that
  resolve somewhere other than inside the served directory, or that mean two
  different files depending on the platform. See the Security entry below.

- 🃏 **A `*.example.com` site now covers one label, not any depth.** Routing used
  to match a wildcard site with `ends_with(".example.com")`, so
  `a.b.example.com` reached `*.example.com` as well as `a.example.com` did. One
  label is what a wildcard TLS certificate covers, what Caddy matches an SNI
  against, and what two other parts of this server — the client-auth policy table
  and the access-log host patterns — already did. Routing was the one that
  disagreed, which meant a request could be **routed** by a wildcard site while
  being **admitted** under the catch-all's mutual-TLS policy.

  A request two labels deep now reaches the catch-all site, or 404s if there is
  none. Configure the deeper name explicitly, or add a `*.b.example.com` site.

- 🌐 **Automatic public certificates are now issued only for the hostnames a
  site actually names.** Automatic HTTPS used to decide what to ask a
  certificate authority about from the server name in the handshake: an
  unrecognised name was read as "we must not have a certificate for this yet".
  It is now decided from the configuration, resolved before any listener
  accepts and again on every reload.

  **What changes for a working setup.** A site with a concrete hostname, a
  list of hostnames, or a `*.suffix` wildcard proved by DNS-01 is unaffected.
  Two shapes stop getting automatic certificates and need an explicit
  hostname or a manual `tls <cert> <key>` instead: a **catch-all site** (`_`,
  `*`, or an address-only label such as `:8443`) with `tls auto`, and a
  wildcard that is not `*.suffix`. Catch-all is about which requests a site
  answers, not about which names deserve a certificate, and it was only ever
  the latter by accident.

  Alongside it, `auto_https off` now actually stops issuance — it was recorded
  in the configuration and never read at runtime, so a server told not to
  manage certificates would still go and manage them. Certificates already
  issued are still served either way; the switch stops acquiring, not serving.

### 🔄 Changed

- 🌐 **Dynamic DNS now honors source policy.** Empty `resolvers` uses the
  host's system DNS configuration instead of Hickory's Google default. Each
  dynamic pool follows its own `refresh` interval, including when global
  `dns_refresh` is off, while an omitted interval still follows the global
  setting. SRV `grace_period` now bounds stale peers from the first failed
  refresh and withdraws them when the window expires; without a grace period,
  discovery failure withdraws them immediately. Dynamic `dial_fallback_delay`
  is now rejected instead of being accepted without effect. Requests continue
  to read only the atomically published pool snapshot.

- 🌐 **Mixed HTTP/HTTPS site addresses now retain per-listener policy.** A
  block such as `http://example.com, https://example.com { … }` shares its
  handlers without letting the HTTP address disable automatic certificates
  for HTTPS. Explicit HTTP remains plaintext, including on a conventional TLS
  port when `tls off` applies, and different hostnames stay scoped to their
  respective listeners instead of leaking across both schemes.

- 🪵 **Logger sub-options now parse like Caddy.** Log blocks accept
  `hostnames`, global `include`/`exclude`, `sampling { interval; first;
  thereafter }`, and the file rotation options (`mode`, `dir_mode`,
  `roll_compression`, `roll_local_time`, `roll_interval`, `roll_at`,
  `roll_minutes`). `log_skip` is implemented as request-scoped middleware,
  and flat `format filter` directives such as
  `request>headers>Authorization delete` are honoured for the `delete`
  operation. `log_append`, `log_name`, and the `append`/`journald` encoders
  remain unsupported.

- 📦 **`import name { … }` now feeds the snippet's block placeholders.** The
  block is spliced where the snippet writes `{block}`, named sub-blocks are
  addressed as `{blocks.<key>}`, and a placeholder fed nothing splices
  nothing. Snippet definitions imported from a file are visible to imports
  that come later. `{block}` inside an argument list is refused because the
  directive tree cannot re-parse a spliced line the way Caddy's token layer
  can.

- 🔐 **`validate` and `adapt` now agree on three TLS/global spellings.** The
  `tls <email>` shorthand sets the ACME account while keeping automatic
  issuance; the global `persist_config` option accepts only `off` (the
  behaviour this server already has, since the admin config is never
  persisted) and refuses `on`; and the global `local_certs` option moves
  every site without its own certificate management onto the built-in local
  authority. `admin` with a block but no address now defaults its listen
  address instead of being refused.

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
  so no `0.1.7` configuration is affected. `argon2id` is now verified too —
  see the entry below.

- 🔐 **`basic_auth` verifies the declared algorithm and refuses plaintext.**
  The credential's algorithm comes from the directive
  (`basic_auth bcrypt|argon2id`), never from guessing at the hash text, so
  `pingclair hash-password --algorithm argon2id` output now authenticates
  instead of creating a login whose password is the hash text. Argon2id PHC
  strings are verified the way Caddy emits them (v=19) on the same bounded
  blocking pool as bcrypt, for H1/H2 and H3 alike. A credential that is not a
  valid hash of the declared algorithm — including any plaintext password —
  is refused at load on every path, DSL and JSON. Legacy JSON documents that
  said `"hashed": true` still load as bcrypt; the old plaintext JSON spelling
  is refused.

- 🚨 **`error` is a handler now.** `error [<status> [<message>]]` raises its
  status as the response, with Caddy's grammar: a lone three-digit number is
  the status, a lone word is a message on 500, and two arguments are message
  then status. A block may add `message <text…>` when no positional message
  was given. The directive is removed from the not-supported list.

- 🚨 **`handle_errors` routes raised error statuses like requests.**
  `handle_errors [<codes…>] { … }` registers a server-level error route:
  exact three-digit statuses and `Nxx` ranges OR together, and no codes
  catches every error. A raised status — from the `error` directive or a
  missing `file_server` file — runs the first matching route as a route body
  (`handle` blocks keep their mutually exclusive semantics, rewrites apply),
  and only falls back to the custom error page or the status text when no
  route answers. An error raised inside an error route responds directly
  instead of recursing; the duplicate-response and infinite-recursion shapes
  are covered by real-binary integration tests. H3 routes `error`-raised
  statuses the same way; H3 file-server 404 interception remains a tracked
  parity gap.

- 🧰 **`vars` gives each request a place to store values.** `vars
  [<matcher>] <name> <value>` and `vars { <name> <value> … }` set
  request-scoped variables, ordered least specific first so the most
  specific rule wins when several match. Values are templates: they may
  reference other placeholders and earlier variables. `{http.vars.*}`
  reads them back in any later placeholder, and the `vars` matcher gates
  routes on their value. The state lives in `http_policy.rs` and both H1/H2
  and H3 carry it, so a value set by middleware is visible on either
  transport. `vars` matcher placeholder keys stay refused: they resolve
  against the request's placeholder engine, which the router cannot reach.

- 🔍 **Named regexp captures become `{re.*}` placeholders.**
  `path_regexp [<name>] <pattern>` and
  `header_regexp [<name>] <field> <pattern>` record their capture groups
  when they match: `{re.<name>.<index>}`, `{re.<index>}`, and named groups
  by their group name, resolved the way Caddy's replacer does. The three
  `replaceable_upstream*` fixtures compile as a side effect, but their
  runtime behaviour — capture values used as upstream addresses — belongs
  to Phase H2, not this change.

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

- 🧱 **`request_buffers` and `response_buffers` now take effect**, on HTTP/1.1,
  HTTP/2 and HTTP/3 alike. Both were parsed and stored before this release and
  read by nothing; bodies always streamed. They now read that side's body into
  memory before passing it on, so a slow client or a slow reader occupies this
  proxy rather than a backend worker.

  ```
  :80 {
      reverse_proxy localhost:8080 {
          request_buffers 1MB
          response_buffers unlimited
      }
  }
  ```

  🛡️ **`unlimited` does not mean unbounded memory here, and that is a
  deliberate difference.** The format this DSL follows reads the whole body
  into memory for `unlimited` and warns at load that doing so can crash the
  process out of memory. Pingclair buffers up to a fixed 8 MiB ceiling and then
  streams the remainder — which is also what a positive size does once the body
  outgrows it. Bodies arrive complete either way; what changes is when they
  start moving. The ceiling is reported at startup, and the fall back to
  streaming is logged once, when it actually happens.

  📏 Sizes follow the SI/IEC split, so `1MB` is a million bytes and `1MiB` is
  1,048,576. This corrects a third instance of a units defect already fixed in
  `request_body max_size` and `log roll_size`: `1MB` used to compile to
  1,048,576 here, 4.86 % larger than written. Verified value-for-value against
  Caddy v2.11.4's own `adapt`.

  🧵 Buffering has no effect on a `fastcgi` transport, which reads and writes
  its own records without entering either HTTP body path. The server says so at
  startup rather than leaving the knob looking effective.

- 📊 **`metrics [<matcher>]`** serves the Prometheus scrape endpoint from a
  site route, so a scraper can reach the numbers without the admin API being
  exposed at all. Metrics and administration are different trust boundaries,
  and wiring them to one listener forces an operator to open one to get the
  other. Available on HTTP/1, HTTP/2 and HTTP/3 alike.

  ```
  :80 {
      metrics /metrics
      reverse_proxy localhost:8080
  }
  ```

  🛡️ Nothing about the directive restricts who may scrape — the route is as
  open as the site it sits in, so an endpoint on a public site wants a matcher
  or a `basic_auth` in front of it.

- 📊 **A global `metrics { … }` block** decides what the collected series are
  labelled with: `per_host`, `observe_catchall_hosts` and `otlp`. The same
  options may also be written inside a `servers` block, where only `per_host`
  is accepted; both spellings merge rather than overwrite, so the order they
  appear in does not change the answer. See the breaking note above for what
  `per_host` now controls. ⚠️ `otlp` is parsed but refused at startup: there is
  no OTLP exporter here, and starting with one configured would mean a
  dashboard that silently never receives anything.

- 🍃 **`tls { client_auth { verifier leaf … } }`** pins the client's leaf
  certificate: the certificate presented must be one of a known set, checked
  after the chain is verified. Every spelling the format allows is read —
  `verifier leaf file <path…>`, `verifier leaf folder <dir…>`, and the block
  form holding one or several loaders. A folder is walked recursively for
  `.pem` files and rescanned on reload, so dropping a certificate in is
  enough. ⚠️ Any other verifier module name is refused rather than accepted:
  a name we take and never act on is a site that believes it is authenticating
  clients and is not.

- 🔄 **`renewal_window_ratio <fraction>`** decides how early a certificate is
  renewed, as a fraction of its own lifetime rather than a fixed number of
  days. The default is a third, which on today's 90-day certificates is the
  30 days this server used before.
- 🌐 **`default_bind <address>`** gives every site that names no `bind` of its
  own one to inherit. A site's own `bind` still wins.
- 🔗 **`preferred_chains smallest`** and the `any_common_name` /
  `root_common_name` block are parsed and validated. ⚠️ They are **recorded
  and reported at startup, never acted on**: the ACME client this build uses
  takes whichever chain the authority offers and exposes no way to ask for
  another. The certificate works; the chain is simply not the one requested.

- 🔤 **`method <verb>`** replaces the request method before later handlers and
  the upstream see it. The argument is a template and is upper-cased after
  resolution, so `method post` asks the upstream `POST`.
- 🏷️ **`request_header [<matcher>] [+|-]<field> [<value>] [<replacement>]`**
  edits headers on the *request*, where `header` edits the response. Set, add,
  remove, and the three-argument regex search-and-replace all work, on
  HTTP/1.1, HTTP/2 and HTTP/3. Patterns are compiled when the configuration is
  published, never per request.
- 📥 **`request_body { max_size <size> }`** bounds one route's request body,
  overriding the site's limit — which is how the format models it, and which
  a Pingclairfile previously had no way to express at all. `read_timeout`,
  `write_timeout` and `set` are named as unimplemented rather than ignored.
- 🔪 **`abort`** ends the request with no response at all: no status, no body.
  On HTTP/1.1 and HTTP/2 the connection ends; on HTTP/3 the stream is reset and
  the other requests sharing that connection are untouched.

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
- 🗂️ **`try_files` is now the whole directive.** It expands into a `file`
  matcher plus a rewrite — which is what it is upstream — so it gained
  everything that matcher already did: the five selection policies through a
  `{ policy … }` block, a `=404`-style candidate that raises a status instead
  of matching, glob expansion in a candidate, the full set of placeholders the
  request can answer rather than only `{path}`, and a candidate carrying a
  query string. A first candidate that begins with `/` is a candidate again
  rather than an inline path matcher, matching how upstream registers the
  directive. `..`, an unresolvable placeholder, and an unrecognised policy
  still fail closed.
- 🌐 **Admin API.** `/load`, `/adapt` and `/stop`, Caddy-style config traversal
  with `@id` addressing, atomic reload of compatible listener policy,
  restart-required responses for listener topology, autosave and resume, and
  graceful stop.
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
- 🏗️ **Unix-socket upstreams.** `reverse_proxy unix//path/to.sock` dials a Unix
  domain socket, and `unix+h2c//path/to.sock` speaks prior-knowledge HTTP/2 over
  one — the shape local gRPC and application backends expect. Unix upstreams
  never enter the DNS refresher.
- 🧭 **Dynamic and replaceable upstreams.** `dynamic a name port` and
  `dynamic srv _svc._tcp.example.com` discover peers from DNS on a background
  refresher, so no request ever performs a lookup. Dial strings with request
  placeholders (`reverse_proxy {re.dial.1}`) are expanded per request and the
  resulting peers cached by host and port.
- 🏗️ **Wildcard internal certificates.** `tls internal` on a `*.example.com`
  site issues a wildcard leaf that serves every subdomain on H1, H2 and H3,
  matching Caddy's local-CA behavior for `.localhost`-style wildcard sites.
- 🔁 **Remaining reverse_proxy options.** `lb_retry_match` accepts Caddy's
  method, path, header, and expression forms — method/path/status shapes drive
  real runtime retry decisions, and unmappable expressions stay visible in the
  compiled config. `weighted_round_robin` carries inline weights, health probes
  may set the `Host` header, and `method`/`rewrite` mutate the upstream
  request. Buffer ceilings and transport tuning knobs without a runtime
  equivalent are accepted for compatibility and logged at startup.
- 🧭 **Response interception.** `handle_response`, `replace_status`,
  `copy_response`, and `copy_response_headers` evaluate the upstream response
  from its header alone — status and headers — before the client sees a byte.
  A replacement emits its static body exactly once and then drains the
  upstream body chunk by chunk, so 20 MB upstream bodies and SSE streams stay
  bounded on both H1/H2 and H3. The standalone `intercept` handler registers
  the same handlers for proxied responses.
- 🔐 **`forward_auth`.** One inline auth round trip before the request
  continues to the backend: a 2xx copies the configured identity headers onto
  their configured request destinations, deleting each destination first even
  when it was renamed (per GHSA-7r4p-vjf4-gxv4), and falls through; anything
  else is streamed to the client. Incoming header names containing `_` are
  dropped per GHSA-f59h-q822-g45g, matching Caddy's default, so the underscore
  alias cannot smuggle past `copy_headers`. Pingclairfiles now compile the
  shortcut into the same bodyless GET proxy subrequest used by legacy JSON,
  forwarding the original method and URI with identical H1/H2/H3 behavior.
- 🧵 **`php_fastcgi` over a real FastCGI client.** The shortcut expands the
  way upstream does — canonical-path redirect, `try_files` rewrite, and a
  FastCGI reverse proxy, each with its own matcher — and the proxy speaks the
  FastCGI 1.1 wire protocol itself: `BEGIN_REQUEST`, a streamed `PARAMS`
  environment, a streamed request body, and a CGI response parsed from the
  responder's `STDOUT`. Bodies stream record by record (bounded by 65,500
  bytes), `handle_response` error pages can serve files from disk, and a body
  without `Content-Length` is refused with 411 exactly like upstream's
  client. HTTP/3 refuses FastCGI routes with 501 for now.
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
- 📏 **`Range` handling follows RFC 9110 instead of guessing.** Three defects,
  all in one function, all found by executing it rather than reading it. A
  `Range` request for a **zero-byte file** underflowed `file_size - 1` before
  any guard could run — a debug build panicked the worker and dropped the
  connection, for a well-formed `bytes=0-5`; release wrapped and answered
  correctly, which is the only reason it was not shipping. A **malformed
  range** was silently repaired: `bytes=abc-99` became a 206 for bytes 0-99,
  a partial body answering a request the server could not read; it is now
  ignored, and the full body is served as nginx and Caddy do. And a **suffix
  range was read backwards** — `bytes=-5` means the *last* five bytes, and the
  first six were served instead.

- 📁 **`file_server` takes the subdirectives the format defines.** `hide`,
  `status`, `pass_thru`, `disable_canonical_uris`, `etag_file_extensions` and
  `precompressed` all work; `fs` selects a file-system module this build does
  not have and is still refused by name.

  **`precompressed` is now opt-in, which is a behaviour change.** Sidecar
  files were served unconditionally, so a request for `/app.js` with
  `Accept-Encoding: gzip` got `/app.js.gz` whenever that file existed —
  upstream serves it only when asked, and a stale sidecar is a wrong response
  rather than a missing feature. A site relying on sidecars must now write
  `precompressed`; in exchange the encoding order is the operator's, and an
  encoding this build cannot read is refused by name instead of being dropped
  from the list in silence.

  `hide` follows upstream's two rules: a pattern with no separator hides any
  path *component* of that name (`.git` hides `/a/.git/b`, not
  `/.gitignore`), one with a separator is a path prefix resolved against the
  document root. A hidden path answers exactly like a missing one, and a
  hidden sidecar stays hidden.

- 🔁 **The canonical trailing-slash redirect now follows the original
  request.** It was decided from the *rewritten* path and pointed at it, so
  `try_files {path} {path}/ /index.html` — which produces the canonical form
  itself — served the index directly where Caddy answers 308. Relative links
  in that document then resolved against the wrong base, which is the whole
  reason the redirect exists. It now redirects only when the filename survived
  the rewrite, and always back to the path the client asked for.

- 🏛️ **`pki` and `acme_server` are configuration, not behaviour.** The global
  `pki { ca <id> { name, root_cn, intermediate_cn, root/intermediate { cert,
  key, format } } }` block, a site's `acme_server { ca, lifetime,
  sign_with_root, challenges, allow, deny }`, `skip_install_trust`, and
  `trust_pool pki_root`/`pki_intermediate` all parse, validate and serialise,
  so a configuration written for upstream translates through `adapt`.

  **Pingclair does not act as a certificate authority issuing to other
  clients.** A site carrying `acme_server` is refused at startup by name,
  because a server that answers ACME requests and issues nothing is worse than
  one that says so — the clients would keep retrying against something that
  looks alive. A `trust_pool` naming a `pki` authority is refused when the
  trust store is built, rather than silently becoming an empty store that
  rejects every client at handshake time. `skip_install_trust` is accepted and
  changes nothing: the internal CA root is only ever installed by the explicit
  `pingclair trust` command, never automatically, which is what the option asks
  for.

- 📡 **DNS-01 and wildcard certificates, through Cloudflare.** `tls { dns
  cloudflare <token> }`, the global `dns`/`acme_dns`/`tls_resolvers` options,
  and the per-site `resolvers`, `dns_ttl`, `propagation_delay`,
  `propagation_timeout` and `dns_challenge_override_domain` settings all parse,
  compile, and are performed. This is what makes `*.example.com` obtainable at
  all — no other ACME challenge can prove control of a wildcard — and it makes
  issuance work on a host where port 80 is unreachable.

  The challenge is chosen **per name**, so a wildcard served next to ordinary
  hostnames uses DNS-01 while its neighbours keep HTTP-01, in one process. A
  published record is replaced rather than appended to, the zone is found by
  walking the name's suffixes (longest first, so a delegated sub-zone wins),
  and the record is removed on every path out of an order — including the ones
  that failed. `resolvers` is honoured: propagation is confirmed against the
  named servers, with caching off, before the CA is asked to look.

  **Cloudflare is the only provider this build ships.** Any other name is
  refused at startup, by name, with what is available — the server does not
  fall back to HTTP-01, because that cannot answer for a wildcard and the
  failure would surface at renewal as a validation error that never mentions
  the option the operator set. API tokens are held in a wrapper that prints
  nothing, so they cannot reach a log line or a panic message through a
  `Debug` derive added later.

- 🪪 **Mutual TLS.** `tls { client_auth { … } }` is now
  enforced during the handshake rather than merely parsed. All four upstream
  modes behave as their names say: `request` asks and accepts anything,
  `require` insists on a certificate without checking it, `verify_if_given`
  checks one only when offered, and `require_and_verify` does both. Trust
  material comes from `trust_pool inline`, `trust_pool file`, `trust_pool
  system`, or a `combined` tree of those, plus the deprecated flat
  `trusted_ca_cert`/`trusted_ca_cert_file` spellings; `trusted_leaf_cert` pins
  individual client certificates. Every certificate is read and parsed at
  startup, so a missing CA file stops the process instead of failing a
  stranger's handshake later.

  Two consequences worth knowing before turning it on, and both apply to every
  protocol. A listener carrying any mutual-TLS site **requires a request's
  `Host` (or HTTP/3 `:authority`) to be the name its handshake asked for**,
  answering `421` otherwise — without it, a client could offer an unprotected
  name in the ClientHello and then ask for the protected site by header. And
  that listener **turns TLS session resumption off**, because a resumed
  handshake carries no certificate request, so a ticket would keep admitting
  its holder after the certificate behind it expired or the trust pool changed.
  The cost is a full handshake per connection on that listener.

  HTTP/3 enforces the identical policy through its own BoringSSL context, and
  applies the same name check against `:authority`. This matters more than it
  sounds: HTTP/1.1 and HTTP/2 go through Pingora's acceptor while HTTP/3 goes
  through `tokio-quiche`, so a rule enforced on only one of them would be a
  rule any client opts out of by choosing the other transport — and `Alt-Svc`
  invites them to.
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

- 🔤 **A file whose name was not plain ASCII could not be fetched at all.**
  Nothing decoded percent-escapes on the way to the filesystem, and every client
  encodes a space and every client encodes a non-ASCII name — so `文件.txt`
  arrived as `%E6%96%87%E4%BB%B6.txt` and was looked up under that literal name.
  An entire class of filename was unreachable, which on a site whose filenames
  are not English means most of them.

  Under `try_files {path} /index.html` — the shape almost every static site uses
  — it was worse than a 404: the candidate simply did not match, so the request
  fell through to the SPA shell and looked exactly like a missing file.

  Escapes are now decoded in the two places a URL becomes a filename, through one
  shared rule: the static file server's path resolution and the `file` matcher's
  existence probe. Both decode **per path component, after the split and before
  the dot-segment check**, which is what keeps an escape from inventing
  structure — a decoded separator stays inside the component it came from, and a
  component that decodes to one is refused, since no filename can contain it.
  `%2e%2e` is a traversal and is refused as one. A malformed escape like `%zz` is
  taken literally, because a file may be named that way.

  Two things are deliberately *not* decoded. A link target the browse listing
  writes stays encoded, because it is a URL. And the request URI itself is only
  normalized as far as escapes whose byte is *unreserved* — `%70` to `p` — which
  RFC 3986 §6.2.2.2 requires of a normalizer and which keeps the result a valid
  URI that can go upstream. A reverse-proxied request therefore reaches its
  origin with `%2f`, `%20` and non-ASCII escapes exactly as they arrived.

  ⚠️ Two behaviour changes fall out of that. A proxied request now reaches the
  origin with unreserved escapes decoded, so an upstream that distinguishes
  `%41` from `A` — which RFC 3986 says it must not — sees the decoded spelling.
  And a `path` matcher now matches through those escapes, which is the point:
  `path /private/*` used to miss `/%70rivate/x` while an origin that normalizes
  served it anyway, so a matcher used as a gate was one escape from a bypass.

  📌 A remaining gap, recorded rather than hidden: the `file` matcher works in
  `String` and cannot represent a name that is not valid UTF-8, so on Unix such a
  file is reachable through `file_server` but not through `try_files`. Repairing
  it lossily would probe a different filename than the one requested.

  Found while fixing the browse listing, whose corrected link encoding made it
  visible.

- 🔤 **`templates` and FastCGI named files by their encoded spelling too.** Both
  turn a request path into a filename on code paths of their own, so both needed
  the same decode as the file server, and both went without it.

  For `templates` the failure was worse than a 404: an encoded template name did
  not match, so the request fell through to `file_server` and the template was
  served as **source**, `{{ … }}` and all. A template that misses leaks rather
  than fails. For FastCGI, `SCRIPT_FILENAME` and `PATH_TRANSLATED` are filesystem
  paths — CGI keeps `SCRIPT_NAME` and `PATH_INFO` encoded and these two decoded —
  so a script whose name was not plain ASCII was handed to the backend under a
  name it could not find.

  All three sites now share one confinement helper, which also closed a gap that
  was not about encoding at all: the H3 `templates` terminal joined the request
  path with **no `..` check of its own**, relying entirely on the plan that
  selects it having checked first. It has its own now, for the same reason the
  file server re-checks a configured index.

- 🔁 **`lb_retry_match` decides retries instead of being logged and ignored.**
  Expressions used to be kept as text, scanned for a few substrings, and
  announced at startup as "accepted but not evaluated". For a directive whose
  job is to *restrict* retries that is the worst available answer: someone
  writing one to stop non-idempotent requests being replayed got a server that
  kept replaying them, with a single log line as the only warning.

  Two things change for anyone already using it:

  - **Separate `lb_retry_match` blocks are alternatives, not one merged rule.**
    Each block is now its own condition and any of them permits a retry, with
    the conditions *inside* one block joined by AND — which is what upstream
    does. Previously every block was folded into shared `methods`,
    `path_patterns` and `status_codes` lists, so two blocks reading "retry
    POSTs" and "retry anything under /foo" became one rule demanding both, and a
    later block's `method` line silently replaced an earlier one's.
  - **An expression this server cannot evaluate now fails to load.** Response
    headers, transport errors, and the `method()`, `path()`, `host()`,
    `protocol()`, `query()`, `header()`, `path_regexp()` and `header_regexp()`
    conditions are all evaluated; anything else is refused by name at startup
    rather than accepted and ignored.

  A request carrying a body is still never replayed, and the attempt cap and
  deadline still bound every retry, whichever condition matched.

- 🧾 **`health_headers` sends every value written for a header, not one.** The
  block's signature is `<field> [<values...>]`, and three of the four shapes it
  allows were losing data while the configuration compiled: `X-Keys a b` sent
  only `a`, and `Same-Key 1` followed by `Same-Key 2` sent only `2`. A probe
  therefore did not carry what the operator wrote — and since a health check
  decides whether a backend receives traffic, a probe that is subtly not the
  request you configured is worth more than it looks. Values now accumulate in
  the order written, on both the `health_headers` block and the
  `health_check { header … }` spelling.

  JSON configurations keep loading either way: `{"X-Probe": "yes"}` and
  `{"X-Probe": ["yes"]}` mean the same thing.

- 🧵 **A `handle` block now runs every directive in it, not just the first.**
  The exclusivity `handle` is known for is between *sibling* blocks; the
  directives inside one block are a sequence. The two meanings shared one
  container, so any block whose first directive did not write a response
  swallowed the rest of the block —
  `handle /x/* { header X-A b; respond "ok" }` set the header and then
  answered nothing, arriving at the client as a 502, and
  `handle /api/* { request_header … ; reverse_proxy … }` set the header and
  never proxied. Sibling blocks are still mutually exclusive, because each one
  answers. The exclusive container survives under its own name for `try_files`,
  which is the one construct that genuinely needs it.
- 🔁 **`header <field> <find> <replace>` performs the search-and-replace it
  describes.** The third argument was read and discarded, so the line set the
  header to the *search* text — a configuration that loaded, started, and did
  something else. The response side now supports what the request side does:
  `+` append, `-` remove, three-argument regex replacement, and a trailing
  colon on the field name. `?field` sets a value only when the response does
  not already carry one, and `>field` and a block's `defer` line are accepted:
  they ask for the operation to be applied after the handler chain, which is
  the only moment this server applies response headers. Patterns and
  replacements may contain placeholders, resolved per request. Both header
  directives now read a line through one function, so they cannot drift apart
  again. `header { match { … } }` is refused by name rather than treated as a
  header called `match`.
- 🔄 **A short-lived certificate is no longer renewed the moment it is
  issued.** Renewal triggered whenever fewer than 30 days remained, full stop.
  For the 90-day certificates public CAs issue that is a third of the
  lifetime, which is why it looked right; for a 7-day certificate it is true
  from the second it is signed, so every scan would re-request every
  certificate, forever, against the authority's rate limits. The window is now
  a fraction of each certificate's own validity period.
- 📏 **`roll_size` rounds up to a whole mebibyte, which is the resolution a
  rotation threshold has.** Combined with the size fix below, `roll_size 1mb`
  now means what it means upstream: a million bytes, rounded up to 1 MiB. The
  byte value was previously kept verbatim, which looked more precise and rolled
  at a different point than the configuration was written for.
- 🔢 **`1MB` is now a million bytes, not 1,048,576.** Sizes follow the SI/IEC
  split the configuration format uses: `kb`/`mb`/`gb`/`tb` are powers of a
  thousand and `kib`/`mib`/`gib`/`tib` are powers of 1024. Every size the DSL
  reads was 4.9 % larger than written (7.4 % at `gb`), which in practice meant
  `log { roll_size 10mb }` rotated at 10,485,760 bytes rather than the
  10,000,000 the author asked for. Fractional sizes such as `1.5mb` now parse
  as well. ⚠️ This changes the effective value of existing `roll_size`
  settings; a deployment that depended on the old number should write `10mib`.
- 🔤 **HTTP/3 no longer discards a rewritten request method when proxying.**
  The HTTP/3 upstream call re-read the method from the raw QUIC request rather
  than from the request the handler chain had produced, so a `method` rewrite
  applied on HTTP/1.1 and HTTP/2 and was silently dropped on HTTP/3.
- 🧯 **Running out of file descriptors no longer takes a healthy backend out
  of rotation.** When this process cannot create a socket, `socket()` fails
  before a packet leaves the machine — the backend is healthy, idle, and has
  no idea anything happened. Every connect failure was nonetheless treated as
  evidence about the backend, so a local resource shortage marked it down for
  a ten-second cooldown. On a route with one backend there is nothing to fail
  over to, and the whole route stopped answering: measured on a burst that
  produced five local socket failures, **139 requests were rejected** with
  `no upstream available`, and a single request against a completely healthy
  backend kept returning 502 for nine seconds after the load had stopped and
  every descriptor had been returned. Connect failures are now classified by
  origin — a refused, unroutable, timed-out or TLS-failed backend still drives
  passive health and failover exactly as before, while descriptor exhaustion,
  ephemeral port exhaustion, and the other local shortages leave the backend
  in rotation. The same classification applies on HTTP/1.1, HTTP/2 and
  HTTP/3, and to both reverse-proxy and FastCGI upstreams.
- 🏷️ **A local resource failure now answers 503 instead of 502.** 502 claims
  the backend gave a bad answer, which is untrue when this server never
  reached it. 503 is what the overload path already returns, so capacity
  alerting does not need a second signal to watch.
- 🔀 **HTTP/3 now resolves a rewrite target's placeholders.** `HandlerConfig::Rewrite`
  ran `resolve_caddy_placeholders` on HTTP/1.1 and HTTP/2 and passed the
  template through verbatim on HTTP/3, so a site using `try_files` or
  `php_fastcgi` rewrote the URI to the literal text
  `{http.matchers.file.relative}` and the file server behind it answered 404
  for every request — the whole single-page-application pattern, silently, and
  only over HTTP/3.
- 🚨 **A `=404` candidate now raises its status on HTTP/3 too.** The `file`
  matcher answers with three outcomes, not two, and HTTP/3 evaluated pipeline
  element matchers through a boolean helper that collapsed the third
  (`Error`) into no-match. The same configuration therefore answered 404 over
  HTTP/2 and fell through to the next handler over HTTP/3.
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

- 🔐 **A cleartext client could make this proxy report its connection as
  secure.** The request scheme was decided by looking for port 443 or 8443 in the
  authority when the URI carried no scheme and no trusted `X-Forwarded-Proto` said
  otherwise — and on HTTP/1.1 the authority is the client's own `Host` header. So
  `Host: anything:443` over plain HTTP was reported as `https`, which is what
  `{http.request.scheme}` resolved to, what the `X-Forwarded-Proto` sent upstream
  said, and what the access log recorded. Anything behind this proxy that reads
  the scheme as "already encrypted, no redirect needed" believed it.

  The same guess was wrong in the other direction, and that half only broke
  things: a genuine handshake on any other port was reported as `http`, so
  HTTP/1.1 over TLS on a high port told its origin the request arrived in
  cleartext. HTTP/2 was unaffected there, because its request target is absolute
  and `:scheme` carried the truth regardless.

  The scheme now comes from the handshake — `Session::digest()`'s `ssl_digest` is
  `Some` exactly when TLS was terminated here, the same field the strict-SNI check
  already read. A trusted peer's `X-Forwarded-Proto` is still honoured, because a
  PROXY-protocol ingress that terminates TLS elsewhere leaves no local handshake
  to observe; an untrusted peer's is not. The port is never consulted, and
  `authority_port` is gone with it.

  Separately, one HTTP/3 placeholder site passed `http` where its eight
  neighbours passed `https`, so a `reverse_proxy` `rewrite` template resolving
  `{http.request.scheme}` disagreed with the rest of the same request. HTTP/3 runs
  on QUIC and cannot be cleartext. Found by review.


- 📊 **Anyone who could reach the Admin listener decided how many metric series
  this process held.** `pingclair_admin_http_requests_total` was labelled with the
  raw request path and the raw method, both copied off the wire. A Prometheus
  series outlives the request that created it, so 200 invented paths meant 200
  permanent series, and nothing bounded the set. Authentication was no defence:
  the counter records rejected requests too, and it should — a spike in 401s is
  the thing worth alerting on — so an unauthenticated client got a series per
  path it made up.

  The method was the same defect through a header nobody thinks of as free-form:
  an HTTP method is a token, not an enumeration, so `WIBBLE7 /config` arrived and
  became its own series.

  Both labels are now a fixed set decided by this server rather than by the
  caller: an endpoint class (`config`, `config_path`, `id_path`, `unknown`, and
  one per remaining route) and a method class that folds anything unrouted into
  `other`. The `path` label is accordingly spelled `endpoint`, because it names a
  class and not a path — the metric is new in this release, so nothing published
  was relying on the old spelling. The counter also got *more* useful: 60
  unauthorized probes are now one series reading 60 instead of 60 series each
  reading 1. Found by review.

- 📁 **A directory listing named the files `hide` was told to conceal, and did
  not encode the names it printed.** `hide` was applied when a file was asked
  for directly and when a pre-compressed sidecar was looked up, but not when a
  browse listing enumerated the directory holding it. So `hide *.env` answered
  `/api.env` with a 404 and then named `api.env` in the index of `/` — which is
  not concealment, it is a list of what to go and ask for. The listing now
  filters each entry through the same policy, and does it before the entry limit
  so the row count cannot disclose how many hidden names a directory holds.

  A listing is also the one page this server builds out of bytes it did not
  choose, and those bytes went in raw. A filename is now HTML-escaped where it is
  displayed and percent-encoded where it is a link target; the request path
  reflected into the title and heading is escaped as well. Encoding the link
  target is what stops a name from being read as something other than a path: a
  file called `javascript:alert(1)` is a legal filename, and its leading segment
  would have been taken for a URL scheme.

  Two side effects worth knowing about. A link now spells a name the way a URL
  has to — `hello%20world.txt` rather than `hello world.txt` — which is correct
  and also *visibly* correct, so it exposes a separate gap: this server does not
  percent-decode request paths, so a file whose name is not plain ASCII cannot be
  fetched at all. That was equally true before, because a browser encodes the
  link before sending it; it is now easy to see rather than easy to miss. And a
  listing has ceilings: 10,000 entries when the operator names no limit (matching
  `--file-limit`, where the previous default was unbounded) and a 1 MiB page,
  because the whole listing is built in memory and then compressed. A truncated
  listing says so on the page. Found by review.

- 🙈 **Two files holding secrets were written world-readable.** The Admin API's
  autosaved document carries the admin key and any DNS provider credentials the
  configuration named; a `storage-export` archive carries the internal CA's
  private key, every issued certificate's key, and the ACME account key. Both
  went through a plain create, which produces `0666 & !umask` — `0644` under the
  ordinary default — so every local user could read them. Both are now owner-only
  from creation rather than from a later `chmod`, which would leave a window in
  which the file is open and readable.

  The autosave also went through a fixed `<path>.tmp` with no `fsync`, so two
  writers collided and a crash could leave a truncated document where the next
  start expects a complete one. It now uses the same atomic writer the TLS store
  has always used: unique temporary, owner-only at creation, fsync, rename, fsync
  the parent.

  Alongside it, the admin key and DNS provider arguments are now held in a
  `SecretString` whose `Debug` prints `SecretString(redacted)`. Nothing prints
  them today; a derived `Debug` on a type containing a secret is one `{:?}`
  anywhere — including in a panic message — away from a log line, and no amount of
  care at each call site fixes that. Found by review.

- 🌊 **Three ways to ask a static file server for a large file allocated the
  whole file.** Streaming had one shape — a complete, uncompressed response above
  256 KiB — and everything else buffered. So the most expensive request this
  server could be asked for was `Range: bytes=0-` on the largest file in the
  document root: any `Range` header disabled streaming outright, and the range
  was clamped to the file, so the whole thing went into one `Vec`. A negotiated
  `Accept-Encoding` did the same, plus the compression CPU. And a pre-compressed
  `.br`/`.gz`/`.zst` sidecar was read whole even though its bytes on disk *are*
  the response body. The 64 MiB compressed-body budget only decided what to keep
  after the allocation had already happened.

  All three now stream. A `Range` streams from an offset with the reads bounded by
  the window; a sidecar streams as-is; and a file past a new 8 MiB compressible
  bound streams uncompressed rather than being buffered and compressed. Per-request
  memory is the 64 KiB chunk size in every case, whatever the file size and
  whatever the client asked for. Found by review.

- 📁 **A configured `file_server` index could name a file outside the document
  root.** The request path has always been confined — `..` is rejected before
  anything is opened — but the directory index was joined on *afterwards*, and
  nothing treated it as untrusted because it comes from the configuration. It is
  still a path component. `Path::join` is what makes that dangerous rather than
  merely wrong: joining an **absolute** path discards the left side, so an index
  of `/etc/passwd` did not resolve under the root, it replaced the root. A
  `../` form needed no such quirk. The resolved index also skipped the `hide`
  list and was accepted on `exists()`, which is true for a directory.

  Indexes are now refused at load if they could leave the root, and the runtime
  puts the index through the same confinement the request path gets, plus the
  `hide` check and a regular-file check. Found by review.

- 🔐 **An inline subrequest ignored the upstream TLS policy it was configured
  with.** A route's own reverse proxy compiles its `upstream_tls` block at load
  and dials under it. An inline subrequest — what `forward_auth` becomes — did
  not: the configuration parsed, passed validation, and was then discarded, so a
  subrequest told to trust one private CA dialled with the system trust store
  instead, one told to override the SNI sent the upstream's own name, and one
  told to present a client certificate presented none. For a `forward_auth`
  exchange that is the connection whose answer decides whether a request is
  allowed through.

  Subrequests now compile and apply the same policy through the same code as a
  main route, including its fail-closed case: trust material that cannot be
  loaded refuses the exchange rather than quietly dialling with system trust and
  no identity. Found by review, and `0.2.0-dev` only.

  📌 Only the JSON and Admin paths could reach this. The Caddyfile's
  `forward_auth` accepts `uri` and `copy_headers` and rejects anything else, so
  upstream TLS for a subrequest cannot be written in the DSL at all — a gap worth
  closing separately, but one that fails closed today.

- 🏠 **One capital letter in `Host` could move a request to a different site.**
  Virtual hosts were looked up by comparing the bytes of the client's `Host` or
  `:authority` against the bytes of the configured name. DNS names are
  case-insensitive and a trailing dot marks a name as absolute, so
  `SECURE.example.com` and `secure.example.com.` are the same host as
  `secure.example.com` — but the map disagreed, and the bytes are the client's to
  choose. The consequence was not a failed lookup: a miss falls through to the
  catch-all site, so a request addressed to a protected host with its name
  spelled unusually was served by whatever the default site allows — its routes,
  its access rules, its handlers.

  Configured names are now canonicalized once when a configuration is published,
  and a request's authority once per lookup, so both sides of every comparison
  are in the same form. This also fixes the same class of mismatch further in: a
  route's `host` matcher and the SNI-against-`Host` check on a mutual-TLS
  listener were each comparing a differently normalised name. Found by review.

- 🧹 **Four places decided what a client may hand to an origin, and they
  disagreed.** The HTTP/1.1 and HTTP/2 upstream path, the HTTP/3 one, inline
  authorization subrequests, and the FastCGI environment each carried their own
  list of fields to drop. Only the first was complete. The other three passed
  through `Proxy-Authorization` and `Proxy-Authenticate` — credentials addressed
  to *this* proxy, handed to somebody else — and the client's own `Forwarded`,
  which an origin has no way to distinguish from one this server wrote. HTTP/3
  additionally ignored the fields a client's `Connection` header names, and
  FastCGI turned a client's `Proxy` field into the `HTTP_PROXY` environment
  variable, which libraries inside a CGI script read to decide where to route
  their own outbound requests.

  All four now share one filter. HTTP/3 also rebuilds `Forwarded` from the
  verified socket peer, which HTTP/1.1 and HTTP/2 already did — previously it
  dropped nothing and added nothing, so the origin received whatever the client
  claimed.

  **What changes for a working setup.** Ordinary end-to-end fields —
  `Authorization`, `Cookie`, `X-Forwarded-For`, everything an application
  actually reads — are unaffected. A CGI script that was reading
  `HTTP_PROXY`, `HTTP_FORWARDED`, or `HTTP_PROXY_AUTHORIZATION` from a client
  will no longer see them; `REMOTE_ADDR` carries the verified client address and
  is the field to use instead. An authorization service behind `forward_auth`
  likewise stops receiving the client's `Forwarded`; give it what it needs with
  an explicit `header_up`.

- 🔁 **An upstream that died after reading a request could make this server
  send it again.** The most ordinary failure a reverse proxy sees is an origin
  closing a pooled keep-alive connection, and the request travelling on it
  getting no reply. What this server cannot know is how far that request got:
  the origin may have read every byte, committed the transaction, and died on
  the way back, which from here is indistinguishable from the request never
  arriving. The retry decision for that phase consulted only whether the
  connection had been reused and whether the attempt budget was spent — so a
  `POST` whose body still sat in Pingora's retry buffer was replayed, and the
  origin performed the operation twice. A request carrying a body is now never
  repeated once the connection was established, whatever else says yes.
  Bodyless requests still retry: a request line with nothing after it has
  nothing to perform twice.

  **The trade-off is deliberate.** A body-bearing request that would previously
  have been rescued by a retry now surfaces the failure to the client instead.
  Failing to charge a card once is recoverable; charging it twice is not.

  Alongside it, HTTP/3 evaluated `lb_retry_match` against the request the
  *client* sent rather than the one the origin received. With
  `reverse_proxy { method … }` or `rewrite` on the route those differ, so a
  policy saying "GETs are safe to repeat" could be deciding about a request the
  origin saw as a `DELETE`. Both transports now match on the request as sent
  upstream, which is what HTTP/1.1 and HTTP/2 already did by side effect of
  rewriting the header in place. Found by review, and `0.2.0-dev` only.

- 🎯 **Mutual TLS trusted a CA and then trusted everything it had ever
  signed.** A certificate says what it is for: a web server's carries an
  extended key usage of `serverAuth`, a client's carries `clientAuth`, and a CA
  grants those as separate permissions. The verification here built a trust
  path and stopped, never asking the question — BoringSSL runs its purpose
  check only when a purpose has been requested, and none was. So the answer to
  "is this chain valid" was being read as the answer to "may this certificate
  act as a client". Under the ordinary private-CA arrangement, where one
  authority issues certificates for a whole fleet, every server in that fleet
  held a working client identity for every other, and any host with a
  certificate from the CA could authenticate as any user of it. The verifier
  now asks BoringSSL for the SSL-client purpose before building the path, so
  the restrictions the CA wrote into its certificates are enforced — on
  HTTP/1.1, HTTP/2 and HTTP/3 alike, which matters because HTTP/3 gets its TLS
  from a different stack. Found by review, and `0.2.0-dev` only: `v0.1.7` had
  no mutual TLS. See the Breaking entry above for which certificates change
  status.

- 🪪 **A misspelled key in a `client_auth` block silently downgraded mutual
  TLS.** `mode` decides how hard a client certificate is checked, and its four
  values are not interchangeable: `require` demands a certificate and then
  never builds a trust path for it, while `require_and_verify` checks the chain
  against the configured pool. Writing `require_and_verify` under a mistyped
  key deserialised cleanly and validated cleanly, leaving `require` in force —
  the site asked every client for a certificate and then accepted whichever one
  arrived, self-signed included. Nothing in the load said so, and the running
  server looked identical either way. The types that name key material, name a
  trust anchor, or decide how hard an identity is checked now refuse fields
  they do not recognise, so the same document is a load error that names the
  key. Found by review, and `0.2.0-dev` only: `v0.1.7` had no mutual TLS to
  downgrade.

- 📡 **`hickory-resolver` moved from 0.24 to 0.26 for RUSTSEC-2026-0119.**
  `hickory-proto` 0.24.4 can be driven into quadratic work while compressing
  names during message encoding; the advisory's fix is 0.26.1. The DNS-01
  propagation check and the dynamic-upstream sources are the two places this
  crate resolves anything. 0.25 removed the synchronous resolver, so the
  dynamic sources now drive the async one on a current-thread runtime they own
  — the same arrangement hickory used to ship, written here instead. Name
  servers keep `trust_negative_responses: true`, which is what the old
  two-argument constructor set, so an `NXDOMAIN` still means the same thing.

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
- 🔐 **Control-plane success could leave the old authorization policy
  active.** Startup, Admin reload, signal reload, and HTTP/3 derived different
  subsets of listener policy. Rotating an Admin key or origin policy, disabling
  Admin, rotating an mTLS CA, or deleting a virtual host could return success
  while old credentials or routes still worked. Compatible reloads now compile
  one `PreparedListenerPolicy`, close versioned H1/H2/H3 and Admin publication
  gates, then publish routing, manual certificates, client-auth trust, the
  active Admin document, and Admin authorization before reopening them. Old
  keep-alive and QUIC connections carry their handshake generation and are
  refused after a trust-pool rotation. Whole-document replacement replaces the
  host table, so a deleted virtual host stops answering immediately. Admin
  ownership is committed under the same publication lock, so a queued SIGUSR1
  cannot overwrite a successful key rotation with the file's older policy. Any
  listener or TLS topology that cannot be rebuilt safely is rejected as
  restart-required with the last-known-good policy and autosave untouched.
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
