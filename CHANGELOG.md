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

📦 This section becomes `## [0.2.0]` when 0.2.0 is cut, and its text is the
release notes of that tag. It covers every change since `v0.1.7`, including
the three release candidates (`0.2.0-rc.1` on 2026-08-20, `0.2.0-rc.2` on
2026-09-19, `0.2.0-rc.3`).

0.2.0 is the release where a Caddyfile means what it means upstream. Route
selection, address parsing, matchers, compression, request limits and the TLS
store now follow Caddy's rules, and a directive that is not implemented is
refused by name instead of being accepted and ignored. The same release makes
the HTTP layer conform to the RFCs it implements — caching, conditional and
range requests, interim responses, stream errors on HTTP/2 and HTTP/3 — and
makes startup, reload and shutdown fail closed and drop no request.

### 🧾 The built-in error body is one sentence on every transport

One refusal had four bodies: a missing static file answered `404 Not Found` on
HTTP/1.1 and HTTP/2 and an empty `404` on HTTP/3, while a body over
`request_body max_size` answered nothing at all for a declared length on
H1/H2, `413 Request Entity Too Large` when the same H1 request streamed, and
the bare `Request Entity Too Large` on H3 (#252, #253). All three transports
now write one sentence from one place: the status, its reason phrase, and the
detail when this hop has one — the field a `431` names, per RFC 6585 §5.
Caddy's built-in bodies are empty; this is a deliberate divergence, recorded
here, because the alternative was a client that could not tell what was
refused. A configured `error_page <status>` still supplies the body, and
`handle_errors` still answers everything a handler raised.

### 🧾 An oversized header block is refused before routing on every transport

A request whose header block exceeded `limits { max_header_bytes }` was
answered differently by each transport. On HTTP/1.1 and HTTP/2 the site's
`handle_errors` rendered the 431, so its page replaced the one sentence naming
the field that was too large; on HTTP/3 the check ran after route resolution,
so the same request to a path that matched no route was answered `404` and
site variables and matchers ran on headers that should already have been
refused (#288, #229). All three transports now enforce the limit before any
matcher runs, answer the refusal directly rather than through `handle_errors`,
and name the field when one field alone is at fault. A configured
`error_page 431` still supplies the body, as it already did.

### 🃏 A manual wildcard certificate serves the names beneath it

A site written `https://*.sandbox.test { tls cert.pem key.pem }` refused a
handshake for `other.sandbox.test` with `unrecognized_name`, even though the
certificate covered that name — the manual table was read by exact spelling,
while the same site written with `tls internal` answered, because the internal
authority already matched wildcards (#285). Manual pairs now follow the same
one-label wildcard rule as issuance and the internal authority, on TCP and
HTTP/3, at startup and reload. A top-level `client_auth { … }` is refused with
the scope it belongs to instead of "`client_auth` looks like a second site".

### 🛡️ A glob expansion is bounded by the entries it reads

A `file` matcher's glob — `try_files /cache/*` — read and sorted a directory in
full before its 1,024-result ceiling could stop anything, and `**` walked a
whole tree for a pattern that matched nothing, so the work one request could
ask for was bounded by the filesystem rather than by the configuration (#240).
The walk now examines at most 16,384 directory entries per evaluation: far
above any plausible configuration, and far below a directory that would make
one request expensive. Names already collected are still followed, so a
truncated read costs matches at the end of a directory, not the ones it found.

### 🧮 The static caches are sized from the machine

The file server's caches had fixed ceilings — 64 MiB of compressed bodies,
16 MiB of raw ones, 4,096 metadata entries — and the keepalive pools may
reserve 512 idle descriptors per connector per worker. Those numbers are now
what they always were *at most*: at startup the process sizes the caches from
the memory it may actually use (a cgroup limit first, then the machine's
available memory) and logs the values it chose, so a 512 MiB container keeps a
sixteenth of what a 16 GiB host does instead of the same fixed block. The
descriptor side already warned when the pools alone can exceed
`RLIMIT_NOFILE`; both halves now belong to one sizing policy (#33).

### 🚫 A directory listing answers `GET` and `HEAD` only

With `browse` on and no index file, a `POST` to the directory received the
`200` listing: the browse branch returned before the method check that
answers `405` for a file. A listing is this server's representation of the
directory, so it is served to the same methods a file is, and the refusal
carries `Allow: GET, HEAD` (#242). A path that does not exist is still `404`.

### 📏 A `HEAD` describes the response its `GET` would receive

With `encode` configured, a `HEAD` forwarded the origin's identity fields while
the matching `GET` received compressed bytes — a client that sized its
download from the `HEAD` was told the identity length and then read a shorter,
encoded body (#264). A `HEAD` now announces the negotiated coding, drops the
identity `Content-Length` (the compressed length is only known once the body
has been produced, and RFC 9110 §8.6 makes the field the content's length),
and carries the same weakened validator as the `GET`. Caddy 2.11.7 announces
the coding too but reports the length of a gzip stream over an *empty* body,
which describes neither representation; this release omits the field instead.

### 🗜️ A range over a precompressed sidecar ranges over the sidecar

A client that accepted `gzip` and sent a `Range` was answered with the identity
representation — identity bytes, identity `Content-Range`, identity `ETag` —
while the same client's full request received the sidecar, because any parsed
range skipped the precompressed branch entirely (#254). The sidecar *is* the
representation the client negotiated, so its bytes are what a range applies
to, which is what Caddy serves. `If-Range` and `If-None-Match` compare against
the sidecar's own tag for that shape, and a range whose `If-Range` does not
hold is ignored in favour of the whole sidecar. On-the-fly compression still
never applies to a range response: a compressed stream cannot start at an
arbitrary offset.

### 🏷️ A configured `ETag` is the validator, not just a label

A site that set `ETag` with the `header` directive sent that tag to every
client, but `If-None-Match` and `If-Range` were still compared against the file
server's own size-and-mtime tag — so revalidating with the tag the client had
been given answered `200`, while a tag nobody had ever been sent answered `304`
(#265). Preconditions now read back the tag the site's own header policy would
put on the response and use it as the representation's validator, which is what
RFC 9110 §13.1.2 asks for: one representation, one tag on the wire, and the tag
the client was given is the one that decides.

### 🗜️ A compressed response stays decodable when trailers end it

An HTTP/2 origin can end a response with trailing HEADERS, announced or not,
and Pingora writes that task as the end of the message instead of the `Done`
task the response encoder used to wait for. The gzip or zstd trailer was never
written, so the client held compressed bytes it could not decode and the whole
response was lost (#225). The encoder now finalizes on the trailer task as
well. Trailer fields cannot share the final body chunk through this
dependency's hook, so a compressed response drops them: the body decodes,
while the same response without `encode` keeps its trailers.

### 🧵 `php_fastcgi` measures a body that did not declare its length

A request to a `php_fastcgi` route was answered `411 Length Required` whenever
it carried no `Content-Length` header: a chunked upload, and a bodyless `POST`
or `DELETE`, which RFC 9112 §6.3 says simply has no body. PHP-FPM does read
exactly `CONTENT_LENGTH` bytes from STDIN, so the proxy now reads a lengthless
body itself — up to the route's `request_buffers`, and this server's own
buffering ceiling when the route set none — and sends the measured length,
while a request that says nothing about a body arrives as `CONTENT_LENGTH: 0`.
A lengthless body larger than the ceiling is refused with `413 Payload Too
Large` instead of reaching php-fpm as a body the responder would read as empty.
The same policy holds on HTTP/1.1, HTTP/2, and HTTP/3 (#248).

### 🛑 HTTP/3 cancellation releases idle upstream requests

Cancelling an HTTP/3 request now releases its upstream exchange even when the
origin has stopped writing an SSE response or has not sent response headers.
The other streams on that QUIC connection remain usable. Previously, a peer's
`STOP_SENDING` could remain unnoticed until the next response write (#286).

### 🛡️ Canonical static redirects preserve the origin and query

Directory and file redirects retain the original query string on HTTP/1.1,
HTTP/2, and HTTP/3. Redirect paths clean repeated slashes and dot segments and
escape literal backslashes, so a request such as `//sub?x=1` receives
`Location: /sub/?x=1` instead of a reference to another host. Rewrites that
change the filename and `disable_canonical_uris` retain their existing behavior.

### 🪪 An exact site's `client_auth` outranks a wildcard

A wildcard site with `tls { client_auth … }`, such as `*.example.test`, used
to impose its demand on a different site on the same port that has an exact
name, such as `public.example.test`, and configured no `client_auth` at all:
every visitor to the exact site was asked for a client certificate, and one
signed by the wildcard's CA was accepted (#259). The handshake now picks the
client-certificate policy of the most specific site for the name the client
sent, exactly as it already picks the certificate, on HTTP/1.1, HTTP/2 and
HTTP/3. A site without `client_auth` is that statement too: "no client
certificate here". The listener still requires the handshake name and the
`Host` (or `:authority`) to agree, so the open name cannot be used to reach a
name only the wildcard covers.

📦 **Upgrade:** An exact site that shares a port with a wildcard `client_auth`
site no longer asks its clients for a certificate. If it relied on the
wildcard's demand, give it its own `client_auth` block.

### ⚠️ Before you upgrade

Most configurations keep working unchanged. These are the changes most
likely to alter what an existing configuration does; each links to its entry
below, which ends with what to write instead.

- **Static ranges stream when compression is enabled.**
  → [Static ranges stream when compression is enabled](#-static-ranges-stream-when-compression-is-enabled)
- **Precompressed sidecars have independent validators.**
  → [Precompressed sidecars have independent validators](#️-precompressed-sidecars-have-independent-validators)
- **Empty static bodies have a shared entry ceiling.**
  → [Empty static bodies have a shared entry ceiling](#-empty-static-bodies-have-a-shared-entry-ceiling)
- **Immediate-flush routes bypass the response cache.**
  → [Immediate-flush routes bypass the response cache](#-immediate-flush-routes-bypass-the-response-cache)
- **Response cache budgets apply at load and reload.**
  → [Response cache budgets apply at load and reload](#-response-cache-budgets-apply-at-load-and-reload)
- **Response cache freshness includes upstream age.**
  → [Response cache freshness includes upstream age](#-response-cache-freshness-includes-upstream-age)
- **`uri strip_prefix`, `strip_suffix` and `path_regexp` resolve placeholders.**
  A `${1}` group reference in a `path_regexp` replacement is now read as the
  placeholder `{1}`; write `$1`.
  → [`uri` operands resolve placeholders](#-uri-operands-resolve-placeholders)
- **`servers { trusted_proxies … }` takes Caddy's module spelling.** Write
  `trusted_proxies static <ranges>` there, and one line per scope.
  → [`trusted_proxies` inside `servers` reads as upstream](#-trusted_proxies-inside-servers-reads-as-upstream)
- **An upstream weight of 0 drains it; weights above 100 are refused.** A pool
  whose every primary has weight 0 is refused too.
  → [A zero upstream weight drains that upstream](#-a-zero-upstream-weight-drains-that-upstream)
- **A configured header with CR, LF or NUL in its value, or a name that is not
  a token, is refused at load.** Remove the stray bytes.
  → [Configured header fields must be valid fields](#-configured-header-fields-must-be-valid-fields)
- **A middle `*` no longer jumps ahead of an equal-length sibling.** Put the
  intended winner first when equal-length patterns overlap.
  → [Equal-length route patterns keep file order](#-equal-length-route-patterns-keep-file-order)
- **Braces in route paths are literal.** Use `path_regexp` for captures.
  → [Route braces stay literal](#-route-braces-stay-literal)
- **Host validation and HTTP/1 parser decisions now follow Go.**
  → [HTTP parser decisions follow Go](#-http-parser-decisions-follow-go)

- **Malformed chunked request bodies now receive 400 and close instead of 500.**
  → [Malformed chunked bodies are client errors](#-malformed-chunked-bodies-are-client-errors)

- **Raw spaces and controls in HTTP/1 request targets now receive 400 and close.**
  → [Raw request targets reject whitespace](#-raw-request-targets-reject-whitespace)

- **HTTP/1.1 without Host now closes after its 400 response.**
  → [Short HTTP requests answer and close](#-short-http-requests-answer-and-close)

- **A CONNECT for a host no site names is refused and closes instead of
  answering 200; a CONNECT without a port receives 400.**
  → [An unmatched CONNECT is refused and closes](#-an-unmatched-connect-is-refused-and-closes)

- **A specific address and a wildcard on one port share one listener.** A
  `bind`-restricted site beside a wildcard site on the same port is refused,
  and a `0.0.0.0` site beside a `[::]` site on one port answers over IPv6.
  → [One port, one listener](#-a-specific-address-and-a-wildcard-on-one-port-share-one-listener)
- **`bind` now applies to a site with an explicit address or port.** Such a
  site listens only on its `bind` host; address a `servers` block to that host.
  → [`bind` applies to every listener](#-bind-applies-to-every-listener-of-a-site)
- **A bound site's automatic HTTP redirect listens on its `bind` host.** It
  is no longer reachable on other interfaces.
  → [Redirect listener](#-the-automatic-https-redirect-listens-where-its-site-does)
- **A site's `listen` directive keeps the address it names.** `listen
  127.0.0.1:8080` binds loopback only; a hostname or an unbracketed IPv6
  address in `listen` is refused.
  → [`listen` keeps its address](#-listen-keeps-the-address-it-names)
- **`bind` and `default_bind` with more than one address are refused.** Only
  the first was ever used; write one address or one site per interface.
  → [One bind address](#-bind-takes-one-address)
- **`default_bind` now applies to JSON configurations.** A JSON site with no
  `bind` and no explicit listen address listens only on `default_bind`.
  → [`default_bind` in JSON](#-default_bind-applies-to-json-configurations)
- **FastCGI HEAD and download limits apply on H1/H2.** Expect no HEAD body and
  budget download time according to configured rate limits.
  → [FastCGI body policy](#-fastcgi-bodies-honor-head-and-download-pacing)
- **Oversized FastCGI parameters return 431.** Reduce the header or environment
  value so each encoded parameter fits in one FastCGI record.
  → [FastCGI parameter limits](#-oversized-fastcgi-parameters-return-431)
- **Broken FastCGI bodies now abort the response.** Treat a reset or incomplete
  response as a failed download and retry only when safe.
  → [FastCGI body failures](#-fastcgi-body-failures-abort-the-response)
- **Admin config writes honor `If-Match`.** Refresh the config and its Etag
  after a 412 before retrying.
  → [Admin config validators](#️-admin-config-validators)
- **Admin reads keep serving through reload.** Read the returned generation;
  retry a write after a conflict if another reload changed its authorization.
  → [Admin reads during reload](#️-admin-reads-during-reload)
- **Missing Admin config reads return `200 null`; standard metric names change.**
  Check the returned value and update dashboards using the metric mapping.
  → [Admin config reads and metric names](#-admin-config-reads-and-metric-names-follow-caddy)



- **Automatic HTTPS changes its plaintext listener and redirects.**
  `disable_redirects` leaves the automatic HTTP port unbound.
  → [Automatic HTTPS follows the configured listener policy](#-automatic-https-follows-the-configured-listener-policy)
- **Scheme-only site addresses inherit global ports.** Explicit ports stay as written.
  → [Scheme-only addresses use global ports](#-scheme-only-addresses-use-global-ports)
- **`http://[::1]` names a site instead of becoming the catch-all; a malformed
  bracketed address is refused.** Other `Host` values stop reaching that block.
  → [Bracketed IPv6 site addresses name a site](#-bracketed-ipv6-site-addresses-name-a-site)
- **Request no-transform disables proxy encoding.** Expect identity responses.
  → [Proxy encoding respects request no-transform](#️-proxy-encoding-respects-request-no-transform)
- **Static gzip ETags include quality.** Expect one cache revalidation.
  → [Static gzip validators include quality](#️-static-gzip-validators-include-quality)
- **Static encode matchers see header policy.** Review header-based matchers.
  → [Static encode matchers see response policy headers](#️-static-encode-matchers-see-response-policy-headers)
- **H3 compression removes identity digest trailers.** Update digest consumers.
  → [H3 encoding removes obsolete integrity trailers](#️-h3-encoding-removes-obsolete-integrity-trailers)
- **Local encoding cache keys survive header policy.** Review downstream cache keys.
  → [Local header policy preserves encoding Vary](#️-local-header-policy-preserves-encoding-vary)
- **Disabled encoding rejects blocks.** Remove contradictory encode blocks.
  → [Encode off rejects blocks](#-encode-off-rejects-blocks)
- **`encode` blocks now take effect and reject unknown settings.** Review size floors and response matchers.
  → [Encode blocks take effect](#️-encode-blocks-take-effect)
- **Static compression offers exactly the encode list in order.**
  → [Static compression follows the coding list](#️-static-compression-follows-the-coding-list)
- **Static file responses always send Vary: Accept-Encoding, even without encode.**
  → [Static responses always vary by encoding](#️-static-responses-always-vary-by-encoding)
- **Proxied responses on encode sites send Vary: Accept-Encoding even when served as identity.**
  → [Proxy encode responses always vary by encoding](#️-proxy-encode-responses-always-vary-by-encoding)
- **Re-encoding a proxied response turns its strong ETag into a weak validator.**
  → [Proxy compression weakens strong etags](#️-proxy-compression-weakens-strong-etags)
- **Static compression follows the same content-type allow-list as proxy compression.**
  → [Static and proxy compression share mime rules](#️-static-and-proxy-compression-share-mime-rules)
- **Both response paths apply encode gzip levels and use the Caddy default of 5.**
  → [Compression uses the configured gzip level](#️-compression-uses-the-configured-gzip-level)
- **Accept-Encoding wildcard acceptance no longer enables an unnamed coding.**
  → [Wildcard acceptance does not enable compression](#️-wildcard-acceptance-does-not-enable-compression)









- **Empty startup can load its first HTTP listeners.** TLS listeners and later topology changes still require restart.
  → [Admin-only startup accepts its first HTTP generation](#-admin-only-startup-accepts-its-first-http-generation)
- **Manual TLS requires a named site.** Unnamed and `_` sites are rejected instead of silently ignoring their certificate sources.
  → [Unnamed manual TLS fails closed](#-unnamed-manual-tls-fails-closed)
- **Empty and stdin startup survive reload signals.** SIGHUP is ignored; SIGUSR1 reports that no file reload source exists.
  → [Reload signals remain safe without a file](#-reload-signals-remain-safe-without-a-file)
- **`-c -` always reads stdin**, even when the working directory contains a directory named `-`.
  → [Stdin takes precedence over filesystem entries](#-stdin-takes-precedence-over-filesystem-entries)
- **Running without a configuration now starts the admin API.** Supply an explicit path when a missing file must fail startup.
  → [Run starts empty when no default configuration exists](#-run-starts-empty-when-no-default-configuration-exists)
- **CLI scripts can use Caddy-style configuration flags.** Explicit adapters override filename extensions.
  → [Run and validate accept configuration flags](#-run-and-validate-accept-configuration-flags)
- **Validation now rejects unusable TLS material.** Fix malformed or mismatched manual pairs before deployment.
  → [Validate loads manual TLS material](#-validate-loads-manual-tls-material)
- **`handle_errors` pages render, and answer proxy and body-size errors.**
  An error route ending in `file_server` serves its page with the error's
  status, and a `502` or `413` now reaches the error routes too.
  → [`handle_errors` serves its own pages](#-handle_errors-serves-its-own-pages)
- **Routes are chosen in directive order**, not by the most specific path.
  A `redir`, `route` or `handle` catch-all can now answer requests that a more
  specific `respond` used to take.
  → [Directive order decides which route answers](#-directive-order-not-the-most-specific-path-decides-which-route-answers)
- **Nothing is compressed unless `encode` asks.** Sites that relied on the old
  gzip-by-default must add `encode gzip`.
  → [A site compresses only where `encode` asks](#️-a-site-compresses-only-where-encode-asks)
- **No request-body ceiling by default.** The old 1 MiB limit is gone; set
  `request_body { max_size … }` to keep one.
  → [No request-body ceiling unless the configuration asks for one](#-no-request-body-ceiling-unless-the-configuration-asks-for-one)
- **`remote_ip` matches the connection's peer.** Behind `trusted_proxies`, use
  `client_ip` to match the forwarded client.
  → [`remote_ip` matches the connection's peer, `client_ip` the client](#-remote_ip-matches-the-connections-peer-client_ip-the-client)
- **`{remote_host}` is the connection's peer.** Behind `trusted_proxies`, use
  `{client_ip}` for the forwarded client, e.g. in `header_up X-Real-IP`.
  → [`{remote_host}` is the connection's peer, `{client_ip}` the client](#-remote_host-is-the-connections-peer-client_ip-the-client)
- **`{remote_ip}` is refused at load.** It was never Caddy's; write
  `{client_ip}` for the client or `{remote_host}` for the peer.
  → [`{remote_ip}` is refused](#-remote_ip-is-refused-write-remote_host-or-client_ip)
- **A site address with a port and no scheme is HTTPS**, as upstream:
  `example.com:8080` needs `http://` in front to stay plaintext.
  → [Breaking](#️-breaking)
- **`*.example.com` covers one label**, not any depth.
  → [Breaking](#️-breaking)
- **Startup refuses a taken port** — HTTP, HTTP/3 (UDP) and admin alike —
  instead of logging and carrying on.
  → [A taken admin port stops startup](#-a-taken-admin-port-stops-startup-instead-of-being-logged)
- **The internal CA moves** to `pki/authorities/local/` and is not migrated;
  run `pingclair trust` again after upgrading.
  → [The local TLS store is filed the way Caddy files it](#️-the-local-tls-store-is-filed-the-way-caddy-files-it)
- **Automatic retries only repeat idempotent methods** once the upstream has
  seen the request.
  → [The retry policy has one implementation](#-the-retry-policy-has-one-implementation)
- **Static-file ETags change once** on upgrade, so caches revalidate each file
  one time.
  → [Static-file ETags describe one exact body](#️-static-file-etags-describe-one-exact-body)
- **Metrics are off unless `metrics` is set.** Add the global `metrics`
  option to keep collecting; without it the scrape endpoints answer empty.
  → [Metrics are collected only when `metrics` is set](#-metrics-are-collected-only-when-metrics-is-set)
- **Route paths ignore letter case.** `respond /Admin/*` now also answers
  `/admin/x`, as in Caddy; a site that used case to tell two routes apart
  needs a `path_regexp`.
  → [Every route path ignores letter case](#-every-route-path-ignores-letter-case)
- **A malformed `hide` pattern is refused at load**, where it used to be
  dropped with a warning while the server started. `hide [secret` has to
  become a pattern whose `[` set closes.
  → [Security](#-security)
- **Path matchers see escapes decoded.** `/secret%21` now matches
  `path /secret!`; a pattern written with an escape such as `/a%20b` has to
  be written decoded to keep matching.
  → [Security](#-security)


- **`handle_path`, `uri strip_prefix` and `uri strip_suffix` ignore letter
  case** too, so `handle_path /API/*` strips `/api` from `/api/x`.
  → [A strip ignores letter case like the route that chose it](#-a-strip-ignores-letter-case-like-the-route-that-chose-it)
- **Every address of a multi-name site gets a certificate**, on every
  protocol. `tls internal` issues one more leaf per extra name, and a
  `tls <cert> <key>` pair now also answers for the site's other names.
  → [Every address of a site has a certificate](#-every-address-of-a-site-has-a-certificate)
- **`lb_try_duration` no longer cuts a response.** It now only limits how
  long new attempts may start, so a slow answer or a long event stream is
  bounded by `transport http` timeouts instead.
  → [`lb_try_duration` limits retrying, not the response](#-lb_try_duration-limits-retrying-not-the-response)
- **A missed upstream keepalive reuse is logged at `DEBUG`**, not `ERROR`.
  Alerts matching `failed to acquire reusable stream` stop firing.
  → [A keepalive reuse miss is not an error](#-a-keepalive-reuse-miss-is-not-an-error)
- **A request header has one minute by default**, start to finish, where it
  had no limit unless `limits { header_timeout }` was set. An idle HTTP/1
  keepalive connection is therefore closed after a minute without a request,
  and an HTTP/3 request stream whose header is still unfinished after a minute
  is reset. Set `limits { header_timeout … }` to choose another bound.
  → [Security](#-security)
- **A request body may pause one minute by default** between two reads
  before the request is answered `408`, or, for an HTTP/2 upload through
  `reverse_proxy`, has its stream reset. An upload client that stalls longer,
  such as a quiet gRPC client stream, needs `limits { body_timeout … }`.
  → [Security](#-security)
- **`CF-Connecting-IP` no longer names the client by itself.** A deployment
  behind Cloudflare that relied on it must add
  `servers { client_ip_headers CF-Connecting-IP }`.
  → [`CF-Connecting-IP` counts only when `client_ip_headers` lists it](#️-cf-connecting-ip-counts-only-when-client_ip_headers-lists-it)
- **Admin `/config` reads mask secrets.** An export can no longer be posted
  back to `/load` unchanged; put the real `api_key` and DNS arguments back.
  → [The admin API's configuration reads mask secrets](#-the-admin-apis-configuration-reads-mask-secrets)
- **`handle`, `handle_path` and `route` refuse a token that is not a
  matcher.** `handle *.php { … }` used to compile into a block that answered
  every request; write `handle @php { … }` with `@php path *.php`.
  → [A block directive takes `*`, a `/path` or `@name`](#-a-block-directive-takes--a-path-or-name)
- **An exact site no longer inherits a wildcard's `client_auth`.** A site
  that relied on it needs its own `client_auth` block.
  → [An exact site's `client_auth` outranks a wildcard](#-an-exact-sites-client_auth-outranks-a-wildcard)

The full list of breaking changes is under [Breaking](#️-breaking); the
known defects that ship are under
[Known defect — WebSocket upgrades under load](#-known-defect--websocket-upgrades-under-load)
and [Other known defects that ship](#-other-known-defects-that-ship).

### 🌊 Static ranges stream when compression is enabled

Large ranges on compressible static files now stream in bounded chunks while retaining identity encoding and the correct partial-response headers.

**Upgrade:** No configuration change is needed; concurrent large range requests no longer allocate the complete range.

### 🏷️ Precompressed sidecars have independent validators

Precompressed files use their own size and modification time for ETags, with tags distinct from live compression. Sidecars take precedence over cached live-encoded bodies, and conditional requests use the selected sidecar tag.

**Upgrade:** Sidecar ETags change once; clients revalidate their encoded copies. Replacing only a sidecar now invalidates that copy.

### 🧱 Empty static bodies have a shared entry ceiling

Static body caches share a 16,384-entry ceiling in addition to their existing byte budgets. Empty files and stale file identities compete for those slots; eviction and teardown return them.

**Upgrade:** No configuration change is needed; sites with many tiny or empty files may see more cache eviction.

### 🧊 Immediate-flush routes bypass the response cache

Routes with `flush_interval -1` bypass response-cache admission using state computed when configuration loads. The existing SSE content-type safeguard remains in effect.

**Upgrade:** Remove reliance on cached responses from immediate-flush routes; use a separate ordinary route if caching is desired.

### 🧊 Response cache budgets apply at load and reload

The process-wide response-cache ceiling is configured before traffic and resized on reload. Shrinking it evicts retained entries immediately; removing caching drains the store. The existing requirement that caching routes agree on `max_size` remains.

**Upgrade:** Use the same `max_size` on every caching route. Reloads now apply a changed ceiling without a restart.

### ⏳ Response cache freshness includes upstream age

Stored responses account for upstream `Age`, apparent age from `Date`, and upstream response delay under RFC 9111. Cache hits retain that age, and `Expires` supplies a lifetime relative to `Date`. Route TTL remains a fallback and sanitized private headers stay stripped. Validated bodies use the new clock even when the validation forbids storage; extremely old responses bypass caching.

**Upgrade:** Already-aged responses expire sooner; expect revalidation or origin requests earlier than the previous local-only countdown.

### 🔌 An unmatched CONNECT is refused and closes

A `CONNECT` whose authority named no site used to fall through to the
no-matching-site answer: an empty `200` on plaintext listeners. A `200` to
`CONNECT` tells the client its tunnel is open, so it starts sending tunnel
bytes — and on HTTP/1.1 this server read those bytes as the next request and
served it. Every `CONNECT` now gets the same refusal whether or not its
authority names a site: `405` with `Allow`, and the HTTP/1.1 connection closes
(RFC 9931 §8). A target without a usable port (`CONNECT example.com`,
`example.com:0`) is malformed and receives `400` instead (RFC 9110 §9.3.6).
HTTP/2 and HTTP/3 give the same answers; on HTTP/3 an unmatched `CONNECT` used
to receive `404`.

📌 Upgrade note: nothing that worked changes. A client that relied on the `200`
was never given a tunnel; Pingclair is a reverse proxy and opens none. Send
`CONNECT` targets as `host:port`. Caddy v2.11 answers an unmatched `CONNECT`
with `200` too; this follows the RFC rather than that behaviour.

### 🧭 `uri` operands resolve placeholders

`uri strip_prefix /api/static/{re.sample.1}` strips the prefix the
`path_regexp` matcher captured, and `uri path_regexp ^/old/(.*)$
/new/{http.request.scheme}/$1` writes `/new/http/…`, on HTTP/1.1, HTTP/2 and
HTTP/3. Only `rewrite`'s target used to be resolved: a strip compared the path
against the literal braces, never matched, and forwarded the request untouched,
and a regexp replacement put the braces themselves on the wire. Caddy resolves
every operand, and so does this release (#278).

📌 Upgrading: a literal operand behaves exactly as before. A `path_regexp`
replacement is resolved before the regexp sees it, as upstream, so the braced
group reference `${1}` reads as the placeholder `{1}` and disappears; write
`$1`.

### 🌐 `trusted_proxies` inside `servers` reads as upstream

Inside `servers {}`, `trusted_proxies` names an ip_source module first, as in
Caddy: `trusted_proxies static 12.34.56.0/24` and `trusted_proxies static
private_ranges` load, and the bare `trusted_proxies 12.34.56.0/24` is refused
with the `static` spelling in the message. Caddy refuses the bare form in that
position too, so a file that loaded here could not be carried back. A second
`trusted_proxies` line in the same scope is refused as well: Caddy keeps only
the last line, while this build used to add the lines together and so trusted
more peers than the same file does upstream (#142).

📌 Upgrading: the top-level `trusted_proxies 10.0.0.0/8`, this build's own
option, is unchanged. Inside `servers {}`, put `static` in front of the
ranges, and merge repeated lines — including a top-level line plus a
`servers {}` one — into one.

### 🔀 A zero upstream weight drains that upstream

`lb_policy weighted_round_robin 0 1` now sends nothing to the first upstream.
The zero used to be clamped to 1 at selection time, with no log line, so a
backend drained for a cutover kept taking half the traffic. Caddy skips a
zero-weight upstream the same way. The block spelling, `to … { weight 0 }`,
used to be refused and now means the same thing. Any policy honours the
drain, not only round robin (#266).

📌 Upgrading: a weight above 100 used to be clamped to 100 silently and is now
refused, because the selector expands each weight into that many table slots;
scale the weights down to keep the same ratio. A pool in which every primary
upstream has weight 0 is refused, since it could answer nothing but errors.

### 🚫 Configured header fields must be valid fields

`header X-Inject "legit\r\nInjected-Header: pwned"` used to validate. HTTP/1.1
and HTTP/2 then cancelled every response on that route, while HTTP/3 put the
bytes on the wire, where a strict client dropped the connection and a lenient
one silently lost the field. RFC 9110 §5.5 calls CR, LF and NUL in a field
value invalid and dangerous, so `pingclair validate`, the Admin API, a reload
and a JSON document now refuse them in `header`, `request_header`,
`header_up` and `header_down` values, and refuse a `header` or
`request_header` name that is not a valid field name (#255).

📌 Upgrading: a configuration that loads today and carries such a value was
already broken on every transport; remove the stray bytes.

### 🚫 HTTP parser decisions follow Go

Invalid nonempty Host values receive 400 and close on HTTP/1; HTTP/2 fields
and HTTP/3 authority use the same character grammar. Empty HTTP/1 Host retains
its 400 response and reusable connection. HTTP/1 rejects leading blank lines,
unfolds continued headers in place, answers unsupported transfer codings with
501, and unsupported protocol versions with 505. Absolute-form requests route
by their URL authority after the original Host is validated.

📌 Upgrade note: use valid ASCII host authorities. A Host override no longer
changes the destination of an absolute-form URL. Open a fresh HTTP/1 connection
after a malformed nonempty Host, 501, or 505. CONNECT remains refused on all
transports because Pingclair does not implement generic tunnels; the former
default body ceiling has already been removed.

### 🚫 Malformed chunked bodies are client errors

Local body reads classify chunk-framing failures as downstream errors. The
error response advertises closure and the connection cannot be reused.

📌 Upgrade note: clients must fix the chunk size and CRLF framing, then open
a new connection. Pingclair reads local-handler bodies to enforce streaming
limits, so a framing failure is 400; Caddy may preserve a handler response
when its handler does not read that body.

### 🚫 Raw request targets reject whitespace

Request-line validation runs before Pingora can percent-escape illegal raw
bytes. Explicit percent-encoded targets retain their existing routing.

📌 Upgrade note: encode spaces as `%20` in client URLs. A raw space or control
byte in the request-target is refused and its HTTP/1 connection closes.

### 🚫 Short HTTP requests answer and close

Short requests are no longer held by h2c detection. A missing HTTP version
receives 400 and closes; HTTP/1.1 without Host now closes after its 400, too.
HTTP/1.0 without Host receives an HTTP/1.0 200 response and closes.

📌 Upgrade note: monitoring clients may omit Host only with HTTP/1.0. Send
a Host field with HTTP/1.1 and open a fresh connection after a rejection.

### 🔌 A specific address and a wildcard on one port share one listener

`http://127.0.0.1:8080` and `http://example.test:8080` in one configuration
used to become two sockets, `127.0.0.1:8080` and `[::]:8080`, each carrying
only its own site. Linux binds only one of the two, so which site answered on
`127.0.0.1:8080` depended on which socket the kernel took first; macOS kept
both, and each answered only for its own site (#246). Now a specific address
that shares its port with a wildcard is served through the wildcard socket at
startup and on every reload, for TCP and HTTP/3 alike, and sites are still told
apart by `Host`, as Caddy does. An IP-literal site that is alone on its port
still binds only its own address. Each fold is logged when the configuration
loads.

The same holds for `0.0.0.0:8080` beside `[::]:8080`, which Linux also refuses
to bind as two sockets: every address on a port that has `[::]` is served
through `[::]`. A port whose only wildcard is `0.0.0.0` carries that port's
IPv4 addresses and leaves IPv6 ones on their own sockets. A site addressed
`http://0.0.0.0:8080` is a catch-all, like `http://:8080`, instead of a site
for a `Host` named `0.0.0.0` that no client sends.

📦 **Upgrade:** Configurations need no change unless the port now carries
conflicting socket policy, which is refused at load: a site restricted by
`bind` (or `default_bind`, including `bind 0.0.0.0` beside a `[::]` site)
beside a wildcard site on the same port, a plaintext site beside a TLS site,
PROXY protocol on only one of them, or a `servers <address>` block for the
folded address. Bind every site on that port
to the same addresses, move one of them to another port, or address the
`servers` block to the wildcard. A literal site that shares a port with a
wildcard site is reachable on every interface by a client that sends its
`Host`; give it a port of its own if it must stay on loopback. Likewise a
`0.0.0.0` site that shares its port with a `[::]` site now answers over IPv6
too; give it a port of its own if it must stay IPv4-only.

### 📍 `bind` applies to every listener of a site

`bind` used to be read only for a site without an address of its own, so
`http://example.test:8080 { bind 127.0.0.1 }` listened on `[::]:8080`, every
interface, instead of the loopback address it named. `bind` now replaces the
host of every listener the site declares, at load time, for TCP, TLS and
HTTP/3 alike, and `adapt` shows the resulting addresses, as Caddy does. An
IPv6 bind host is bracketed (`bind ::1` listens on `[::1]:443`, where it used
to produce the unbindable `::1:443`).

📦 **Upgrade:** A site with both an explicit port and `bind` is no longer
reachable on other interfaces; that was the intent of writing `bind`. A
`servers <address>` block meant for such a site must name the bound address
(`servers 127.0.0.1:8080`), not the wildcard. A bound site beside a wildcard
site on the same port is refused, as it already was for a site without an
explicit port.

### 🔁 The automatic HTTPS redirect listens where its site does

The plaintext listener that automatic HTTPS adds for an HTTPS site, which
redirects to HTTPS and answers ACME HTTP-01, always listened on
`[::]:<http_port>`, so `example.com { bind 127.0.0.1 }` kept a redirect
listener on every interface. It now listens on the HTTP port of each host the
site listens on, as Caddy does. When another site already needs a wildcard on
the HTTP port, the redirect is served through that one socket, as before,
because Linux cannot bind both.

📦 **Upgrade:** Clients that reached a bound site's HTTP redirect through
another interface no longer can; that is what `bind` asked for. Nothing
changes for sites without `bind`.

### 🎧 `listen` keeps the address it names

The per-site `listen` directive kept only the port of its address, so
`listen 127.0.0.1:8080` listened on `[::]:8080`, every interface. It now reads
its argument the way nginx does: `listen 127.0.0.1:8080` and
`listen [::1]:8080` bind that address, `listen :8080`, `listen 8080` and
`listen *:8080` bind every interface, and an address with no port takes the
HTTP (or, with `https://`, the HTTPS) port. A site whose `listen` names an
address does not inherit `default_bind`.

📦 **Upgrade:** A `listen` that named a specific address now binds only that
address; write `listen :<port>` to keep listening everywhere. These are
refused at load, each with a message naming the fix: a hostname
(`listen example.com:80`, since `listen` binds and never resolves), an IPv6
address without brackets, a port that is not a number from 0 to 65535, and a
`listen` address that disagrees with the site's `bind`.

### 🚫 `bind` takes one address

`bind 127.0.0.1 ::1` and `default_bind 127.0.0.1 ::1` kept the first address
and dropped the rest without a word, so the site was missing from an
interface the operator listed. Caddy binds every listed address; this build
puts each listener on one interface, so a second address is now refused at
load instead of ignored.

📦 **Upgrade:** Keep one address, use `[::]` for every interface, or write one
site per interface.

### 🌐 `default_bind` applies to JSON configurations

`global.default_bind` was only honoured for a Pingclairfile: the compiler
copied it into each site, and a JSON configuration, whether loaded from a file
or posted to the Admin API, skipped that step, so its sites listened on every
interface. The global default now applies to JSON too, with the Pingclairfile
rule: a site gets it when it has no `bind` and every `listen` entry is a bare
port or `[::]`. A `listen` that names an address, `0.0.0.0` included, keeps
it. A JSON `default_bind` with more than one address is refused, as it already
was in a Pingclairfile. Pingclairfile configurations are unchanged.

📦 **Upgrade:** A JSON site that relied on `default_bind` now listens only on
that address, which is what the option says. To keep a JSON site on every
interface, give it `"bind": "[::]"` or a `listen` entry with an explicit
address.

### 🤐 FastCGI bodies honor HEAD and download pacing

H1/H2 FastCGI responses now use the local response-body policy, matching H3.
HEAD responses keep their metadata without sending content, and download rate
limits apply to streamed, buffered, intercepted-file, and replacement bodies.
The same path also enforces whole-request deadlines and response byte accounting.

📦 **Upgrade:** Configurations need no change. A configured
`download_bytes_per_sec` now slows FastCGI responses too; allow enough time in
client deadlines and whole-request timeouts for the configured download budget.

### 🧾 Oversized FastCGI parameters return 431

An encoded FastCGI name/value pair larger than 65,500 bytes now returns 431 on
H1, H2, and H3 before any PARAMS record is built or sent. Previously, a value
was shortened after its full length was encoded, leaving malformed records.
Valid pairs still span multiple records as complete pairs, compatible with
PHP-FPM's per-record decoder. The serializer keeps one bounded scratch record.

📦 **Upgrade:** Reduce large request headers or configured FastCGI environment
values so their encoded pair fits the record limit. A larger HTTP header limit
cannot increase the FastCGI pair limit.

### 🔪 FastCGI body failures abort the response

A FastCGI responder that disconnects or sends an invalid record after its headers
now closes the HTTP/1 connection or resets the HTTP/2 or HTTP/3 stream. Previously,
a partial body without `Content-Length` ended normally and looked complete.
Lengthless HTTP/1.1 bodies use chunked framing so a missing final chunk exposes
the failure. Buffered bytes from an incomplete response are discarded without
a clean end.

📦 **Upgrade:** Configurations need no change. Clients must treat an incomplete
response as failed rather than storing or displaying it as a complete document;
retry only requests that are safe to repeat.

### 🚫 A block directive takes `*`, a `/path` or `@name`

`handle`, `handle_path` and `route` take at most one matcher token before
their block, and that token is `*`, a path starting with `/`, or a named
matcher. Anything else used to be dropped without a word, so
`handle *.php { php_fastcgi … }` became a block with no matcher that answered
every request on the site, PHP or not. Such a configuration is now refused at
load with the token it did not understand, at site level and inside nested
blocks alike.

**Upgrade:** Name the matcher: `@php path *.php` and `handle @php { … }`.

### 🏷️ Admin config validators

`GET /config/...` returns a path-qualified Etag. Config writes with a stale
`If-Match` return 412 and leave the running document unchanged (#221).
`/load` and `/adapt` retain their existing behavior.

**Upgrade:** Refresh the config and its Etag after a 412; writes without
`If-Match` remain unconditional.

### ♻️ Admin reads during reload

Admin requests no longer receive 503 just because a reload is publishing
(#197). Access policy and the config document are published as one immutable
generation. Each request retains the generation that authorized it, and writes
still check its revision under the publisher's lock.

**Upgrade:** Polling scripts need no publication-delay retry. A write racing
another publication may still require reauthentication and retry after 409
(or a refreshed Etag after 412 for a conditional config write).

### 📊 Admin config reads and metric names follow Caddy

`GET /config/<missing path>` now returns `200` with JSON `null` and an Etag,
including missing object keys and array indices (#164). Conditional creation
can use that validator. Missing write paths still return errors; diagnostics
name the nearest parent and its keys or array length rather than the document's
root keys.

Standard metric families now use Caddy's series names. This mapping follows
Caddy from memory; its metrics source was not read. Values remain Pingclair's,
and existing labels and cardinality limits are unchanged.

| Previous name | New name |
| --- | --- |
| `pingclair_requests_total` | `caddy_http_requests_total` |
| `pingclair_request_duration_seconds` | `caddy_http_request_duration_seconds` |
| `pingclair_request_size_bytes` | `caddy_http_request_size_bytes` |
| `pingclair_response_size_bytes` | `caddy_http_response_size_bytes` |
| `pingclair_response_duration_seconds` | `caddy_http_response_duration_seconds` |
| `pingclair_request_errors_total` | `caddy_http_request_errors_total` |
| `pingclair_admin_http_requests_total` | `caddy_admin_http_requests_total` |
| `pingclair_reverse_proxy_upstreams_healthy` | `caddy_reverse_proxy_upstreams_healthy` |

Metrics without a definite Caddy equivalent retain their `pingclair_` names:
connections, overload, cache, access-log drops, upstream timing/errors/retries,
TLS and H3 counters, readiness, config version, queue occupancy, circuit state,
and process resources. No collectors are dropped or duplicated.

**Upgrade:** Scripts must check for `null` instead of relying on a 404 from a
missing config read. Replace the old metric names in dashboards, recording
rules, and alerts with the names above; histogram `_bucket`, `_sum`, and
`_count` series follow the renamed family. The old names are no longer exported.
The names do not imply that Pingclair exports Caddy's complete label schema.

### 📏 Equal-length route patterns keep file order

A route path with a `*` in the middle used to count as an exact path when two
routes of the same directive tied on length, so it jumped ahead (#230). With
`respond /abb* "first"` written before `respond /a*b "second"`, both patterns
match `/abb` and both are four characters once the trailing `*` is dropped,
yet `second` answered. Now `first` does: two different patterns of equal
length keep file order. "Exact before wildcard" applies only between twins,
patterns equal once the trailing `*` is dropped (`/foo` and `/foo*`), and the
twins sit together where the first of them was written. Site routes, `handle`
blocks and scoped middleware all sort this way.

**Upgrade:** Where two equal-length patterns overlap, write the one that
should answer first, or list them in a `route` block to fix the order
explicitly.

### 🧭 Route braces stay literal

🧭 Exact paths and wildcard prefixes escape braces before entering the radix
tree (#228). `/{id}` matches only that literal path, and a sibling `*.php`
route remains eligible for `/x.php`. Unmatched braces are accepted as literals;
an unexpected radix insertion failure rejects configuration instead of dropping
a route. Both HTTP transports use these candidate lists.

**Upgrade:** Replace accidental brace parameters with a `path_regexp` matcher
when captures are needed. Review fallbacks that relied on `/{id}` matching
arbitrary path segments.

### 🔄 Automatic HTTPS follows the configured listener policy

`auto_https disable_redirects` no longer binds an automatic plaintext listener.
A non-companion plaintext listener answers an unmatched Host with 200 and an
empty body. Automatic 308 redirects preserve the request Host's case and omit
both port 443 and the configured default `https_port`; a site on another HTTPS
port keeps that port in the URL, as in Caddy (#163).

**Upgrade:** Declare an HTTP site explicitly if plaintext service is needed
with `disable_redirects`. Use DNS and host matchers rather than treating an
empty 404 as a plaintext virtual-host health check. When forwarding external
port 443 to a custom internal port, set `https_port` to that internal port.

### 🌐 Scheme-only addresses use global ports

`http://example.test` and `https://example.test` now listen on `http_port`
and `https_port`, respectively, as in Caddy. Previously they always bound
80 and 443. Addresses that name a port keep that port (#220).

**Upgrade:** Remove workarounds that repeat global ports in site addresses,
or name an explicit port to keep a site on its previous listener.

### 🌐 Bracketed IPv6 site addresses name a site

`http://[::1]` and `https://[::1]` used to be split on the last colon, which
sits inside the brackets, so the address parsed to nothing: the block became
the unnamed catch-all for every `Host` on the port, had no listener of its own,
and `https://[::1]` lost TLS. They now name the host `[::1]` on the scheme's
global port, exactly as `http://127.0.0.1` does, and `https://[::1]` gets the
local certificate authority like any IP-literal site. A request for
`Host: [::1]:8080` now reaches a site named `[::1]`, with or without a port in
its address; before, no request could. A bracket that does not hold an IPv6
address, or is followed by anything but `:port` (`http://[::1]x`), is refused
when the configuration loads (#267).

📌 Upgrade note: a block written as `http://[::1]` answered every unmatched
`Host`; it now answers only `[::1]`. Add a catch-all site (`:80`, `http://`)
for traffic that relied on it. Caddy parses these addresses the same way
(from memory, caddyserver/caddy#80).
### 🗜️ Local header policy preserves encoding Vary

🧊 Static responses and generated upstream failures retain `Accept-Encoding`
after header policy. Upgrade: caches keep identity and compressed variants
separate even when a `header Vary` directive replaces or removes the field.

### 🗜️ H3 encoding removes obsolete integrity trailers

🧾 Re-encoded H3 responses drop identity digests from undeclared upstream
trailers while preserving other trailers. Upgrade: clients must validate a
digest for the encoded bytes, rather than relying on the upstream identity digest.

### 🗜️ Static encode matchers see response policy headers

🎯 Static encode matchers inspect policy-added, replaced and removed response
headers before selecting a body or evaluating conditional requests. Directory
listings use the same policy. Upgrade: review encode matchers that depended on
policy headers being invisible.

### 🏷️ Static gzip validators include quality

🏷️ Static gzip strong ETags include the configured quality, so different
encoded bytes no longer share a validator across reloads or replicas. Upgrade:
gzip caches revalidate once; identity validators remain stable.

### 🗜️ Proxy encoding respects request no-transform

🛡️ Both proxy transports honor `Cache-Control: no-transform` on the request,
including multiple field lines and case-insensitive directives. Upgrade: these
clients receive the upstream identity bytes even when they accept compression.

### 🚫 Encode off rejects blocks

🚫 Explicit `encode off` or `encode none` cannot carry a block that overrides
the disable. Upgrade: remove the block or explicitly enable its codings.

### 🗜️ Encode blocks take effect

🗜️ `encode { gzip [level]; zstd; minimum_length; match { … } }` now preserves
its settings instead of silently compiling every block as gzip. Unknown
sub-directives fail at load time. Upgrade: remove misspelled settings and review
response matchers and size floors that were previously ignored. Gzip levels are applied by both response paths.

### 🗜️ Static compression follows the coding list

🗜️ Static compression offers exactly the encode list in order. Upgrade: name each desired coding in encode; brotli remains available only as a precompressed sidecar (#216).

### 🗜️ Static responses always vary by encoding

🗜️ Static file responses always send Vary: Accept-Encoding, even without encode. Upgrade: expect shared caches to reserve an encoding-specific key before compressed variants appear (#219).

### 🗜️ Proxy encode responses always vary by encoding

🗜️ Proxied responses on encode sites send Vary: Accept-Encoding even when served as identity. Upgrade: allow caches to distinguish identity clients from clients that accept the configured codings (#226).

### 🏷️ Proxy compression weakens strong etags

🗜️ Re-encoding a proxied response turns its strong ETag into a weak validator. Upgrade: use weak ETags for cache revalidation; range resumption must use a validator for the actual encoded bytes (#227).

### 🗜️ Static and proxy compression share mime rules

🗜️ Static compression follows the same content-type allow-list as proxy compression. Upgrade: set gzip_types explicitly to enable additional MIME types; an explicit encode match block replaces the default matcher (#217).

### 🗜️ Compression uses the configured gzip level

🗜️ Both response paths apply encode gzip levels and use the Caddy default of 5. Upgrade: set gzip 1 inside encode for faster compression, or gzip 9 for a smaller body; zstd uses one shared native default of 3 (#223).

### 🗜️ Wildcard acceptance does not enable compression

🗜️ Accept-Encoding wildcard acceptance no longer enables an unnamed coding. Upgrade: send gzip or zstd explicitly; wildcard-only requests receive identity responses (#224).

### 🧰 Admin-only startup accepts its first HTTP generation

On Unix, an admin-only process can load its first plaintext HTTP listener set
through `/load` (#175). Every socket and route is prepared before publication;
a bind failure leaves the empty document intact and releases prepared sockets.
The listeners use Pingora's H1/H2 proxy, resource guards, and graceful shutdown
watch, and later route reloads publish through the existing transaction path.
Upgrade note: this bootstrap supports plaintext HTTP without PROXY protocol;
start with a file for TLS/H3, and restart for later listener topology changes.

### 🔐 Unnamed manual TLS fails closed

Common configuration validation rejects manual certificate pairs on unnamed,
empty-name, and `_` sites (#218). Startup and admin loads share this refusal;
validation no longer approves a certificate source the runtime would ignore.
Upgrade note: give the site a certificate hostname before configuring manual TLS.

### 🔁 Reload signals remain safe without a file

Empty and stdin startup install the same SIGHUP and SIGUSR1 handlers as file
startup (#175, #222). SIGHUP is ignored and SIGUSR1 leaves the active document
serving while reporting that no configuration file is available.
Upgrade note: reload these processes through the admin API instead of SIGUSR1.

### 🧰 Stdin takes precedence over filesystem entries

`run` and `validate` resolve `-c -` as stdin before inspecting the filesystem
(#222), with or without an explicit adapter.
Upgrade note: use `./-` when you mean a directory literally named `-`.

### 🧰 Run starts empty when no default configuration exists

With no path and neither `Pingclairfile` nor `Caddyfile` in the working directory,
`pingclair run` starts with no HTTP sites and the admin API at `127.0.0.1:2019`,
following Caddy (#175). `--resume` checks the autosave first, even without default
files. There is no file watcher or signal file reload for an empty configuration.
Explicit missing paths and absent `validate` input continue to fail.
Upgrade note: orchestration may start Pingclair before creating a plaintext HTTP
configuration and load it through the admin API on Unix; supply an explicit file
path if its absence should stop the process or if TLS/H3 is required.

### 🧰 Run and validate accept configuration flags

`run` and `validate` accept `--config` / `-c` alongside the positional path,
and `--adapter caddyfile|json` selects the file format explicitly (#222).
Watch and signal reloads preserve the selected adapter. Unknown adapter names
and simultaneous positional/flag paths are refused. Explicit adapters require
a single file; directory loading keeps its existing per-file format inference.
Upgrade note: existing positional commands still work; JSON uses Pingclair's
schema, and an explicit adapter overrides the filename extension.

### 🔐 Validate loads manual TLS material

`pingclair validate` reads, parses and matches manual certificates and private
keys through the same loader as startup, without starting listeners (#218).
Upgrade note: replace malformed PEM files or mismatched keys before validation.

### 🚨 `handle_errors` serves its own pages

`root * /srv/errors` inside a `handle_errors` block was refused at load as a
directive that "is not supported inside a route or handle block"; it is now
the error route's document root, as in Caddy (#209). A bare `file_server` in
an error route without one serves from the site's `root`. As upstream, the
`root` line may sit anywhere in the block, and a matcher-scoped
`root @name …` is refused there for the same reason it is at site level.

A `file_server` inside `handle_errors` now serves from that error route's
own configuration (#208). It used to be looked up in the slot of the route
that raised the error, so `rewrite * /{err.status_code}.html` followed by
`file_server` never rendered: HTTP/1.1 and HTTP/2 sent the bare error text,
and HTTP/3 answered `503 File Server Unavailable`. The page goes out with the
raised status, as Caddy's does, and is read as a plain `GET`: the failed
request's `Range` and validators belong to the resource that failed, so they
can no longer turn an error into a `206` or a `304`.

Errors the server produces itself now reach `handle_errors` too, on every
protocol, as they do in Caddy: a `reverse_proxy` that cannot reach its
upstream (`502`, `503`, `504`), a request body over its `request_body`
limit (`413`, whether its length was declared or it streamed past the limit),
a body that stops arriving (`408`), and, on HTTP/3, a missing file (`404`,
which HTTP/1.1 and HTTP/2 already routed). They used to answer with the
built-in text or the site's `error_page` whatever the error routes said. A
site with no error route for the status answers exactly as before, and an
error route that fails itself is answered directly rather than routed again.

**Upgrade:** Nothing to change for a configuration that already worked. One
whose error route ends in `file_server` now answers with the page it names
instead of the error text, with the error's status rather than `200`. A
catch-all `handle_errors { … }` now also answers gateway and body-size
errors; give it status codes (`handle_errors 404 { … }`) to keep it to the
ones it was written for. Its gateway answers carry no `Proxy-Status`, which
the built-in gateway error still does.

### 🚫 Non-goals for 0.2.0

What this release deliberately does not do, so the rest can converge:

- A layer-4 TCP proxy or TLS ClientHello routing (#183).
- Per-listener `servers <address> { … }` options beyond
  `metrics` (#47); an addressed block that sets anything else is refused.
- Caddy's native JSON config as an input format (#138); the
  Caddyfile is the compatibility surface.
- Conditional response header groups, `header { match { … } }`
  (#41).
- OpenMetrics exposition (#45).
- Plugins; `pingclair-plugin` stays an unwired skeleton, and a
  plugin handler is refused.

### 🔁 `reload` has no gap; `restart` has a brief one

`systemctl reload pingclair` (`SIGUSR1`) is the zero-downtime way to apply a
configuration. `systemctl restart pingclair` is not, and cannot be: the old
process stops accepting the moment it receives SIGTERM, lets running
requests finish for at most `grace_period`, and exits, and systemd starts
the new process only after that. New TCP connections are refused in
between. Measured on Linux with release builds under load, that gap was 40
to 210 ms when only short requests were running, and as long as the longest
running request when one was — which is how a production-like soak with
`grace_period 20s` and open event streams saw about 390 refused connections
over 20 seconds. An HTTP/3 client that connects during the gap is not
refused: its handshake goes unanswered, its retransmissions reach the new
process, and it is served once the gap ends, unless the gap outlasts its
handshake timeout (ten seconds for curl). The installed unit adds nothing to
the gap: it has no `ExecStop=` (the repository lint now refuses one) and
keeps systemd's own stop timeout as a backstop.

🔐 Ownership of the running configuration moves with the first change made
through the Admin API: `/load` and the traversal writes claim it inside the
publication lock, and a `SIGUSR1` that arrives afterwards is refused instead
of letting the file on disk overwrite an API key rotation that just
succeeded. Send further changes through the Admin API, or restart the process
to hand ownership back to the file.

📌 Upgrading: apply configuration changes with `reload`, and keep
`grace_period` short where restarts must be brief. (#210)

### 🔻 Passive health counts failures after the connection

A backend that accepted the connection and then failed mid-response — a
truncated body, a reset before the response ended, a malformed response —
kept receiving traffic forever, because only connect failures fed the
passive health mark. Response-phase failures now count the same way, and
Caddy's `max_fails` and `fail_duration` are honoured instead of refused
(`fail_duration 0` keeps Caddy's "do not remember failures"). The default is
one failure and a ten-second window, the rule a refused connection already
followed (#262).

### 🔌 An HTTP/3 request cut by a stop ends at `grace_period`, not at an idle timeout

When `grace_period` ran out with an HTTP/3 request still running — a
server-sent-events stream, a long download — the process exited without
telling the client. A TCP client hears the kernel close its socket at exit;
a QUIC connection exists only in the server's memory, so the client heard
nothing and kept waiting until its own idle timeout gave up, about seventy
seconds in a production-like restart. The same could happen to a connection
whose last request had just finished, if the process exited before that
connection's close left it. Now every HTTP/3 connection still open when the
drain ends is closed with `H3_NO_ERROR` (after the `GOAWAY` it already
received), and the process exits only once those closes have been sent, or
after at most half a second more. A request cut this way ends without its
final bytes, so the client can tell it was incomplete.

The drain also waits for a response that had finished just before the stop
but was not yet acknowledged. Such a response used to stop counting the
moment its last byte was handed to the QUIC stack, so a stop that began
while it was still in flight saw nothing running and ended at once, losing
any packet of it that had to be sent again.

📌 Upgrading: nothing to change. (#211)

### 🙈 The admin API's configuration reads mask secrets

**Breaking for scripts that export `/config` and load it back.** `GET
/config`, `GET /config/<path>` and `GET /id/<name>` used to return the admin
`api_key` and every DNS provider argument (a Cloudflare token, for instance)
in plain text, so anything allowed to read the configuration also received
the key that guards the API. Those reads now show `[redacted]` in their
place. The same goes for credentials written as ordinary values: a header
named `Authorization`, `Proxy-Authorization`, `Cookie` or `Set-Cookie`, or
one whose name contains `api-key`, `token`, `secret` or `password` (in
`header_up`, `header`, `health_headers` and the like), a FastCGI `env`
entry named that way, and a basic-auth hash. The stored configuration is
unchanged, and traversal writes
(`POST`/`PUT`/`PATCH`/`DELETE /config/<path>`) still edit the real values.

A document that carries `[redacted]` as a secret is refused by `/load` and
`POST /config`, because loading it would make that well-known string the
admin key. Caddy returns its configuration unmasked; this follows the
project rule that admin dumps never carry secrets.

📌 Upgrading: edit in place with a traversal write (`PATCH /config/...`), or
restore the real secrets in an exported document before posting it to
`/load`.

### ☁️ `CF-Connecting-IP` counts only when `client_ip_headers` lists it

**Breaking for deployments behind Cloudflare that relied on the header.**
Behind `trusted_proxies`, `CF-Connecting-IP` used to name the client ahead of
every other header. But a trusted peer is not necessarily Cloudflare: an
ingress or load balancer that passes client headers through untouched let
any client choose its own `{client_ip}`, and with it what `client_ip`
matchers, rate limits and access logs believed. The header now counts only
when it is listed.

Caddy's `client_ip_headers` server option is implemented to list it, in the
global `servers` block or an addressed `servers <address>` block for one
listener. Listed headers are the only sources, consulted in order; the
first that names a client decides. When the list leaves out
`X-Forwarded-For`, an incoming `X-Forwarded-For` is not passed upstream
either: the chain the origin receives starts from the client the listed
headers named. Without the option, the client comes from
`X-Forwarded-For` and `Forwarded`, with `X-Real-IP` when neither was sent, as
before. Caddy's default is `X-Forwarded-For` alone.

📌 Upgrading: a site behind Cloudflare writes

```caddyfile
{
    servers {
        trusted_proxies static 173.245.48.0/20
        client_ip_headers CF-Connecting-IP
    }
}
```

with Cloudflare's published ranges (or the tunnel's address) as the trusted
proxies.

### 📊 Metrics are collected only when `metrics` is set

**Breaking for anyone scraping `/metrics` without asking for it.** A
configuration that never says `metrics` now collects nothing, as in Caddy.
Until now collection was on by default and the DSL had no way to switch it
off, so every Pingclairfile-configured server paid for metrics it had not
asked for, and the benchmark shape (metrics off) could not be written down.
The global `metrics` option, or `servers { metrics }`, turns it on; in a JSON
config `"metrics": true` does, and a JSON document without the field now
means off, the same as a Pingclairfile that is silent.

When it is off, request paths skip metric work entirely, and both the admin
API's `/metrics` and a site's `metrics` handler answer `200` with an empty
body. A reload that adds or removes `metrics` now takes effect without a
restart; before, only the configuration the process started with counted.

📌 Upgrading: add `metrics` to the global options block to keep collecting:

```caddyfile
{
    metrics
}
```

(#32)

### 🚫 `{remote_ip}` is refused; write `{remote_host}` or `{client_ip}`

**Breaking for any configuration that writes `{remote_ip}`.** Caddy has no
such placeholder; it was this project's own, and it meant the verified client
while the `remote_ip` matcher means the connection's peer. The same word
naming two different addresses made `header_up X-Real-IP {remote_ip}`
impossible to read correctly. A Pingclairfile or JSON config that uses it
anywhere now fails to load, and the error names where it appeared.

📌 Upgrading: write `{client_ip}` for the client after `trusted_proxies`
(what `{remote_ip}` meant), or `{remote_host}` for the connection's peer.
(#200)

### 🔌 `{remote_host}` is the connection's peer, `{client_ip}` the client

**Breaking for `{remote_host}` behind `trusted_proxies`.** The placeholders
now split the same way the matchers did in #191, as in Caddy.
`{remote_host}` and `{http.request.remote.host}` are the connection's own
peer, whatever any header says; behind a trusted load balancer that is the
balancer. `{client_ip}` and `{http.request.client_ip}` are the client after
`trusted_proxies` is applied. Until now `{remote_host}` printed the forwarded
client, so a log line or `header_up X-Real-IP {remote_host}` behind a
balancer could never name the balancer.

`{remote_port}` / `{http.request.remote.port}` and `{remote}` /
`{http.request.remote}` (`host:port`) are new and also describe the peer.
They used to render empty, on HTTP/3 as well as HTTP/1.1–2. A file or
`vars` matcher reads `{remote_host}` and `{client_ip}` the same way. FastCGI
`REMOTE_ADDR` was already the peer and stays so.

📌 Upgrading: a site without `trusted_proxies` sees no change, because there
the two addresses are the same. A site with `trusted_proxies` that relied on
`{remote_host}` meaning the client — `header_up X-Real-IP {remote_host}`,
a log field, a `respond` body — must write `{client_ip}` instead. (#194)

### ♻️ A reload no longer refuses requests

A reload (`SIGUSR1`, `pingclair reload`, or the Admin API) used to answer
every request that arrived while it was publishing with
`503 Configuration Reload In Progress` and close the connection, and to
refuse new TLS and HTTP/3 handshakes in the same window. On a busy server
that was a burst of failures per reload: with 64 sites, a debug build held
the window for 6 to 13 ms, and a test sending traffic through eight reloads
saw 353 of 2,150 requests fail. Each listener's routes and client-certificate
policy are now published together as one snapshot, so a request sees either
the old configuration or the new one and is always served. The slow part of
a reload, compiling every site, now runs before anything is swapped.

📌 Upgrading: nothing to change. On a listener with `client_auth`, a reload
still asks connections admitted under the previous policy to reconnect, as
before. The Admin API also keeps serving through publication; see
[Admin reads during reload](#️-admin-reads-during-reload).

### 🏷️ A build of `main` says it is a dev build

`main` now carries version `0.0.0`, and a release is a single commit off
`main` that sets the real number. A binary built from `main` therefore
reports `v0.0.0-dev+<commit>` from `pingclair version`, `build-info` and
`list-modules --versions`, and `pingclair 0.0.0-dev+<commit>` from
`--version`, or plain `v0.0.0-dev` when it was built
without a git checkout, such as from a source tarball or in the Docker
image's build context. A release binary reports exactly its version, as
before.

📌 Upgrading: nothing changes for anyone installing a release. A script that
parsed the version of a source build to decide what it is must now expect
`0.0.0-dev`. Previews for the next minor are published as prereleases named
`X.Y.Z-alpha.N`; only a stable `X.Y.Z` becomes the "Latest" GitHub release
or the image's `:latest` tag, which an rc used to move as well. The channels
and the procedure for cutting a release are in `CONTRIBUTING.md` under
"Releasing".

### 🧭 `servers <address> { … }` optioned the listener it names

An addressed `servers` block used to lose its address: the children were lifted
to the global level, so `servers :8443 { listener_wrappers { proxy_protocol } }`
demanded the PROXY header on **every** listener — and a port whose clients do not
send it rejects every connection, so a working site would stop answering. Two
addressed blocks that disagreed silently resolved to whichever came second. The
block was then refused outright, which at least said so.

It now works, and the address selects one listener: `listener_wrappers`,
`protocols` and `trusted_proxies` apply to the address the block names, and to
nothing else. `trusted_proxies` is the sharpest example — believing a forwarded
client address is a decision about who sits in front of *that* socket, and two
deployments behind different load balancers is the case the address exists to
separate. 📌 Upstream's behaviour was measured rather than assumed: a
`client_ip` matcher answers differently on the two listeners, and the same four
requests appear in `compat-audit/verify/impl-gaps-ab/runtime/47/`.

🚫 Two shapes are refused rather than guessed at. An address that names no
listener of this configuration — Caddy ignores it silently, so the block would
option nothing and say nothing — and any option that is process-wide by nature
(`admin`, `email`, `pki`), which has no meaning for one socket and would have to
widen to all of them to apply at all.

### 🪵 An unnamed global `log { … }` block configures the process log

The block — Caddy's spelling for the process-wide default logger — used to
compile into a field nothing read: no file appeared, no line was logged, and
`validate` exited 0. It was then refused by name, which at least said so. It now
works, and points this server's own records where the operator asked: `output
file <path>` (created if missing, mode 0600, no colour escapes), `output stdout`,
`output stderr`, `format json|text`, and `level`.

The setting is applied when the configuration is read and again on every reload,
so a reload can move the log to a file and a later one can move it back —
Caddy re-provisions its loggers for the same reason. One startup line names the
destination, as Caddy's own "redirected default logger" does. `RUST_LOG` still
outranks a configured `level`.

📌 Two things deliberately do not move with it. The `🚀 Pingclair running...`
banner stays on stdout, because supervisors — including this repository's own
integration harness — read it there to know the process came up. And stdout
keeps its colour escapes: a file sink turns them off, a terminal is where the
rest lands.

🧹 Three fields that no code ever read are gone from `LoggingConfig` — `level`,
`format` and `file`. A JSON document carrying them was silently ignored before
and is silently ignored now, which is the defect rather than the fix; the
unnamed global `log` block is the spelling that does something.

### 🧭 `header { match { … } }` gates a response header block

A `header` block that wrote `match { … }` was refused by name, so a block meant
to apply to some responses and not others did not load at all. It now works:
the matcher is judged against the finished response — the only moment its
status and headers exist — and the block's operations, including `-Server` and
`-Via`, apply only when it matches. On both HTTP/1.1–2 and HTTP/3.

The gate covers the **whole** block wherever the `match` line was written in
it, and a gated block's operations land after the block's unconditional ones.
Both are upstream's behaviour, measured rather than assumed: Caddy keeps the
matcher and the operations as two fields of one handler and defers a gated
block's work to the moment the response header is written. Two gated blocks
that write the same field therefore resolve the way they do there — the one
written first wins — and `match` accepts what upstream accepts and nothing
else: `status` (bare codes and the `2xx` class shorthand) and `header`.

🚫 `handle_response { header { match { … } } }` stays refused, now by a message
that names it. Caddy judges that gate against the response the subroute itself
produces, which this build does not compose at that point; dropping the gate
instead would accept a configuration that reads as conditional and is not.

### 📥 All four `request_body` options are implemented

`request_body` accepted only `max_size`; `read_timeout`, `write_timeout` and
`set` were refused by name, so a configuration using them did not load at all.
All three now work, on both HTTP/1.1–2 and HTTP/3.

`read_timeout` and `write_timeout` bound reading the body and writing the
response for that route. A stalled upload is answered with `408` once the
deadline passes instead of holding the connection open. `set "<body>"` replaces
the request body: placeholders in the value are expanded for the request, and
the `Content-Length` sent upstream is the replacement's. The client's own bytes
are discarded as they arrive rather than read into memory, so replacing a 20 MB
upload costs the replacement's length in upstream body and no buffer. (#38)

Two consequences worth knowing. A response to a body read or write deadline is
now `408` rather than `500` — a client that stopped sending is the client's
fault, and HTTP/3 already said so, so the two transports disagreed. And an
empty `request_body { }` block, or `set ""`, now loads as a handler that does
nothing, which is what Caddy adapts them to.

### 🔌 `remote_ip` matches the connection's peer, `client_ip` the client

**Breaking for `remote_ip` behind `trusted_proxies`.** The two matchers now
read different addresses, as in Caddy. `client_ip` matches the client after
`trusted_proxies` is applied: the forwarded address when the connection comes
from a trusted proxy. `remote_ip` matches the connection's own peer, whatever
any header says; behind a trusted load balancer that is the balancer. Until
now both matched the forwarded client.

📌 Upgrading: a site without `trusted_proxies` sees no change, because there
the two addresses are the same. A site with `trusted_proxies` that used
`remote_ip` to match clients (for example to block a range) must now write
`client_ip`, or the rule will compare the balancer's address instead. In a
JSON config the `remote_ip` matcher key changes meaning the same way, and the
new `client_ip` key holds the old one; a PROXY-protocol listener's declared
source counts as the peer. Both HTTP/1.1–2 and HTTP/3 behave alike. (#191)

### 🌐 IP matcher ranges are parsed once, and a malformed one is refused

`remote_ip` and `client_ip` ranges are now parsed when the configuration
loads rather than on every request. A range that does not parse, such as
`10.0.0.0/33`, now stops the configuration with an error naming it — from a
Pingclairfile, a JSON config, or an Admin API reload alike. It used to load
and then match nothing, so a block list with a typo let the address through.
Matching an address against a four-range guard went from about 106 ns to
about 23 ns in the router microbenchmark. (#192)

### 🧩 Nested sibling handles are mutually exclusive

Nested sibling `handle` and `handle_path` blocks now run only the first
matching block, even when that block writes no response. This applies inside
`handle`, `route`, `handle_path`, and `handle_errors`. Directive sorting and
explicit `route` order are preserved. (#43)

**Upgrade note:** If a matched nested handle only sets headers or rewrites the
request, later sibling handles no longer provide a fallback response. Put the
response inside the selected block or after the sibling group.

### 🧮 Static-file cache budgets are shared across routes

All `file_server` instances now share process-wide limits of 64 MiB for
compressed bodies, 16 MiB for raw bodies, and 4,096 metadata entries, including
during reload. Adding routes no longer multiplies these budgets. Cache admission
uses atomic accounting without adding request-path locks; a route serves misses
uncached when other routes occupy the budget. File eligibility and HTTP behavior
are unchanged. These fixed limits are not a total process-memory ceiling. (#33)

### 🔤 Every route path ignores letter case

**Breaking.** An exact or prefix route path now matches without regard to
ASCII letter case, as Caddy's `path` matcher does: `respond /Health "ok"`
answers `/health` and `/HEALTH`, and `/Admin/*` answers `/admin/users`.
Until now those two shapes compared case exactly, while a wildcard pattern
such as `*.php` already ignored it (#193), so two patterns in one
Pingclairfile disagreed about what `/Admin` meant. Route paths are
lowercased once when the configuration loads; a request path is only
folded when it has a capital letter, on the stack, so an all-lowercase
request pays for one scan and nothing more. Letters outside ASCII still
compare exactly.

**Upgrading:** a mixed-case request can now reach a route it used to miss.
A site that relied on case to send `/Admin` and `/admin` to different
routes, or to keep `/Private/*` from answering `/private/x`, needs a
case-sensitive `path_regexp` matcher instead. (#198)

### 🪚 A strip ignores letter case like the route that chose it

**Breaking.** `handle_path`, `uri strip_prefix` and `uri strip_suffix` now
compare without regard to ASCII letter case, as Caddy's path trim does.
Once route paths ignored case (#198), `handle_path /API/*` was chosen for
`/api/users` but still compared the prefix byte for byte, so it forwarded
`/api/users` untouched instead of `/users`; the same happened on HTTP/3.
The comparison borrows the path and folds nothing, so it costs no copy.
Letters outside ASCII still compare exactly.

**Upgrading:** a strip whose spelling differs in case from the request now
removes the prefix or suffix. A configuration that relied on case to keep a
prefix in place needs a case-sensitive `path_regexp` and `rewrite` instead.
(#214)

### 🏠 Every address of a site has a certificate

A site written with two addresses, such as
`*.example.com, example.com { … }`, now has a certificate for both. The
certificate sources read only the site's first address: `tls internal`
issued no leaf for the second, a `tls <cert> <key>` pair was filed under the
first name only, and the HTTP/3 certificate table was seeded from the first
name alone. With public certificates the second name still worked over
HTTP/1.1 and HTTP/2, which obtain a certificate during the handshake, but its
HTTP/3 handshake was refused; with internal or manual certificates it failed
on every protocol. Each source now covers every address, as Caddy manages one
certificate per hostname.

**Upgrading:** `tls internal` issues one more leaf for each extra address,
and the second address of a site now presents the site's manual certificate
instead of failing the handshake; make sure that certificate names it.
(#202)

### ⌛ `lb_try_duration` limits retrying, not the response

`lb_try_duration` now means what it means in Caddy: how long after the
request arrived the proxy may still *start* another attempt at a backend.
It used to be applied as a deadline on the attempt itself, so an event
stream was cut once the duration passed, and an origin that answered after
it got a 504 even though its answer had arrived. On HTTP/3 the origin's
complete response was replaced by that 504. A running attempt is now
bounded by the `transport http` timeouts (`dial_timeout`,
`response_header_timeout`, `read_timeout`, `write_timeout`) and the site's
request deadline, on every protocol.

**Upgrading:** a route that relied on `lb_try_duration` to cap how long a
slow backend may take must set `transport http { response_header_timeout … }`
or `read_timeout` for that. Long streams behind a route with
`lb_try_duration` now run to completion. (#206)

### 🔁 A keepalive reuse miss is not an error

Under ordinary concurrent load the process log carried a steady trickle of
`ERROR failed to acquire reusable stream`, with no failed request behind any
of them. The record comes from Pingora's upstream connection pool: now and
then it takes an idle connection back while the task watching that
connection has not quite released it, so it drops the connection and dials a
new one. The request is unaffected; the cost is one extra connect. As in
nginx, which logs an unusable cached keepalive connection at `debug`, the
record is now emitted at `DEBUG`, with its `log.target`, `log.file` and
`log.line` fields unchanged. Every other record Pingora logs keeps its level.

**Upgrading:** set `log { level DEBUG }` to see these records again; an
alert keyed on the message at `ERROR` no longer fires. (#212)

### 🧩 A `*` anywhere in a route's path matches

A path matcher with a `*` that is not its last character never matched
before: `@a path /a/*x` let `/a/bx` fall through to whatever came next, and
`@php path *.php` matched nothing. Such patterns now match the way Caddy's
`path` matcher reads them:

- one leading `*` is a suffix at any depth (`*.php` matches `/x/y/index.php`);
- two, one at each end, is a substring (`*/admin/*`);
- any other placement is a glob in which each `*` stays inside one path
  segment: `/a/*x` matches `/a/bx` but not `/a/b/cx`, and `/files/*/raw/*`
  matches `/files/7/raw/readme` but not `/files/7/8/raw/readme`.

Such a pattern ignores letter case, as Caddy's matcher does. These routes take their
place in directive order like any other, so a longer pattern of the same
directive still goes first. Unlike Caddy, `?`, `[…]` and `\` in a path
pattern are literal characters, not wildcards.

The same rules apply to a `path` matcher that does not pick a route — one
gating a directive inside a `handle` or `route` block, or under `not`.
There a `*` in the middle used to cross `/`, so `path /accounts/*/info`
also matched `/accounts/42/7/info`; now it does not.

**Upgrading:** a site that listed such a pattern had it silently match
nothing; it now answers the requests it names. Check that those routes
should. A nested `path` matcher that relied on a middle `*` spanning
several segments needs one `*` per segment, or a `path_regexp`. (#193)

### 🧭 Directive order, not the most specific path, decides which route answers

**Breaking.** A site's routes are now tried as one list, ordered the way
Caddy orders them, and the first route that matches answers. Until now the
most specific path won wherever it was written. So this site answers
`hello` for `/assets/a.txt`, where it used to serve the file:

```caddyfile
example.com {
    root * /srv
    file_server /assets/*
    respond "hello" 200
}
```

`respond` ranks ahead of `file_server` in the directive order, and ahead
of `reverse_proxy` and `php_fastcgi`; `redir`, `handle` and `route` rank
ahead of `respond`. Between routes of the same directive, the one whose
single path is longer once a trailing `*` is removed goes first (`/foobar*`
before `/foo`), then exact before wildcard (`/foo` before `/foo*`), then
file order. A matcher with several paths, or none, goes after every
single-path sibling. `handle` blocks sort their contents by the same rule.

Three entries rank as something other than their own name: a matched
middleware directive (`header @api …`) ranks where the site's answering
directive does, since that is what answers for it; `php_fastcgi` ranks as
itself, after `respond`; and `templates` beside `file_server` ranks as
`file_server`. Two different paths of equal length keep file order, where
Caddy sorts them alphabetically. Only a `*` that is not at the end lets two
such paths match one request: with `@a path /a/*x` and `@b path /*/bx`,
`/a/bx` is answered by whichever is written first here, and by `/*/bx`
in Caddy.

**Upgrading:** a configuration where a narrower directive sits below a
broader one of an earlier rank now answers differently. To keep the old
answer, give the narrower route an earlier rank — wrap both in `handle`
blocks, which are exclusive and put the one with a path first, or move a
directive with the `order` global option (`order file_server first`) —
or list them in a `route` block, which keeps written order. (#18)

### 📁 A globbed `try_files` candidate sees every file in the directory

A `file` matcher or `try_files` candidate containing a glob could not
match a filename that is not valid UTF-8 — legal on Linux, and served
by `file_server` without complaint. The glob library skipped such
names, and the matches it did return were then converted to text
lossily. Candidates are now expanded by walking the directory and
matching names as bytes, with the same `*`, `?`, `[...]` and `**`
syntax. `{http.matchers.file.relative}` spells a globbed match in
percent-escapes, so a name with a space is no longer pasted raw into
the rewritten request line, and metacharacters in the configured
`root` are no longer expanded as part of the pattern. (#12)

### 🔤 `try_files {path}` reaches a filename that is not valid UTF-8

`file_server` already served `/na%EFve.txt` from a file whose name holds
the Latin-1 byte `0xEF`, but the `file` matcher in front of it — and so
`try_files` — gave up on any escape that decoded to such bytes, and the
request fell through to the next candidate. The matcher now resolves
candidates to filesystem paths with the same helper `templates` and
FastCGI use, so all of them agree on which file a request names. (#12)

### 🐘 FastCGI names a non-UTF-8 script by its real bytes

`SCRIPT_FILENAME`, `PATH_TRANSLATED` and `DOCUMENT_ROOT` were converted
to text lossily before they reached the responder, so a request for
`/na%EFve.php` told PHP-FPM to run `na\u{FFFD}ve.php`, a file that does
not exist. The CGI environment now carries these values as the bytes
on disk. (#12)

### 🧱 Body buffering reaches the FastCGI transport

`request_buffers` and `response_buffers` were accepted on a `fastcgi`
transport (and so inside `php_fastcgi`) and then ignored, with a startup
warning saying so: FastCGI writes and reads its own records and never
passed through the code that buffers HTTP bodies. Both now apply there
too, over HTTP/1.1, HTTP/2 and HTTP/3, with the same 8 MiB ceiling past
which the rest streams, so a slow client or reader no longer holds a
php-fpm worker for its whole transfer. The startup warning is gone. (#16)

### 🔌 `CONNECT` gets the same 405 on every protocol

This server is a reverse proxy and opens no tunnels, but each transport
refused `CONNECT` differently. HTTP/1.1 and HTTP/2 answered a bare `405`
from inside Pingora, naming no allowed methods and leaving no access-log
line. HTTP/3 reset a well-formed `CONNECT` as malformed, and answered
`501` only to a nonstandard one carrying `:scheme` and `:path`. Every
protocol now answers `405` with `Allow` (RFC 9110 §9.3.6), logs it, and
closes an HTTP/1.1 connection afterwards so tunnel bytes the client sent
early are never read as a request. On HTTP/3 the nonstandard shape is now
the malformed one (RFC 9114 §4.4). (#86)

### 🏷️ A gateway error this proxy wrote says so with `Proxy-Status`

A 502 or 504 that Pingclair generated because it could not get an answer
from a backend looked exactly like one the backend sent itself. Those
responses now carry an RFC 9209 `Proxy-Status` field, such as
`Proxy-Status: pingclair; error=connection_refused`, on HTTP/1.1, HTTP/2
and HTTP/3. The member name is the fixed token `pingclair`, and only the
error type is included: no backend address and no OS error text, because
those would describe internal topology to any client. Responses forwarded
from a backend, including its own 502s, are unchanged, and so are local
responses that involve no backend, such as `respond` or a rate-limit 429.
While a failed backend sits out its cooldown, the 502s answered without
dialling it carry `error=destination_unavailable` on every protocol; only
the first 502 used to carry the field (#203).

### 🚫 An addressed `servers` block may only carry the options a listener has

`servers :80 { … }` names one listener, but its options were applied to
every listener, so two addressed blocks that disagreed (`protocols h1` on
one, `protocols h1 h2` on the other) resolved silently to the second one
everywhere. An addressed block that sets an option this build cannot scope to
one listener is refused, naming the option and the address. The options that
*can* be scoped — `listener_wrappers`, `protocols`, `trusted_proxies` — now
reach the listener the block names, which is what the section above this one
describes; `metrics` stays accepted because it is app-wide wherever it is
written.

### 🛡️ A malformed `blocked_ips` entry is refused

An entry in the global `blocked_ips` list that is neither an address nor a
CIDR used to pass `pingclair validate` and the Admin `/load` endpoint, and
the listener then dropped it with a warning, so the address it was meant to
block got through. It is now refused by the shared validation step, naming
the entry, wherever a configuration comes in. A configuration that loaded
before with such an entry no longer does.

### 🏷️ A handshake for a name this server does not serve says so

A TLS client asking for a hostname no site configures used to be refused
with an alert about something else: `internal_error` over TCP, and
`handshake_failure` (QUIC error `0x128`) over HTTP/3. Both now end with
`unrecognized_name` (`0x170` on QUIC), as RFC 9846 §6.2 asks, so the
client's error names the wrong hostname instead of suggesting a broken
server. A client that sends no name at all, on a listener without
`default_sni`, now gets `missing_extension` (§9.2) on both. A `default_sni` whose own certificate is
missing ends with `internal_error`, because that one is the
configuration's fault. Which handshakes succeed is unchanged. A served
name is now also acknowledged with an empty `server_name` extension in the
server's reply, as RFC 6066 §3 asks.

### 🧾 An oversized header section gets a named 431 on HTTP/2 and HTTP/3

`max_header_bytes` was handed to the protocol libraries as their own
header-list limit, so they refused an oversized request before the site's
check ran: HTTP/2 answered with an empty 431, and HTTP/3 closed the whole
connection with `H3_EXCESSIVE_LOAD`, failing every other request sharing
it. Both libraries now get a looser but still bounded limit (twice
`max_header_bytes`, plus 32 bytes for each field the site allows), so the
site's own check decides: the one request gets a 431, naming the field when
a single field is at fault, and the rest of the connection carries on. A
section beyond the looser limit is still refused by the library as before.

### ⚠️ Startup warns when keepalive pools can outgrow the descriptor limit

Every idle upstream connection kept for reuse holds a file descriptor, and
there is one keepalive pool per TCP listener, sized at
`upstream_keepalive_pool_size` times the worker threads, plus one per HTTP/3
port. On a 4-core box, `:80` + `:443` + HTTP/3 may keep 4,608 idle upstream
connections, past the 1,024 descriptors a container usually starts with.
Startup now adds these up, with the listening sockets, and logs a warning
with the numbers as structured fields when the total exceeds the soft
`RLIMIT_NOFILE`. It does not refuse to start. The pools are still sized per
listener; sharing one budget across them is still open.

### 🔧 A taken admin port stops startup instead of being logged

The admin API bound its address in its own thread after startup had
succeeded. If another process held the port, the only sign was a line on
stdout, and the server ran on without `/load`, `/config`, or `/metrics`. The
admin listener is now bound during startup, next to the data-plane
listeners, and a failed bind stops the process with
`failed to bind admin API on ADDR`. `admin off` still binds nothing.
**Upgrading:** a deployment that was silently running without its admin API
now refuses to start; free the port, move the admin address, or turn the
admin API off.

### 🚫 A site with `http3 off` is no longer advertised over HTTP/3

`tls { http3 off }` made the QUIC handshake for that site fail on purpose,
but the `Alt-Svc: h3=…` header was chosen once per listener, so the site's
HTTP/1.1 and HTTP/2 responses still invited clients to HTTP/3. A client that
believed it retried the doomed handshake on every new connection for the
advertised 24 hours. The header is now withheld from responses for an
opted-out name, matched by the same rule (exact name or `*.` wildcard, any
letter case, trailing dot ignored) that refuses its handshake; other sites on
the same port keep it. (#104)

### 🔐 `Strict-Transport-Security` follows the connection, not the `tls` block

The header tells a browser to use HTTPS only, and RFC 6797 forbids it on a
plaintext response. Pingclair decided by asking whether the site had a `tls`
policy, so a site with both an `http://` and an `https://` address sent it
on its plaintext answers, and a `tls internal` site never got the built-in
JSON `security.hsts` value even over TLS. The header is now stripped from
every plaintext H1/H2 response, whether the built-in policy, an operator's
`header Strict-Transport-Security …` or the upstream set it, and added on
every encrypted one (HTTP/3 always counts as encrypted). In a Pingclairfile,
`header Strict-Transport-Security "max-age=…"` is the way to turn HSTS on;
when a response already carries the header, the built-in value no longer
replaces it. The built-in value is now spelled `max-age=N; includeSubDomains`
without the trailing `;`.
**Upgrading:** behind a load balancer that terminates TLS and forwards
plaintext, the header now appears only when that balancer is listed in
`trusted_proxies` and sends `X-Forwarded-Proto: https`.

### 🧹 A trailing comma in a forwarding header no longer hides the client

Behind a trusted proxy, `X-Forwarded-For: 203.0.113.7,` — a trailing comma,
the usual leftover of merging two lists — made the whole header unreadable,
and the next line of the identity logic then ignored a perfectly valid
`Forwarded` beside it too. Access logs, rate limits and `remote_ip` rules saw
the proxy's address instead of the client's. Empty list elements are now
skipped in both `X-Forwarded-For` and `Forwarded`, as RFC 9110 §5.6.1.2
requires, up to one per permitted hop (32); a header of nothing but commas is
still rejected.

A header that cannot be read no longer discards the other one either. Only two
readable headers that name *different* clients still fail closed to the
proxy's address. A `Forwarded` hop that hid its address (`for=unknown`, an
obfuscated `for=_name`, or no `for=` at all) used to make the whole field
unreadable; it now ends the trust walk at that hop, so nothing reported by the
hidden party is believed, while `X-Forwarded-For` can still name the client.
`X-Real-IP` is consulted only when neither chain header was sent.

### 🍪 `lb_policy cookie` no longer depends on cookie order

A browser holding two cookies with the same name, set for different paths,
sends both, and RFC 6265 §4.2.2 says their order is not something a server
may rely on. `lb_policy cookie sid` took the first `sid` on the first
`Cookie` line, so the same user could be pinned to a different backend
depending on which client they used. It now reads every `Cookie` line and,
when the name repeats, hashes the smallest non-empty value by bytes, so the
same set of cookies always picks the same backend. This applies to HTTP/1.1,
HTTP/2 and HTTP/3 alike.

### 🍪 A FastCGI script reads two `Cookie` lines as two cookies

An HTTP/1.1 client that sent `Cookie: a=1` and `Cookie: b=2` on separate
lines reached a `php_fastcgi` application as `HTTP_COOKIE=a=1, b=2`. A comma
is not a cookie separator, so the script saw one cookie `a` with the value
`1, b=2`. The lines are now joined with `"; "`, the same rule the HTTP/2 and
HTTP/3 paths already used, and all three share one implementation.

### 🛑 SIGTERM lets running requests finish within `grace_period`

A graceful stop (`SIGTERM`, `SIGINT`, or `POST /stop`) exited the process
about a quarter of a second after the signal, whatever `grace_period` said, so
every request still running was cut with no response. The stop now runs in
one order: `/ready` turns 503, the listeners close (a new connection is
refused, and HTTP/2 connections receive `GOAWAY`), running requests finish,
the access log and tracing queue are flushed, and the process exits. It exits
as soon as the last request is done, and cuts whatever is still running once
`grace_period` (default 30 s) has passed. `SIGQUIT` still exits immediately
with status 2.

HTTP/3 takes part in the same stop. Each connection receives `GOAWAY` naming
the first request it will not serve, so a client knows which requests ran and
which it may retry elsewhere; a request opened after that is refused with
`H3_REQUEST_REJECTED`; running requests finish; and the connection closes
with `H3_NO_ERROR` once its last response has been acknowledged. New QUIC
connections are ignored while the process drains. HTTP/3 never sent `GOAWAY`
before, not even at shutdown.
### 🔄 A site can set its own renewal window

`tls { renewal_window_ratio … }` was refused at site level while the same
option worked in the global block, so a Caddyfile that moved the value one line
up or down changed from loading to not loading. It is accepted in both
positions now, and parsed by one function so the two cannot drift apart.

The site value is a **policy for that site's names**, not a replacement for the
global one. Caddy models it as one automation policy per set of subjects, and
this build follows: `renewal_window_ratio` stays the answer for every name no
site claimed, which is why a site writing `0.25` does not make every other site
renew differently. The certificate store resolves the policy by name, using the
same wildcard rule the handshake uses, so a `*.example.com` policy covers the
one label under it and nothing deeper.

**Upgrading:** nothing to do. A site that writes no ratio keeps the process-wide
value exactly as before, and a site that writes one announces itself in the
startup log with the names it covers.

### 🧰 A `vars` matcher key may be a placeholder

`@m vars {http.request.method} GET` was refused, so a Caddyfile using a
placeholder as a `vars` key could not load. The key is now stored exactly as
written, and the braces are what decides how it is read: `{http.request.method}`
asks the request's placeholder engine, while a bare key names an entry in the
request's `vars` map. That is Caddy's rule, and its own adapted JSON carries the
braces through for the same reason.

The placeholder form is checked against the same list a `try_files` candidate is,
and for the same reason: a name the matcher cannot resolve answers the empty
string on every request, so the matcher would compile, load, and silently never
match. A name outside the list is refused with the list in the message —
`{env.HOME}` is the usual one, because the matcher runs in the router and the
process environment is not reachable from there.

**Upgrading:** nothing to do. A `vars` matcher whose key was previously refused
now compiles; one whose key was a bare name behaves exactly as before.

### 🔐 `auto_https ignore_loaded_certs` loads, and does what it names

A Caddyfile carrying this option was refused outright, so a configuration using
it could not load at all. It parses now, and it changes the decision it names:
a site that loaded its own certificate — `tls <cert> <key>` — is put in front
of a certificate authority instead of being skipped because the operator
already has a certificate for that name.

**Upgrading:** the option means what it says, so read it before adding it. A
site whose certificate file was the whole answer will now be issued one, which
is traffic to a third party. Operator-supplied certificates are still what a
handshake serves — the manual file keeps precedence — so the visible effect is
that the name is obtained for and kept fresh, not that the served certificate
changes.

`auto_https disable_certs` remains refused by name, and the refusal now names
only itself.

### 🔌 A request shorter than the h2c preface is answered instead of ignored

A connection whose first request was shorter than 24 bytes was answered with
nothing at all, and the socket stayed open. Those 24 bytes are the HTTP/2
connection preface, which this server reads to tell a prior-knowledge h2c
client from an HTTP/1 one; the read asked for the whole preface before looking
at what it had, and a short request never sends bytes 19 to 24. So
`GET / HTTP/1.0\r\n\r\n` — 18 bytes, and perfectly legitimate — sat with no
first byte until the client's own timeout, and so did an HTTP/1.1 request that
omitted `Host`. The check now stops at the first byte that cannot belong to the
preface, which settles an ordinary request in one or two bytes, keeps the
waiting proportional to the evidence, and still gives a client that really is
sending the preface the time it needs.

**Upgrading:** a client that used to time out against these requests now gets
an answer — `200` for HTTP/1.0 without `Host`, `400` for HTTP/1.1 without it.
Setting `limits { header_timeout }` is no longer needed to stop a short request
from holding a connection; that option still bounds a client that sends nothing
at all.

### 🗄️ Where the TLS store lives, and two TLS options, are configuration now

Three global options an ordinary Caddyfile carries were refused outright, so a
migrating configuration could not load at all. All three parse now, and each
either does what it says or explains why it cannot.

- **`storage file_system <path>`** names the directory the TLS store lives in,
  and outranks `PINGCLAIR_TLS_STORE` and the platform convention. Two
  deployments on one host can now be pointed at two stores from their own
  configurations. A remote or shared backend is still refused by name:
  accepting it would leave the store where it is while reading as if it had
  moved.
- **`ocsp_stapling off`** is accepted, and it names what this build already
  does — no OCSP response is stapled onto a handshake here, so the option asks
  for nothing to change and a startup line says so. `on` and the bare option
  are refused rather than accepted into a stapler that does not exist; Caddy
  refuses both spellings too (`invalid argument 'on'`), so nothing that loads
  upstream is turned away.
- **`servers { listener_wrappers { proxy_protocol } }`** requires a PROXY
  protocol header on every listener the Caddyfile declares, which is what the
  addressless block means upstream. This is upstream's `fallback_policy
  require`, and it is stricter than the name upstream: there the bare
  `proxy_protocol` defaults to `ignore` and answers a request that carries no
  header (measured on `caddy v2.11.4`), where here that connection is refused.
  `fallback_policy require` is accepted because it names this behaviour; the
  permissive policies (`ignore`, `use`, `reject`, `skip`) and `timeout` and
  `allow`/`deny` are refused by name with the reason. `tls` and `http_redirect`
  are refused by name too — TLS here is chosen per site by automatic HTTPS and
  the HTTP-to-HTTPS redirect belongs to the companion port automatic HTTPS
  creates — and so is the addressed `servers <address> { … }` form, which would
  demand the header on listeners the operator did not name.

  **Upgrading:** a Caddyfile that wrote `listener_wrappers { tls }` or
  `http_redirect` still does not load; it now says which wrapper is missing
  instead of `Unknown directive`. One that wrote `proxy_protocol` loads, and
  any client that reached the port without a header now has its connection
  refused rather than served — which is the same thing `listen …
  proxy_protocol` has always done.

### 🗄️ Request cache directives match by name across all field lines

A request whose `Cache-Control` extension merely contained `no-cache` or
`no-store` in its name or value bypassed the response cache. Pingclair now
recognizes only those directive names, without a per-request lowercase copy,
and checks every `Cache-Control` field line. A named `no-cache` directive also
works with a field-name value.

### 🔌 A taken HTTP/3 port stops startup instead of being advertised

The HTTP/3 UDP socket was bound in a background task after startup had
reported success, and every HTTPS listener was already sending
`Alt-Svc: h3=":PORT"; ma=86400`. If another process held the port, the only
sign was a log line; clients cached a day-long promise of a service nobody
ran. The socket is now bound during startup, next to the TCP listener, and a
failed bind stops the process with `failed to bind HTTP/3 (UDP) on ADDR`.
`Alt-Svc` is set only after the bind succeeds, and is withdrawn if the QUIC
server ever stops. **Upgrading:** a deployment that was silently running
without HTTP/3 on a taken port now refuses to start; free the port or turn
HTTP/3 off.

### 🔤 A site name with a capital letter finds its own certificate

A site written `Example.test` with `tls <cert> <key>` served no certificate at
all: the certificate was filed under `Example.test`, and every handshake asked
for `example.test`, the lowercase name clients send. The configuration
validated and startup reported success; only real clients failed. Site names
are now lowercased and stripped of a trailing dot when the configuration is
compiled, and the certificate table files every name in that one spelling.

### 🧭 `TRACE` is refused and `Max-Forwards` is honoured

`Max-Forwards` was never read, so `TRACE` and `OPTIONS` went to the origin
whatever hop budget they carried. On every transport, `TRACE` is now answered
with 405 and an `Allow` list and never reflected or forwarded; `OPTIONS` with
`Max-Forwards: 0` is answered here with 200 and `Allow`; and `OPTIONS` with a
larger budget is forwarded with the value one smaller (RFC 9110 §7.6.2).

### 🔐 The admin API's 401 names the Bearer scheme

A request to the admin API without the right `api_key` got a bare 401, which
RFC 9110 forbids: a 401 must say how to authenticate. It now carries
`WWW-Authenticate: Bearer` and labels its JSON body `application/json`.

### 📜 Internal CA leaves say they have no revocation information

Certificates from `tls internal` never had a CRL or OCSP responder, but nothing
in them said so, so a relying party could not tell "never published" from
"temporarily unreachable". New leaves carry the non-critical `noRevAvail`
extension (RFC 9608); the root does not, and the 90-day lifetime is unchanged.
Leaves already on disk gain it when they are next reissued.

### 🚫 `file_server` answers 405 to methods other than `GET` and `HEAD`

`file_server` never looked at the method, so a `POST` or `DELETE` to a static
file got `200` and the file, as if the write had been accepted. Such a request
now gets `405 Method Not Allowed` with `Allow: GET, HEAD`, on every transport.
A missing file is still `404` whatever the method, and `pass_thru` still hands
a miss to the next handler.

### 🏷️ `file_server` answers conditional requests

`file_server` sent `ETag` and `Last-Modified` but never read them back, so a
browser revalidating its cache downloaded the whole file again. It now
evaluates `If-Match`, `If-Unmodified-Since`, `If-None-Match`, and
`If-Modified-Since` in the order RFC 9110 §13.2.2 sets, on HTTP/1.1, HTTP/2,
and HTTP/3 alike. A matching `If-None-Match` or a current `If-Modified-Since`
answers `304 Not Modified` with the validators and no content; a failed
`If-Match` or `If-Unmodified-Since` answers `412 Precondition Failed`. Each
content coding has its own tag, so a cache's gzip copy is revalidated against
the gzip tag. A `status` override (the maintenance-page shape) skips the
evaluation and keeps its status. Proxied routes are unchanged: they still
forward these fields to the upstream.

### 🚫 A malformed sidecar ETag no longer panics the file server

With `etag_file_extensions` set, a sidecar such as `app.js.etag` holding
something that is not an entity tag, for example two tags on two lines,
panicked every request for that file. Such a sidecar is now skipped with a
warning naming it, and the file is served with its derived `ETag`.

### 🔎 An HTTP/1.1 431 names the field that was too large

When one header field alone is larger than `max_header_bytes`, the 431 body
now names that field (never its value), as RFC 6585 §5 asks; when only the
total is too large, no field is named. The body used to read `431 Error`, and
a site's `error_page 431` was never used because the check ran before the
site had been recorded for the request; both are fixed. HTTP/2 and HTTP/3
now answer the same way; see the entry on oversized header sections above.

### 🚦 A rate-limit rejection says why

A request refused by `rate_limit` used to get a bare `429` status with no
body; over HTTP/1.1 it also had no `Content-Length`, so the connection closed
after it. The 429 now carries a `text/plain` body (`429 Too Many Requests`
on HTTP/1.1 and HTTP/2, `Too Many Requests` on HTTP/3) or the site's
`error_page 429` when one is configured, and still sends `Retry-After` and
the `RateLimit-*` fields.

### 🔪 A compression failure ends the response instead of switching to plaintext

If the encoder behind `encode` failed partway through a response, the rest of
the body went out uncompressed under the `Content-Encoding` header already
sent — a stream no client can decode correctly. The response is now
abandoned at the failure: the HTTP/2 stream is reset and an HTTP/1.1
connection is closed. No real request is known to trigger such a failure;
this closes the path, not an observed outage.

### 🧊 HTTP/3 static files send `Vary: Accept-Encoding`

A file served over HTTP/3 from a `precompressed` sidecar said
`Content-Encoding: gzip` but never `Vary`, so a cache could hand the gzip copy
to a client that never asked for it. HTTP/3 now sends `Vary` from the same
file-server decision HTTP/1.1 and HTTP/2 use, adding to any `Vary` already
there rather than replacing it.

### 🤐 `HEAD` gets no content over HTTP/2 and HTTP/3

A `HEAD` answered by a local handler (a static file, `respond`, a redirect, an
error page) sent the whole body over HTTP/2 and HTTP/3; only HTTP/1.1 dropped
it. Every transport now sends the header, `Content-Length` included, and no
content, and a large file is no longer read just to answer `HEAD`.

### 🚫 A local 204 carries no content and no `Content-Length`

Locally generated responses set `Content-Length` from the body they were
given, whatever the status, so every CORS preflight answered `204 No Content`
with `Content-Length: 0`, and `respond "x" 204` said `Content-Length: 1`. Over
HTTP/2 and HTTP/3 the byte itself was sent as well. A 204 (and a 1xx) now goes
out with neither, a 304 keeps its length but sends no content, and both
transports decide this with the same rule.

**Breaking:** `respond` with a 1xx status is now refused at load time. It used
to compile, but a 1xx only announces that a final response is coming, and
`respond` never sends one.

### 🕰️ HTTP/3 responses carry a `Date`

HTTP/1.1 and HTTP/2 responses get `Date` from Pingora, but the HTTP/3 path
builds its own headers and never wrote one: static files, `respond`, redirects
and error pages went out without it, and a proxied reply kept whatever the
upstream sent. Every final HTTP/3 response now carries this server's `Date`,
from the same clock the other transports use, replacing an upstream's value.

### 🔐 `forward_auth` accepts upstream TLS in Pingclairfiles

`forward_auth { transport http { … } }` now accepts the same TLS options as
`reverse_proxy`: `tls`, `tls_server_name`, `tls_trusted_ca_certs`,
`tls_client_auth`, and `tls_insecure_skip_verify`. The auth subrequest uses
that policy for its upstream connection; unsupported transport options still
fail configuration loading. Legacy JSON keeps its default TLS policy.

### 🧩 Site middleware reaches self-answering routes

Unmatched site-level middleware such as `header`, `request_header`,
`basic_auth`, and `request_body` now runs before terminal `handle` routes as
well as the site's fallback route. Route-local middleware still runs afterward
and can override site defaults.

### 🔀 Cache variants include every `Vary` field line

The H1/H2 response cache now reads all response `Vary` lines and every request
field line they name. A second nominated field or repeated request field can
no longer collapse into the first variant. Names are case-insensitive and
order-independent; request values retain their order, boundaries, and presence.
Invalid `Vary` fields, like `Vary: *`, prevent storage rather than silently
weakening the key. Equivalent merged request fields may occupy separate entries
because arbitrary field syntax is not normalized.

### 🔐 HTTP/3 honours the listener's `default_sni`

A QUIC client without SNI now receives the certificate selected by that
listener's `default_sni`, just like TCP. Without a configured default, or when
an explicit name has no matching certificate, the handshake is refused instead
of presenting whichever site's certificate was inserted first. Defaults remain
local to each listener while certificate rotations update the shared table.
Client authentication still uses the name the client actually offered.
### ➕ DNS-01 no longer deletes other TXT records at the challenge name

Publishing a Cloudflare DNS-01 challenge used to delete every TXT record at
`_acme-challenge.<domain>` before writing its own. `example.com` and
`*.example.com` share that name, so when both were being issued at once each
order could erase the other's proof and fail validation; any unrelated TXT
record at the name was deleted too. Pingclair now only adds its record, marks
it with the Cloudflare `comment` `pingclair acme-challenge`, and on cleanup
deletes only the record that order wrote.

### 🔐 The HTTP-01 responder answers only the path RFC 8555 defines

The ACME HTTP-01 responder removed its `/.well-known/acme-challenge/` prefix
as many times as it repeated, so a path such as
`/.well-known/acme-challenge//.well-known/acme-challenge/TOKEN` returned the
token's key authorization too. It now answers only the prefix followed by one
non-empty token with no further `/`; every other path falls through to normal
routing.

### 🚫 Malformed HTTP/3 requests are reset with `H3_MESSAGE_ERROR`

An HTTP/3 request with a misplaced or unknown pseudo-header, forbidden
`Transfer-Encoding`, a bad `Content-Length` or a `:method` that is not a token
was answered with `400 Bad Request` and a clean end of stream, which a client
cannot tell apart from a site that chose to refuse. RFC 9114 §4.1.2 requires a
stream error instead, so the stream is now reset with `H3_MESSAGE_ERROR` and no
response. Other requests on the same connection are unaffected.

### 🔌 HTTP/3 refuses connection-specific fields

An HTTP/3 request carrying `Connection`, `Upgrade`, `Keep-Alive` or
`Proxy-Connection`, or a `TE` other than `trailers`, was accepted. With
`Connection: upgrade` and `Upgrade: websocket` the fields were even forwarded
to the origin, as though HTTP/3 could carry an HTTP/1.1 upgrade. RFC 9114 §4.2
makes such a request malformed, so it is now reset with `H3_MESSAGE_ERROR`
before any upstream is contacted.

### 🧭 HTTP/3 refuses empty targets and `:protocol`

An HTTP/3 request with an empty `:path` or `:authority`, or a `:path` that does
not start with `/` (other than `*` for `OPTIONS`), was accepted, though RFC 9114
§4.3.1 says these fields must not be empty. A `:protocol` pseudo-header was
accepted and answered `501`, although extended CONNECT is only allowed after
the server offers it, and Pingclair never does. All of these are now reset with
`H3_MESSAGE_ERROR`.

### 🔌 A WebSocket handshake with a split `Connection` header is relayed

A client may send `Connection` as two field lines, such as
`Connection: keep-alive` followed by `Connection: Upgrade`. The upgrade check
read only the first line, decided the request was not a WebSocket handshake,
and stripped `Connection` and `Upgrade` before the origin saw them, so the
upgrade silently failed. Every line is now read.
### 🏛️ The local TLS store is filed the way Caddy files it

**Breaking for anyone who has served a `tls internal` site with an earlier
build, and nothing is migrated for them.**

The store a local site writes is now the one an operator already has tooling
for: `pki/authorities/local/{root,intermediate}.{crt,key}` for the authority,
and `certificates/local/<site>/<site>.{crt,key,json}` for its leaves. A backup
procedure, a "which certificates expire this month" report and a certificate
audit written against a Caddy data directory read this one the same way. The old
tree could not support that at any depth: below the store root the two layouts
shared no name at all.

**The old `internal/` layout is neither read nor moved** — unlike the move to
the service account's home, which copied the store and compared before removing
it. On the next start the server finds no authority where it now looks, creates
a new one, and re-issues the certificates it needs. It also logs a warning when
it finds the old tree, because an operator who pulled a new container image
reads no changelog. Every client that trusted
the old root must be given the new one (`pingclair trust`). If your configuration
also obtains certificates from a public CA, re-issuing them counts against that
CA's rate limits.

Two changes beyond the filenames. The authority is genuinely two tiers now:
leaves are signed by an intermediate, which the root signs, and the chain served
to a client is the leaf plus the intermediate, because the root is the trust
anchor and a client that trusts it already has it. And the private key is no
longer serialized into the metadata file: `<site>.json` carries the covered
names and nothing secret, so it is safe to copy into an inventory, and the key
exists only in `<site>.key`.

A wildcard site is filed under Caddy's spelling of it — `*.example.com` becomes
`certificates/local/wildcard_.example.com/`. An underscore is a legal character
in a host name, so a site literally named `wildcard_.example.com` wants that
same directory; it is now refused by name, with both names in the message,
rather than overwriting the first site's certificate.

### 🩺 The admin API answers Caddy-shaped requests in Caddy's terms

An operator pointing Caddy tooling at this server saw three answers that were
technically true and practically misleading.

`POST /load` with a Caddy document — `{"apps":…}` — was refused with a message
about an unknown field named `apps`. That is the report of a typo in a document
its author copied from a working Caddy installation, and it sends them looking
for a misspelling instead of at the shape this endpoint takes. The refusal now
says which schema this is and points at the Caddyfile spelling that works. The
body is still refused: the two schemas are different, and reading one as the
other is the failure the `deny_unknown_fields` attribute exists to prevent.

`GET /config/apps/` says the same thing in the same terms, and any other unknown
path names the document's real top level rather than only reporting that the
path is not there.

`GET /reverse_proxy/upstreams` now exists, where it used to 404 — an answer a
health check cannot tell apart from a deployment with no upstreams at all. It
lists the addresses the configuration names, walking nested handlers so a
reverse proxy inside a `handle` is found. The per-upstream request and failure
counters Caddy includes are left out rather than reported as zero: the proxy
does not publish them yet, and a counter nothing maintains is worse than a
counter that is absent.

### 🔄 The plaintext listener redirects an unknown `Host` too

The listener automatic HTTPS provisions on port 80 has one job — send plaintext
visitors to HTTPS — and it did that only when the request's `Host` named a
configured site. A visitor arriving by IP address, by a hostname that resolves
here but is not in the configuration, or through a load balancer that sends its
own `Host`, got a bare 404 from the very port whose purpose was to forward them,
while typing `https://` by hand worked. Caddy answers the same request with the
308, which is what the README already promised.

The redirect echoes the caller's `Host`, so the port in it is always this
server's own HTTPS port and never one the request carried — a caller-chosen
authority in a `Location` is an open redirect — and it names the port only when
that port is not 443. A `Host` that is not an authority at all, one carrying a
slash, an `@`, a space or a control character, produces no redirect rather than
an escaped one, and falls through to the same 404 as before. `disable_redirects`
still turns the whole behaviour off: the listener is then provisioned for ACME
validation only, with no routes, and redirecting there would quietly undo the
mode the operator asked for.

### 🕰️ Access-log records carry a timestamp

A JSON access-log record had no field saying when its request happened, so a
collector had to substitute its own arrival time. That is wrong after any
restart, rotation or buffering, and a timestamp is the one field a log line
cannot recover later. The record now carries `ts`: seconds since the Unix epoch
with a fractional part, named and shaped like Caddy's own timestamp.

This is an addition, not a schema change — every other key keeps its name, its
place and its shape. Both transports derive the value the same way, from the
instant each one started timing the request, so a record is dated when its
request began rather than when it finished and a slow request does not sit in a
collector's timeline beside requests that arrived after it.

### 🧩 `adapt` validates what it prints

`pingclair adapt` converted a Pingclairfile and exited 0 without checking the
result, so a migration script that used it to decide whether a configuration was
ready got a green light for a site the server then refused to start. The two
commands disagreed in the direction that hurts: `adapt` accepted what `validate`
rejected, and the refusal arrived after the cutover, not before it.

`adapt` now runs the same validation `validate` does before printing anything,
so an exit code of 0 means the document this build produced is one this build
can load. `--validate` is still accepted and no longer changes anything, so a
script that passes it keeps working.

The output is Pingclair's own JSON, not Caddy's `{"apps":…}`, and the README now
says so explicitly — including the consequence, which is that `caddy adapt`'s
output cannot be loaded here and this output cannot be loaded by Caddy. Migrating
means keeping the Caddyfile that both servers can read.

### 🗜️ A site compresses only where `encode` asks

A static site — `root *` plus `file_server`, nothing else — answered
`Content-Encoding: gzip` to every client whose `Accept-Encoding` allowed it.
The Caddyfile said nothing about compression; the compiler simply fell back to
gzip for a site with no `encode` directive, and each file server then treated
that as permission. Caddy compresses only where an `encode` directive asks, so
the same file reached a client with a different `Content-Length`, a different
`ETag` and therefore a different stored object on the two servers.

**This changes behaviour on upgrade.** A Caddyfile that was relying on the old
default now serves the bytes on disk and compresses nothing. Write
`encode gzip` — or `encode zstd gzip`, which lists the preferences in order —
on the site to get it back. `encode off` still means what it did, and
`file_server { compress off }` still exempts one file server on a site that
does compress.

A JSON configuration is deliberately unaffected: with `encodings` absent it
still defaults to gzip, so a stored document written before that field existed
keeps behaving the way it was written. The two entry points differ on purpose —
a Caddyfile is read by someone who can see whether `encode` is there.

A `Range` on a compressing file server is answered `206` from the bytes on
disk, in the offsets its own `Content-Range` names, with no `Content-Encoding`:
compressing the interval would put gzip bytes under an offset that counts the
file.

### 🌊 Compressed HTTP/1.1 responses keep the connection open

A proxied response that Pingclair compressed for an HTTP/1.1 client lost its
`Content-Length` and gained no `Transfer-Encoding`, so its end was signalled by
closing the connection — right after `Connection: keep-alive` had told the
client it could reuse it. Every compressed response cost a new connection, and
a client could not tell a complete body from a cut one. Compressed HTTP/1.1
responses are now sent with `Transfer-Encoding: chunked`.

### 🧹 Compression drops the origin's digest fields

When Pingclair compressed a proxied response it forwarded the origin's
`Content-Digest`, `Repr-Digest`, `Digest` and `Content-MD5` unchanged, though
they described the uncompressed bytes. Any client that verified them reported
corruption that never happened. The fields are now removed whenever the proxy
re-encodes a body; responses it leaves alone keep them.

### 🛡️ `Cache-Control: no-transform` stops compression

An upstream response marked `Cache-Control: no-transform` was compressed
anyway, replacing a body whose exact bytes a signature or hash check
downstream may depend on. RFC 9111 binds every intermediary to the directive,
cache or not, and Pingclair now forwards such responses unchanged, with their
original `Content-Length`. The same holds when the directive comes from a
`header` directive on the route.

### 📐 Partial and bodiless proxied responses are no longer compressed

A proxied `206 Partial Content` — from the origin, or sliced out of the cache
for a `Range` request — was gzip-compressed while its `Content-Range` still
counted the uncompressed bytes, so a client assembling the file from ranges
wrote the wrong bytes at the wrong offsets. `HEAD`, `204` and `304` responses
also lost their `Content-Length` to a coding that had no body to apply to.
Compression now applies only to complete representations: never a `206`,
never a response carrying `Content-Range`, never `HEAD`, `204` or `304`.

### 🧊 Compression adds to `Vary` instead of replacing it

A proxied response that Pingclair compressed had its `Vary` field overwritten
with `Vary: Accept-Encoding`, erasing whatever the origin or the CORS policy
had put there — `Vary: Cookie` on a signed-in page, `Vary: Origin` on a CORS
grant. A shared cache or CDN in front of Pingclair then stored the page keyed
on the coding alone and could serve one user's response to another.
Compression now appends `Accept-Encoding` to the existing list, never repeats
it, and leaves `Vary: *` alone.

### 🪪 `identity` takes part in `Accept-Encoding` negotiation

The unencoded body was never ranked against the codings, so a client's view of
it was ignored. `gzip;q=0.5, identity` — "plain, preferably" — got gzip, and
`identity;q=0` — "anything but plain" — got the plain body. Both static files
and proxied responses now rank identity like any coding: a coding rated below
identity is skipped, and refusing identity lets codings the client did not
mention stand in as last resorts. When nothing acceptable is left (`*;q=0`),
the plain body is still sent rather than a `406`, which RFC 9110 §12.5.3
permits.

### 🗜️ Precompressed sidecars follow the client's quality values

`file_server { precompressed … }` picked a `.gz`/`.zst`/`.br` sidecar by
searching the raw `Accept-Encoding` text for the coding's name. A client that
sent `gzip;q=0` — "never gzip" — got the `.gz` anyway, and one that sent `*`
got no sidecar at all. Sidecars are now chosen by the same negotiation as
on-the-fly compression: the client's quality values first, the configured
order to break ties, and the next-ranked sidecar when the preferred one is
missing on disk.

### 📥 No request-body ceiling unless the configuration asks for one

A proxied request body one byte over 1 MiB was answered `413 Payload Too Large`
with `Connection: close`, from a default nothing in the configuration stated and
nothing in the startup log mentioned. Caddy applies no request-body limit unless
one is configured, so a Caddyfile that worked there refused uploads here. There
is now no ceiling by default; `request_body { max_size … }` on a route, or
`client_max_body_size` on a site, sets one as before, and `0` still means
unlimited. **If you were relying on the 1 MiB default, set a limit explicitly**
— the effective limit on an unconfigured site is now unbounded.

A site-level `request_body { max_size … }` written without a matcher now limits
every request in the site, as it does in Caddy. It used to reach only requests
that fell through to the site's own handlers: a request answered inside a
`handle` block was unlimited, so a 5 MiB upload to `handle /api/* { … }` was
accepted under a 1 MiB site limit. A `request_body` inside a `handle` still
overrides the site's limit for that route, in either direction.

### 🔪 A broken HTTP/3 response now ends in a reset, not a clean finish

When an upstream failed partway through a response body, or pacing ran past
the whole-request deadline, HTTP/3 clients used to receive the headers, a
short body, and a normal end of stream — a truncated response presented as a
complete one. The stream is now reset with `H3_INTERNAL_ERROR`, so clients
report a failed transfer instead of saving a short file. Proxied responses
and subrequest responses both take the new path. An error raised after a
response started — a file whose pacing overran `request_timeout`, for one —
also resets the stream now, where it used to append the error page's body to
the bytes already sent. HTTP/1.1 and HTTP/2 no longer try to write an error
page onto a response that already started either: the HTTP/2 stream is reset
with `INTERNAL_ERROR` and an HTTP/1.1 connection is closed.

### 🛡️ Retries after the upstream has answered repeat only idempotent methods

A bodyless `POST` or `PATCH` that `lb_retry_match` named used to be sent again
after the upstream answered with a retryable status or dropped the connection
mid-response, because the retry gate asked only whether the request had a body.
An empty body does not make a `POST` safe to repeat — `POST /orders/submit` can
place an order without one. Once the upstream may have seen the request,
Pingclair now repeats only `GET`, `HEAD`, `OPTIONS`, `TRACE`, `PUT` and
`DELETE`, on both HTTP/1.1–2 and HTTP/3. A connection failure, where the
upstream never received anything, is still retried for any method.
`lb_retry_match method POST` still loads, with a warning at startup and on
reload that the named non-idempotent methods apply only to connection failures.

### 🔁 HTTP/3 waits past `103 Early Hints` for the real response

An HTTP/3 request proxied to an HTTP/1.1 upstream that answered with
`103 Early Hints` (or `100 Continue`) before its real response used to receive
the interim response as its whole answer — a bodiless `103` — and never the
response behind it. Pingclair now skips interim responses and relays the final
one, and the circuit breaker and `lb_retry_match` judge that final status, so
an upstream that sends hints in front of its `503`s is still broken. Hints are
not yet forwarded to HTTP/3 clients. An upstream `101 Switching Protocols`,
which an HTTP/3 request never asks for, now yields `502`, as does an upstream
that sends more than 32 interim responses before its answer.

### 🚫 HTTP/3 no longer forwards `Expect`

An HTTP/3 request proxied to an upstream has its whole body sent before the
upstream's response is read, so an upstream's `100 Continue` could only arrive
after the body it was meant to invite. Pingclair now drops `Expect` from HTTP/3
requests before forwarding them.

### 📜 An unusable `max-age` no longer overrides `cache { ttl }`

The cache treated the origin as having stated a lifetime whenever a `max-age`
token or an `Expires` field was present, even when neither could be used. So
`Cache-Control: max-age=abc` set the configured `ttl` aside, and the response
lived a 60-second placeholder nobody configured. The `ttl` now applies unless
the origin's lifetime actually parses. A response with two `Expires` lines,
which contradict each other, is stored stale and rechecked on every reuse, one
of the two answers RFC 9111 §4.2.1 allows.

### ⏳ A cached error no longer lives for the route's whole `ttl`

`cache { ttl }` replaced the lifetime of every stored response, so a `503` the
origin said nothing about was held for the full `ttl` — up to a year — and one
upstream hiccup was served to every visitor until it ran out. The `ttl` now
applies only to a `200` whose origin stated no lifetime. A silent `404` or `410`
is held for ten seconds (or the `ttl`, if shorter), and a silent server error is
not stored at all; an origin that wants its errors cached can still say so with
`Cache-Control`.

### 🚫 The response cache no longer stores statuses it must not share

A `429 Too Many Requests` carrying `Cache-Control: max-age=300` was stored and
replayed to every visitor for five minutes, so one rate-limited moment at the
origin became a site-wide outage. The cache now stores only an explicit list of
statuses: RFC 9110's heuristically cacheable codes plus `302`, `307` and the
gateway errors. `428`, `429`, `431` and `511` (which RFC 6585 forbids a cache to
store) and `206` (this cache does not assemble ranges) always reach the origin,
whatever their caching headers say.

### 🗄️ A cached response is compressed per client, not per stored copy

On a `reverse_proxy` route with `cache`, a compressible response above the
compression threshold could reach the client as plain text under a
`Content-Encoding: gzip` header, and the stored entry could pair one coding's
bytes with another's headers. Compression now runs after the cache, on the way
out to each client: the store keeps the origin's bytes, a client that asks for
gzip gets gzip, and a client that asks for nothing gets the original body.

### 💡 An upstream `103 Early Hints` no longer decides the final body's coding

When an upstream sent a `103` naming a compressible type ahead of a final
response that should not be compressed (an image, say), the H1/H2 proxy
compressed the final body anyway and sent it under headers announcing no
coding, so the client received bytes it could not read. Informational
responses are now skipped by the compression decision; only the final
response's own headers choose the coding.

### 🛡️ A failure behind an upstream `103` now counts against the circuit breaker

The H1/H2 proxy reported an upstream's `103 Early Hints` to the circuit
breaker as the request's outcome — a success — and then ignored the real
status that followed. An upstream that sent a hint before every `503` never
opened its circuit. Informational responses other than `101` are no longer
reported or offered to `retry` status matching; the final status is. The
HTTP/3 path is tracked separately.

### 🪟 `file_server` honours `If-Range`

A client resuming a download sends `Range` with `If-Range`, naming the version
of the file it already holds. `file_server` ignored `If-Range`, so after the
file changed it still answered 206 with bytes from the new version, and the
client stitched them onto the old one. The range is now honoured only when the
`If-Range` entity tag matches the current `ETag` under strong comparison, or
the date matches `Last-Modified` and the file is at least one second old;
otherwise the whole current file is sent with 200. HTTP/1.1, HTTP/2, and
HTTP/3 share the one decision. `If-None-Match` and `If-Modified-Since` are
still not evaluated.

### 🏷️ Static-file ETags describe one exact body

A strong `ETag` promises that every response carrying it has identical bytes.
`file_server` broke that promise: the tag came from the file size and a
whole-second modification time, so two same-size edits within one second kept
one tag, and the plain file, its precompressed sidecar, and a live-compressed
body all went out under the same tag. Tags are now built from the
nanosecond modification time and differ per content coding — a gzip body is
tagged `"…-gzip"`. They stay strong, so resumable downloads keep working.
**Upgrade note:** every static ETag changes once, so clients revalidate each
cached file one time after the upgrade.

### 🌊 HTTP/3 proxy streams keep moving across empty upstream reads

An upstream can produce an empty body read before more data arrives. That empty
read previously occupied the HTTP/3 send queue and could stall a live SSE or
other streaming response. Pingclair now skips empty chunks while preserving the
end-of-stream signal. The H3 cancellation check also verifies continued output
without a retry.

### 🃏 A wildcard site orders the wildcard, once

A site configured as `*.example.com` now obtains one certificate for
`*.example.com` and serves every name under it from that leaf, instead of
ordering a separate certificate for each name a client happened to ask for.
The name ordered is the one the configuration spelled — an exact entry still
wins over the wildcard that would cover it, so listing `example.com` beside
`*.example.com` obtains the apex's own certificate, because a wildcard covers
exactly one label and never its own apex.

Two consequences worth stating: the leaf is obtained at startup like any other
`tls auto` name, so the first visitor does not pay for a DNS-01 propagation
wait inside their handshake; and the subdomains this site serves stay out of
Certificate Transparency logs, which is the privacy argument for a wildcard in
the first place. Reaching the wildcard from a concrete name is a store lookup,
not an order.

### ⚖️ The default load-balancing policy matches Caddy

A `reverse_proxy` that names no `lb_policy` now picks an upstream **at random**,
which is Caddy's documented default, instead of round-robin. Both are reasonable
policies, but only one of them is what the Caddyfile a site migrated from was
already doing — and the difference was invisible on the single-upstream
configurations most sites have. Write `lb_policy round_robin` for the previous
behaviour.

### 🚫 `tls { http3 off }` keeps a site off QUIC, and now it means something

The option was accepted, documented in the HTTP/3 guide, and inert: it reached
the canonical configuration, and the only code that read it was the reload
comparison. It now keeps that site off the QUIC listener while the listener
stays up for every other name on the port — a handshake for the opted-out name
finds no certificate, so a client that was told this port speaks HTTP/3 falls
back to TCP instead of reaching a site that never asked to be served over it.
HTTP/1.1 and HTTP/2 are untouched.

The per-site flag also defaults to **on**, like the global switch, instead of
false: while it defaulted to false, "did not say" and "turned it off" were the
same value, which is why nothing could read it. Whether a QUIC listener exists
at all is still the global `servers { protocols … }` list.

### 🧩 `adapt` converts; `validate` and `run` refuse what cannot be provisioned

`pingclair adapt` and the Admin API's `POST /adapt` stop at proposing the
document: the validation pass that used to run inside the shared compiler
belongs to `validate` and `run`, which is where upstream draws the line too —
`caddy adapt` does not validate. `adapt --validate` still runs the checks on
request.

Two settings that previously failed only at **startup** now fail validation,
because that is where every configuring path meets:

- `metrics { otlp }` — there is no OTLP exporter behind the switch, and metrics
  are scraped only.
- Any `dns` provider other than `cloudflare`, in the global `dns`, the global
  `acme_dns`, or a site's own `tls { dns … }`.

A document naming either still adapts — the compatibility corpus measures
adaptation, not provisioning — while `pingclair validate` and `pingclair run`
refuse it with a message that says what is missing.

### 🔁 The retry policy has one implementation

`status_codes`, `methods`, `path_patterns` and `expressions` are gone from the
compiled configuration. The runtime used to keep **two** ways to decide whether a
failed attempt may be retried — the `lb_retry_match` predicate, and the flat
lists as a fallback whenever it was empty — and two implementations of one rule
drift.

A document that still spells the flat fields is translated at load into the
predicate they stood for: status **and** method **and** (no path patterns **or**
one of them). That covers both paths — the JSON shape a pre-predicate
configuration carries, and the DSL's own `retry` block, which upstream spells
that way. `expressions`, which never took part in the decision, is accepted and
dropped.

**Breaking:** the exported configuration changes shape. `GET /config` and
`pingclair adapt` no longer print the flat fields, a misspelled field inside
`retry` is now a load failure, and an explicitly empty `methods` list stays a
load error rather than quietly becoming "any method".

### 🥇 `lb_policy first` means first

The policy was accepted and mapped to round-robin, so a primary/secondary pair
written the way upstream documents it sent half its traffic to the secondary.
It now pins to the first backend that can take the request and moves to the next
only when that one cannot — the same predicate the other strategies use, without
the counter comparison, and the backup list still covers a pool where nothing is
selectable.

### 🗂️ `file_server browse` takes upstream's listing options

`browse` now parses its options block, and `file_limit <n>` — upstream's name
for it, in the place upstream puts it — caps how many entries a directory
listing shows. The field and its behaviour already existed (the JSON
configuration and `pc file-server --file-limit` both reached it); the DSL was
the one door that could not. A listing template, `reveal_symlinks` and `sort`
are refused by name rather than ignored, and `browse` is now found after a
matcher as upstream allows.

### 📦 Releases are served from `releases.pingclair.com`

GitHub remains where a release is created — the tag, the notes, the assets — and
every release is mirrored to Cloudflare R2, which serves it from a bucket with
no egress fee and a CDN in front of it. Each mirrored object carries the sha256
GitHub reported for it and is read back before the mirror run is allowed to
succeed; a release whose assets GitHub cannot digest is refused rather than
mirrored unverifiable.

The installer reads a channel document on that host — `latest` and `prerelease`,
each naming a tag and a sha256 per asset — verifies the archive against the
digest before extracting it, and falls back to the GitHub releases API when the
host cannot be reached. The one-liner in the READMEs and the documentation is
now <https://pingclair.com/install.sh>, which the documentation Worker serves
from that same single source rather than from a copy.

### 🏠 The certificate store lives under the service account's home

`/var/lib/pingclair/certs` is now `/var/lib/pingclair/.local/share/pingclair`:
the data directory the binary resolves once the `pingclair` account has a home
(`/var/lib/pingclair`), which it now does. The unit therefore names no
`PINGCLAIR_TLS_STORE`, and the unit, `pingclair environ`, and the documentation
all give the same answer to where certificates are.

An upgrade moves an existing store — copy, compare, and only then remove —
and stops if the copy does not match, because the store holds the ACME account
key and every issued certificate, and re-issuing them runs into the certificate
authority's rate limits. The container image names the same path for its
declared volume, so a container and a package install keep their state in one
place.

### 📡 DNS-01 publishes the proof the authority expects

DNS-01 now publishes the base64url-encoded SHA-256 digest of the ACME key
authorization instead of HTTP-01's raw `token.thumbprint` value. The old value
propagated successfully but could never satisfy the authority, so every DNS-01
order ended `Invalid` and no certificate could be obtained through that
challenge — on a host where port 80 is closed, that meant no certificate at
all.

When an order is invalid, Pingclair now refreshes the failed authorization and
includes the authority's challenge error in the issuance failure. The TXT record
stays present until that final status and diagnostic have been read, then is
removed on every exit path. The DNS-01 documentation also makes the two jobs in
an explicit TLS block clear: `auto` authorises issuance and `dns` selects its
challenge.

### ⚡ Per-request work removed from the hot paths

The reverse-proxy configuration is now borrowed from the published snapshot
instead of copied several times per request; small uncompressed static bodies
are answered from a cache keyed on path, mtime and length instead of being read
per request; and the per-request copies of the request id, the original-URI
variables, the client address rendering and cached bodies are gone. Runtime
records keep going to the stream they always went to — the write itself is
handed to a background thread, which is what keeps it off the request path.

### 📝 Buffered access logging

Configured access-log sinks now batch complete records up to 64 KiB, with a
5 ms flush interval and flushes before rotation and explicit barriers. Formatting
avoids temporary numeric strings. Fields, filtering, sampling, and the default
tracing fallback are unchanged. Normal shutdown attempts a bounded 250 ms drain
of accepted access records, and offers every registered writer its barrier
inside that one budget — a sink that fails does not cost the sinks behind it
their flush — while a stalled sink still cannot hold shutdown indefinitely.

### 🚿 The log queue is drained on the way out

The server leaves through `std::process::exit`, which runs no destructors, so
the tracing writer's queue used to be abandoned rather than drained: the last
records — the ones describing the shutdown itself among them — could be
missing from the log, and the reporter that would have said so was one of
them. Graceful shutdown now drains that queue as well as the access log, and
the fallback taken when a signal listener cannot be installed leaves through
that same path instead of exiting bare. A forced SIGQUIT still exits
immediately, which is the behavior it reproduces.

### 🪦 `v0.1.x` is unmaintained

Stated here as well as in the READMEs, because somebody still running `v0.1.7`
has no other way to find out. **There will be no `v0.1.8`**: that line receives
no fixes, no backports and no security advisories, so a defect found in it is
recorded and left alone. The upgrade target is `0.2.0`.

⚠️ One difference worth naming, since it is the concrete reason not to wait.
**The `v0.1.x` Admin API authenticated nothing.** That release parsed
`admin.api_key` into its configuration and then never read it: the admin server
started as `run_admin_server(addr, proxies)` with no key argument, `ApiKeyAuth`
was never constructed anywhere in the tree, and the routes carried no
authorisation layer. An operator who bound the admin listener to a routable
address and set a key had an open admin API and a field that said otherwise. On
`main`, an Admin API with no key configured logs a warning and admits loopback
clients only.

📌 No advisory accompanies this, by the 2026-08-17 decision: with no patch and
no maintained branch, an advisory would only describe a hole nobody can close.
The behaviour change is recorded; the abandoned release is not.

### 🐛 Known defect — WebSocket upgrades under load

Pingclair proxies WebSocket, and roughly **10–15 % of upgrades fail when the
machine is busy**. Stated here, in the release notes, because the feature is
not missing: it works, and then intermittently does not.

The fault is in `pingora-proxy 0.9.0` rather than in this project's handling of
the upgrade — a trace confirms the request reaches the upstream carrying
`Connection: Upgrade` and `Upgrade: websocket`. Upstream issue:
[cloudflare/pingora#946](https://github.com/cloudflare/pingora/issues/946),
open as of 2026-09-10. The proposed fix,
[cloudflare/pingora#947](https://github.com/cloudflare/pingora/pull/947), is
still awaiting maintainer review.

An upgrade request is a `GET` with no body, and the end of that empty body is
mistaken for the end of the tunnel — but only when the upstream's `101` is read
first. The proxy loses that race more often the less idle the machine is: forty
of forty upgrades succeed on an idle ten-core machine, six of forty fail in a
two-core container, and inserting any delay before the `101` — even a bare
yield — removes the failures entirely. A developer machine will report that
this defect does not exist.

No configuration avoids it. From outside, a failure is a connection torn down
immediately after the `101`, both ends seeing EOF with no error.

### 🐛 Other known defects that ship

Found before the release and deliberately left for the next version, because
none of them widens what a configuration exposes. Each has an open issue with a
reproduction; the workaround, where there is one, is in the issue.

- **After an upgrade, a client that half-closes ends the tunnel**, and bytes the
  backend still had to send are lost (#274). The dependency's upgrade loop
  ends the whole exchange when the request side finishes, and it offers an
  embedder no hook to keep the other direction open.
- **HTTP/3 transport-parameter checks** fail 18 of 77 h3spec cases; the fix
  belongs in the QUIC library (#282).
- **A wildcard site's manual certificate** is not served for the names it
  covers over TCP; `tls internal` is not affected (#285).
- **A request's trailer fields are discarded on HTTP/1**, so an `aws-chunked`
  upload's checksum never reaches the origin while the client is answered
  normally. The dependency's HTTP/1 body reader parses the trailer section to
  find the end of the body and does not surface the fields; its own source
  marks proper trailer handling as a TODO (#257).

### ⚠️ Breaking

- 🔢 **A site address with a port and no scheme is now served over HTTPS, as it
  is upstream.** `secure.example:8443` — a hostname, a non-standard port, no
  scheme — used to compile to a listener whose `tls` block said `auto: false,
  internal: false`: TLS switched on, and no issuer, no certificate and no key
  named. That is not "plaintext with a misleading block"; it is a listener that
  can never complete a handshake, because nothing can resolve a certificate for
  it. The gate deciding this tested the *scheme* of each listener, while
  upstream's `automaticHTTPSPhase1` tests the **port** and skips a site only
  when every listener it names is the HTTP port.

  ⚠️ **This changes what an existing address means.** `example.com:8080` used to
  be plaintext and is now HTTPS with automatic issuance. `http://` in front of
  the address is the spelling that asks for plaintext on any port, and it is
  unchanged — as are `localhost:8080` and `127.0.0.1:8080` (already on the local
  authority), a bare `example.com` with no port, and anything pinned to the HTTP
  port. Two sites sharing a port must still agree about TLS, or the whole
  configuration is refused.

  📌 The address-form fixture had frozen the old answer under a site named
  `plain.example`, which is what a fixture is for and also what made a wrong
  answer look deliberate.


- 🧱 **A block must now open at the end of its line.** `route { respond "hi" 200`
  and `to 10.0.0.1:8080 { weight 3 }` used to compile; they are refused now, as
  the format refuses them — measured against v2.11.4, which answers
  `Unexpected next token after '{' on same line`.

  The relaxation was deliberate and temporary: it was introduced when the parser
  front end was replaced, because enforcing the rule in the same change would
  have meant a swap that also changed what compiles, hiding which of the two broke
  something. Tightening it was left as its own change, and this is it.

  ⚠️ **All three READMEs documented a configuration this rejects**, and so did
  thirty-odd test fixtures. The README block used `to 10.0.0.1:8080 { weight 3 }`,
  which upstream would not have accepted either — so the documentation was
  describing a Pingclairfile that was not a valid Caddyfile, in a project whose
  claim is that they are the same thing. Rewritten to the multi-line form in
  English, French and Chinese.


- 🔢 **Twelve `transport http` tuning knobs are now refused instead of accepted
  and ignored.** `read_buffer`, `write_buffer`, `max_response_header`,
  `dial_fallback_delay`, `expect_continue_timeout`, `resolvers`, `compression`,
  `max_conns_per_host`, `keepalive_idle_conns_per_host`, `keepalive_interval`,
  `tls_renegotiation` and `tls_except_ports` parsed, were stored in an untyped
  map inside the compiled configuration, produced one warning at startup, and
  were read by nothing.

  Every one is a Go `http.Transport` concept with no equivalent at the same layer
  in this build's upstream stack, and the near-misses are worse than the gaps:
  `read_buffer` is a buffered-reader size, not the socket receive buffer that
  happens to be reachable, and `keepalive_interval` is an HTTP keepalive, not the
  TCP one. Honouring either approximately would change behaviour without saying
  so. **A configuration using any of them no longer loads**; remove the setting.

  `versions` is the exception and is now implemented rather than ignored:
  `1.1`, `2` and `1.1 2` compile to a typed choice that reaches the upstream peer
  and its connection-reuse group, so a route that asked for HTTP/1.1 cannot be
  handed an HTTP/2 connection somebody else opened. `versions 3` is refused —
  there is no HTTP/3 client for an upstream here, and answering with HTTP/2 would
  speak a different protocol than the one asked for — and `h2c` is refused because
  the `h2c://` upstream scheme already spells it and also decides pool grouping.


- 🔗 **`preferred_chains` is now refused instead of accepted and ignored.** The
  setting parsed, compiled and was stored, and the only sign it did nothing was
  one warning at startup — so an operator who asked for a specific issuer chain
  got whichever one the authority offered first and a log line they read once.
  This build's ACME client cannot request an alternate chain at all
  (`instant-acme` 0.8.5, verified 2026-08-12), so the setting fails closed like
  every other one that cannot be honoured. **A configuration carrying
  `preferred_chains` no longer starts**; remove the setting. The compatibility
  table listed it as implemented, which was the second half of the same defect,
  and all three READMEs now name it among what is not supported yet.


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

- 🦀 **Building from source now requires Rust 1.98 instead of 1.97.** The
  workspace's `rust-version` is 1.98 and CI pins 1.98.1, so the toolchain is the
  same one the tests ran under. `cargo install` picks the toolchain up from the
  manifest; anyone on a pinned 1.97 needs `rustup update` first.

- 🏷️ **An HTTP/3 request now reaches an HTTP/1 upstream with the same field-name
  spelling an HTTP/2 request does.** Both transports previously built the same
  request two different ways: the HTTP/2 path kept no record of field-name case,
  the HTTP/3 path built one and filled it with the lowercase names HTTP/3
  requires on the wire. An upstream reading raw bytes therefore saw `Host:` from
  one and `host:` from the other for the identical request. HTTP/3 now keeps no
  record either, so the two agree.

  The record it was keeping could never have held anything but lowercase — the
  specification requires it and the parser refuses anything else — and building
  it cost one map allocation per request plus a cloned name, a cloned key and a
  hash insert per field.

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
  listeners.
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

- 🔁 **`systemctl reload` applied nothing while reporting success.** The unit
  installed by `scripts/install.sh` set `ExecReload=/bin/kill -HUP $MAINPID`,
  and the server drops `SIGHUP` on purpose — `SIGUSR1` is the reload signal,
  the same signal table Caddy keeps. `systemctl reload pingclair`, and
  `pc service reload` which wraps it, therefore answered
  `✅ Service reloaded successfully` while the old configuration kept serving,
  and an operator editing `/etc/Pingclair/Pingclairfile` had no way to notice.
  `scripts/pingclair.service` now sends `SIGUSR1`.

  systemd can only see that `kill` exited, never what the server made of the
  file it read afterwards, so the outcome is published where the operator is
  already looking: the server sends `sd_notify` status lines, and
  `systemctl status pingclair` reads `Serving (reloaded 2 listener(s) in
  3.4ms)` or `Reload rejected: listener topology changed …`. `pc service reload`
  says the same thing in words rather than claiming the file was applied. A
  configuration the running server refuses still leaves the previous one
  serving.

- 🧰 **The one-liner install wrote a unit the shell had been editing.** The
  fallback heredoc in `scripts/install.sh` was unquoted and one of its comments
  contained a backticked word, so installing through `curl … | sudo bash` ran
  the binary during installation and substituted 25 lines of `--help` output
  into `/etc/systemd/system/pingclair.service` — `systemd-analyze verify`
  reported `Missing '=', ignoring line` for the unit it had just written. The
  same copy carried `Restart=always` without `RestartPreventExitStatus=1`, so a
  configuration the server refuses at startup was retried every five seconds
  instead of leaving the unit failed and visible to the operator.

  The embedded copy is now byte-identical to `scripts/pingclair.service` — the
  reload signal and the hardened restart policy included — and `just repo-lint`
  compares the two, so they cannot drift apart again without a red gate. A
  fresh one-liner install therefore gets `ProtectSystem=full`, `PrivateTmp`,
  `NoNewPrivileges` and `LimitNPROC` as well.

- 🔁 **A refused configuration is no longer retried forever.** Matching the two
  unit copies was not enough to fix this. `systemd` applies
  `RestartPreventExitStatus=` to the main process, never to a failing
  `ExecStartPre=`, and the unit ran `validate` as exactly that — so a file the
  compiler refuses left the unit in `activating` while `NRestarts` climbed every
  five seconds. Measured on Ubuntu 24.04 (systemd 255): `NRestarts` 0, 1, 2, 3, 4
  over twenty seconds, with `Restart=on-failure` and
  `RestartPreventExitStatus=1` already in place.

  The unit no longer carries a pre-command. The server compiles the
  configuration itself before it binds anything and exits 1 when it refuses it,
  which is the exit code the restart policy was written for; the same
  measurement then reads `is-active=failed` with `NRestarts=0`. `just repo-lint`
  refuses a unit that grows an `ExecStartPre=` again, comments excepted.

- ⚡ **A `handle_response { file_server }` no longer rebuilds its file server for
  every response.** Each response constructed one and threw it away. The
  construction itself is cheap; the caches it carries are the point, and
  starting them empty every time meant a custom error page recomputed its
  content type, `ETag` and `Last-Modified` on every single response — and, with
  `compress` on, deflated the same file again for each one. Avoiding exactly
  that is the only reason those caches exist.

  Servers are now built once per distinct configuration and shared. A root that
  comes from `{http.vars.root}` is still built per request and deliberately not
  remembered, because that value can be assembled from the request and a map
  keyed on it would grow without bound.

- 🍪 **A cookie split across several field lines now arrives whole**, on HTTP/2
  as well as HTTP/3. Both protocols let a client send `Cookie` as separate lines — browsers do, because it
  compresses better — and every field went into the request with a call that
  *replaces* rather than adds, so only the last line survived. The origin
  received a truncated cookie and nothing reported a problem. The pieces are
  now rejoined with `"; "` — what RFC 9114 §4.2.1 requires of HTTP/3 and RFC
  9113 §8.2.3 requires, word for word, of HTTP/2, before the request reaches
  anything that is neither. HTTP/1.1 is left alone: a client that sent three
  lines there really did send three, and passing them through is faithful.

  The same defect silently discarded every other repeated field. A client
  sending `Accept-Encoding: gzip` and `Accept-Encoding: br` on separate lines
  had the first one dropped, so the origin was told the client accepts
  something it never said. All values are now kept.

- 🛡️ **A request carrying two `Content-Length` fields is refused** rather than
  collapsed to one of them, on every protocol (RFC 9110 §8.6). How many bytes a
  body has is not a question two readers may answer differently, and the
  previous behaviour — validate each duplicate's grammar, then keep whichever
  came last — is the disagreement request smuggling is built on. An HTTP/3
  request with two `Host` fields is refused for the same reason; HTTP/1.1
  already refused it.

- 🔊 **The server now logs at a level someone can read.** With `RUST_LOG` unset
  — which is every deployment that does not know to set it — the subscriber
  emitted `ERROR` and nothing else. Fifty-eight informational lines across the
  workspace reached nobody, certificate issuance and renewal among them, so a
  running server left no record that it had ever obtained a certificate.

  On a public host the effect was worse than silence: the only lines that did
  get through were strangers scanning port 80 and connections that opened and
  left, so the log was 100 % errors, none of them this server's. `--verbose`
  was inert for the same reason — it logged one line about itself at a level
  nothing was listening to, and now raises the floor to `debug` instead.

  The default is `info`, and `RUST_LOG` still wins outright when set.

- 🌐 **A `uri` rewrite no longer loses the site name on HTTP/2.** Every `uri`
  rewrite replaces the request target with a path-only one, and HTTP/2 keeps
  the site name inside that target rather than in a `Host` header. So a route
  as ordinary as `uri strip_prefix /api` sent the origin a literal `Host:` with
  no value after it — an origin that routes by name served its default site, and
  one that validates the header rejected the request outright. The same route
  over HTTP/1.1 and HTTP/3 was unaffected, which is what kept it hidden.

  The site name is now written into a header before any middleware can reshape
  the URI, so the two places it can live cannot disagree. A request that already
  sends its own `Host` keeps it.

- 🏷️ **An HTTP/3 request now reaches the origin carrying the site name the
  client asked for.** It carried the upstream's own dial address instead, so an
  origin that routes by `Host` — another proxy, a PaaS router, any server with
  several virtual hosts behind one address — served the default site to every
  HTTP/3 request, while the identical request over HTTP/1.1 or HTTP/2 reached
  the right one. Applications that check the host against an allowlist rejected
  the request outright, and anything the origin built from `Host` (a redirect,
  a link in an email) came out pointing at the proxy's own upstream address.

  Nothing reported an error: the status stayed 200. An explicit
  `header_up Host …` still overrides this, and the name used for the TLS
  handshake is unchanged — those were one value here and they answer two
  different questions.

- 🌐 **`{host}` and the placeholders beside it now resolve over HTTP/2.** They
  read the `Host` header directly, and an HTTP/2 request does not have one —
  the site name arrives in `:authority` and stays in the URI. So `{host}`,
  `{hostport}`, `{port}` and `{labels.N}` all resolved to the empty string for
  the transport browsers use by default, while the identical request over
  HTTP/1.1 and HTTP/3 resolved them correctly.

  What that looked like in practice: `redir https://{host}/landing` answered
  `Location: https:///landing`, which no browser follows. Anything else built
  from the site name — a `respond` body, a `header` value, a `vars` entry, a
  `reverse_proxy` `header_up`, a log field — was empty the same way, and a
  matcher written against `{host}` simply stopped matching, with no error.

  `{uri}` was the same mistake seen from the other side: it rendered the whole
  URI, so over HTTP/2 it returned `https://example.com/p?q=1` where HTTP/1.1
  returned `/p?q=1`. It is now the request target on every protocol.


- 🗜️ **A `file_server` compressed bodies too small for compression to win, and
  the behaviour could not be turned off.** There was no size floor anywhere on
  that path, and every browser sends `Accept-Encoding`. Measured against the real
  binary: an 80-byte JSON came back with `Content-Encoding: gzip` and
  `Content-Length: 97` — **21% larger than the file**, having spent CPU to get
  there. Below the size where compression can win, it loses on both axes at once.

  There is now a 512-byte floor, matching the `minimum_length` of the `encode`
  directive that does this job upstream, and the decision goes through the same
  predicate as the streaming choice so a body cannot be judged compressible by one
  and not the other.

  `file_server` also gained a `compress` subdirective, because the adapter
  hardcoded it on and offered no way to say no — reaching `compress: false` meant
  writing the configuration in JSON. That is how this survived a whole performance
  campaign unnoticed: the benchmark configuration was JSON and set it false, and
  the load generators send no `Accept-Encoding`, so nothing measured what every
  browser actually gets.

  📌 The **default is unchanged**. Upstream's `file_server` compresses nothing at
  all — that is the separate `encode` directive — so flipping ours to off is a
  compatibility decision to take with the parity goal in view, not a bug fix to
  smuggle in beside one.


- 🔑 **A certificate and a private key that did not belong together passed
  validation.** `tls site.crt other.key` was accepted: the check proved the
  certificate PEM parsed, the key PEM parsed, and the key's type was supported,
  and stopped there. The reload reported success and every handshake for that site
  failed afterwards, with an error nowhere near the configuration that caused it.
  Validation now compares the certificate's SubjectPublicKeyInfo against the
  public key derived from the private one, so a pair that cannot serve a single
  request is refused where the operator can still act on it. Found by review.


- 📡 **A wildcard site configured for DNS-01 silently used HTTP-01.** The
  challenge override was an exact map lookup keyed by the configured name, and
  its comment justified that with "the identifier the certificate is ordered
  under". That premise was false: a `*.example.com` site orders a certificate for
  each concrete name it is asked for, so the order is for `a.example.com` and the
  lookup missed `*.example.com` entirely.

  The failure was silent, and sometimes it even worked — HTTP-01 for a concrete
  subdomain succeeds wherever port 80 is reachable, so an operator who explicitly
  configured DNS-01 got a different challenge and no signal. Where port 80 was not
  reachable they got a renewal error that never mentions the option they set,
  which is word for word the failure the comment above that configuration code
  already warned about.

  The override now matches a wildcard against the concrete names it covers, by
  one label, with an exact entry still winning. The rule is shared with the
  certificate lookup that already had it right — it existed twice, and the copy
  here was the one that was wrong. Found by review.


- 📦 **`storage-export` followed by `storage-import` restored the store one level
  below itself, and reported success.** Export wrote every entry under a
  `pingclair/` directory; import unpacked straight into the store root. So a round
  trip produced `<store>/pingclair/internal/root.key`, and the server looks in
  `<store>/internal`. The restore printed `✅ Store imported`, the next start found
  no internal CA and minted a fresh one, and every client that trusted the old
  root stopped trusting this server — a disaster-recovery path that reports
  success and restores nothing.

  The archive root is now the store root, matching the command this one is
  modelled on. Import drops a single leading `pingclair/` when it sees one, so an
  archive produced by the older export still restores correctly, and a store a
  previous import nested is repaired the next time one runs.

  Import also checks each entry's path itself now: every component must be an
  ordinary name, which refuses `..`, absolute paths and drive prefixes. `tar`'s
  own `unpack` already refused parent traversal, but rewriting the path means
  unpacking entry by entry, which gives that check up — so the replacement is
  stated and tested rather than inherited. Found by review.


- 🚧 **`admin :2019` — the ordinary spelling, and the one this repository's own
  fixtures use — panicked at startup.** The Admin listener called
  `.parse().expect()` on its configured address, and `SocketAddr` cannot read a
  bare `:port`, which the data plane's own listeners accept and Pingora binds
  directly. In release, where the profile sets `panic = "abort"`, that turned a
  correct configuration into a dead process; in debug it killed only the Admin
  thread, so the server came up serving traffic with no Admin API and one panic
  line to explain it. The same `.expect()` did the same thing for a genuine typo.

  A bare port now resolves to every interface, exactly as it does elsewhere, and
  an address that cannot be bound is refused at load with a message naming it.
  Startup no longer panics even if one reaches it, because the check that would
  have caught it is not the same code as the bind. `admin off`, which compiles to
  a disabled block with an empty address it never binds, is unaffected.


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

- 🛡️ **A cached response skipped `header_down`.** The cache stores the
  origin's headers as they arrived, and `reverse_proxy { header_down … }` was
  applied only to a response coming from the origin. So the first visitor got
  the edited response, and every visitor after that got the cached one with the
  edits missing: a field the operator removed — an internal header, or a
  `Set-Cookie` meant for one person — went out to everyone the cache answered,
  and a field the operator added was absent. Found in a production-like soak
  run. A cache hit now gets exactly the edits the miss got. HTTP/3 has no
  response cache, so it was never affected. A `+` field also stops being added
  once more for every retried upstream attempt.

- ⏱️ **A request header sent slowly enough was never cut off.** A slowloris
  client opens a connection and sends its request header a byte at a time,
  never finishing; ten of them held their connections for over 120 s in a
  production-like soak run. With no `limits { header_timeout }` there was no
  timer at all, and a configured one did not help either: it timed each read on
  its own, so every byte that arrived started it again, and a byte a second
  stayed under a two-second limit forever. The timeout now covers the whole
  header, from the moment the connection is accepted (or the previous keepalive
  request ends) to its last byte, and it defaults to 60 s — Caddy's default
  for `read_header`, and nginx's for `client_header_timeout`. The same deadline
  bounds the HTTP/2 connection preface and the h2c check. A client that misses
  it is disconnected without a response.

  ⚠️ **Behaviour change:** because the deadline also runs while a keepalive
  connection waits for its next request, an idle HTTP/1 connection is now
  closed after 60 s; it used to stay open indefinitely. Set
  `limits { header_timeout … }` for a different bound.

- ⏱️ **A request body that never arrived was waited on forever.** A client
  could send `Content-Length: 999999999999` and then nothing. A `respond` route
  reads the announced body before it answers, and with no `body_timeout`,
  `idle_timeout` or `request_body { read_timeout }` that read had no deadline:
  no response came, and the connection was held for as long as the client
  liked. The old 1 MiB default body ceiling used to refuse this request on its
  header alone; since it went, nothing else stood in the way. A body may now
  pause at most 60 s between two reads when nothing configures it — nginx's
  `client_body_timeout` default — and a client that stops is answered `408`.
  A large upload over a slow link still finishes as long as it keeps moving.
  WebSockets and immediate-flush proxy routes are exempt, because their
  clients may be quiet on purpose; they keep whatever `long_connections` or
  the site's limits say, as before. Found while triaging the slow-header soak
  finding above.

- 🛡️ **A guard written with a matcher protects every route that answers its
  requests.** With routes chosen in directive order (#18), `basic_auth
  /secret { … }` beside `respond /secret "…"` let an unauthenticated client
  read the body: the guard does not answer by itself, the `respond` route
  matched first, and only the matched route ran. The same held for every
  middleware line written with a matcher — `forward_auth`, `request_header`,
  `header`, `request_body`, `rewrite`, `uri`, `try_files`, `rate_limit`,
  `cors`, `access_control`, `intercept`, and a `route` or `handle` block with
  nothing in it that answers — in front of a `respond`, `reverse_proxy`,
  `file_server`, `handle` or other answering sibling, and between two such
  lines matching one request (`header /admin/public …` sorted ahead of
  `basic_auth /admin/*` and ran alone). Each line is now copied, at load, in
  front of every answering route the directive order puts it ahead of, still
  checked against its matcher per request; `redir`, which the order puts
  ahead of `basic_auth`, still redirects unguarded, as upstream. This
  regression came with the directive-order routing work and **never shipped
  in a release**: `0.2.0-rc.3` chose routes by path and answers 401.

- 🛡️ **`forward_auth` without a matcher runs before the site's `respond`.**
  It ranked as `reverse_proxy`, which it compiles to, so in a site with
  `forward_auth` and `respond` the `respond` answered first and the gateway
  was never asked. It now ranks as `forward_auth`, right after `basic_auth`.
  The same ordering put it after `respond` inside a `handle` block. **This
  one shipped** in `0.2.0-rc.1` through `0.2.0-rc.3`: `0.2.0-rc.3` serves a
  site of `forward_auth <gateway>` and `respond "…"` without contacting the
  gateway. A `reverse_proxy` written above it shared its rank and could
  answer first too. **Upgrading:** `intercept` ranks after `forward_auth`, so
  it no longer sees the gateway's denial; to rewrite a denial, put
  `intercept`, `forward_auth` and the handler they guard in one `route`
  block, which keeps written order.

- ⏱️ **An HTTP/3 request header sent slowly enough was never cut off either.**
  The slow-header fix above covered HTTP/1 and HTTP/2. Over HTTP/3 a client
  could open a request stream and send its header block a byte at a time:
  the server sees nothing until the header is complete, and QUIC's idle timer
  starts again with every packet, so the stream and its connection stayed open
  for as long as the client kept trickling — up to a hundred such streams on
  one connection. Each request stream now has the same `header_timeout`
  (60 s by default) from the moment the client opens it, and one that misses
  it is reset with `H3_REQUEST_INCOMPLETE`. Only that stream ends; other
  requests on the same connection are not affected.

  ⚠️ **Behaviour change:** an HTTP/3 request whose header takes longer than
  `header_timeout` to arrive is reset; it used to be waited on indefinitely.

- ⏱️ **An HTTP/2 upload to an upstream or FastCGI that stopped halfway was
  waited on forever, even with `body_timeout` set.** The body-pause bound
  above reached HTTP/2 only for locally answered routes: the server's read
  timeout does nothing on an HTTP/2 stream, so a `reverse_proxy` or
  `php_fastcgi` request whose client sent part of its body and then went
  quiet held the stream, the upstream connection and, for FastCGI, a php-fpm
  worker for as long as it liked. The same pause — `request_body
  { read_timeout }`, else the shorter of `body_timeout` and `idle_timeout`,
  else 60 s — now applies there. A FastCGI request is answered `408`, as on
  HTTP/1; a proxied one has its stream reset with `CANCEL`, because the proxy
  loop that reads that body cannot be made to answer instead. Immediate-flush
  routes keep only a configured value, as on HTTP/1.

  ⚠️ **Behaviour change:** a client-streaming HTTP/2 request through
  `reverse_proxy` (a gRPC upload stream, for example) that sends nothing for
  a minute is now reset. Set `limits { body_timeout … }`, or
  `flush_interval -1` on the route, to allow longer silences.

- 🙈 **`hide` did not hide a file whose name is not valid UTF-8.** On Linux a
  filename is bytes, and the file server serves `secret\xE9.env` to a request
  for `/secret%E9.env`. The `hide` patterns were matched as text, and a name
  that was not text never matched any of them, so `hide *.env` hid
  `secret.env` and served `secret\xE9.env`. Patterns are now matched against
  the name's bytes, by the same matcher the `file` matcher's globs use: `*`
  and `?` take a byte that is not text, and a literal never matches one. No
  configuration change is needed.

- 🙈 **A `hide` pattern that could not be compiled hid nothing.** A pattern
  with a `[` set that never closes, such as `hide [secret`, was dropped with
  a warning and the server started anyway, serving the files the rule was
  written to keep private. It is now refused when the configuration loads,
  from a Pingclairfile and from JSON alike.

  ⚠️ **Behaviour change:** a configuration with such a pattern no longer
  starts. Close the set, or write `[[]` for a literal `[`.

- 🛡️ **A path guard could be skipped by escaping a reserved character.**
  With `basic_auth /secret!` in front of `file_server`, a request for
  `/secret%21` was served the file `secret!` without credentials, over every
  protocol. The server decodes only unreserved escapes (`%41`, `%7E`) in the
  path it routes and forwards, so the guard compared `/secret%21` and did not
  match, while the file server decoded `%21` to find the file. Route paths,
  `path` and `path_regexp` matchers now compare the path with every escape
  decoded once, as Caddy's `path` matcher does; the request that is forwarded
  upstream is unchanged.

  ⚠️ **Behaviour change:** a `path` pattern written with an escape, such as
  `/a%20b`, now has to be written decoded (`/a b`, quoted) to match.

- 🔒 **`rustls` moves to 0.23.45 for RUSTSEC-2026-0285.** Rustls accepted TLS
  1.3 handshake messages sent at the wrong encryption level when they followed a
  key-changing message in the same record — a plaintext `EncryptedExtensions`
  packed alongside the `ServerHello` was taken as valid, where RFC 8446 §5.1
  requires the connection be closed with an `unexpected_message` alert. The
  handshake transcript stays authenticated, so the practical effect is that a
  peer could send messages that should have been encrypted in the clear without
  being rejected, not that a handshake could be completed by an attacker. The
  bump also carries `rustls-webpki` 0.103.15 and `aws-lc-rs` 1.18.1, and cargo
  audit reports the tree clean.

- 💥 **A request path mixing a percent-escape with a non-ASCII character killed
  the process.** The URI normalizer copied unmatched input with a one-*byte* slice
  of a `str`, which panics when that byte falls inside a multi-byte character, and
  the release profile sets `panic = "abort"` — so this was not a bad request, it
  was the whole server. `/%4A¡` is enough, and any client can send it.

  Introduced by the percent-decoding change earlier in this release and caught by
  the property test that sits beside it, on a clean-Linux verification run, after
  the change had already been pushed. The randomised test had passed several times
  locally first; the input is now pinned as an ordinary test as well, so finding it
  again does not depend on a seed. The decoder advances by whole characters now.


- 🛡️ **The HTTP/3 request parser resolved ambiguous requests instead of refusing
  them.** A repeated pseudo-header overwrote the earlier copy, so the last one
  won; pseudo-headers interleaved with regular fields were accepted; an uppercase
  field name was taken as data; `:scheme` was matched and thrown away; and a
  `Host` contradicting `:authority` was silently outranked and then left in the
  field list for a handler to read. RFC 9114 §4.3.1 gives the same answer to all
  of them — the request is malformed — precisely so that no two implementations
  have to agree on which copy to believe. That disagreement is the ground request
  smuggling grows in.

  All five are now refused with 400, which is what an unparseable request already
  received. The `:scheme` rule is the one with teeth beyond framing: there is no
  cleartext HTTP/3, so a request claiming `http` was previously treated as secure
  by everything downstream of the parser.

  ⚠️ **This is stricter than before.** A client sending no `:scheme`, a duplicate
  pseudo-header, or an uppercase field name now gets 400 where it used to be
  served. Real HTTP/3 clients send none of those — verified against a curl built
  on ngtcp2, which still passes the full 27-check functional matrix — but a
  hand-written client that relied on the leniency will notice. Found by review.

- 🔐 **The Admin API key comparison was labelled constant-time and was not.** The
  comment above it said `Constant-time comparison`; the implementation was
  `.all()`, which short-circuits, so it returned as soon as two bytes differed and
  the time it took revealed how many leading bytes were correct. That is how a
  secret is recovered one byte at a time. The comment was the worst part — it told
  every later reader the property had been handled. It now goes through
  `subtle::ConstantTimeEq`, already in the dependency tree via `bcrypt`.

- 🗜️ **A site serving pre-compressed sidecars did not send `Vary:
  Accept-Encoding`.** The header was tied to the dynamic `compress` flag alone, so
  a site with `precompressed` and compression off returned two different bodies
  for one URL — one gzip, one not, chosen by `Accept-Encoding` — while telling
  caches nothing. A shared cache stores whichever it saw first and serves it to
  everyone, so a client that never asked for gzip receives a gzip body it cannot
  read. The header now follows either way a body can vary. Found by review.

- ☁️ **The DNS-01 client's response ceiling described a bound it did not enforce,
  and it had no deadline at all.** The 1 MiB limit was checked *after*
  `.collect()` had already buffered the whole body, under a comment saying it was
  bounded — so the amount of memory this process allocated was the DNS API's
  choice, not ours. That is the same shape as the two static-file bugs already
  fixed in this release, except the peer here is not even ours. The body is now
  read frame by frame against a running total.

  Nothing had a timeout, so an API that accepted the connection and then said
  nothing held a certificate order open forever. Each round trip now has a 30
  second budget covering connect, send and read together.

  🧹 A third defect in the same file: record cleanup removed its local bookkeeping
  *before* the remote delete, so a delete that failed orphaned the TXT record in
  DNS permanently — the next cleanup found no local entry, returned success, and
  the record stayed. A stale `_acme-challenge` record is not just litter; it
  remains standing evidence of control over that name long after the order it
  belonged to, and the operator cannot see it. The local entry is now dropped only
  once the remote copy is gone, so a failure leaves something for the next attempt
  to retry.

  📌 Deliberately not added: retry. The report suggested it, but record creation
  is not established as idempotent here, and a blind retry could publish duplicate
  TXT records for one challenge. That needs its own change. Found by review.

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

- 📡 **`hickory-resolver`, `hickory-proto` and `hickory-net` moved to 0.26.3.**
  0.26.1 had three published advisories: a truncated-response retry loop in
  the name-server pool with no bound, so an upstream DNS server that keeps
  answering truncated can spin the resolver; CNAME records unrelated to the
  query were followed; and the lookup APIs hid DNSSEC validation failures.
  The DNS-01 propagation check and the dynamic-upstream sources are the only
  callers, and neither turns on DNSSEC, so the first two are the ones that
  reached this server.

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

- 🗑️ **The rolling development build channel is gone.** `dev.yml` rebuilt Linux
  binaries, a `dev` GitHub release, and a `ghcr.io/.../pingclair:dev` image on
  every push to `main`, and `install.sh --dev` installed from it. It was a
  second prebuilt channel to keep verified, and `--main` already answers "give
  me what is on main right now" by compiling it. The workflow is deleted, the
  `--dev` flag with it, and the development-build section of the READMEs is
  removed rather than left describing artifacts nothing publishes. Nothing
  changes for release installs: the default path and `--main` are untouched.

- 🗑️ Two vendored performance forks (`pingora-core`, `pingora-http`, 38,532
  lines) were evaluated and removed. Both had a sound mechanism and neither
  ever produced a measurement from a run where the component it patched was
  the saturated resource.

[Unreleased]: https://github.com/dorianverlaine/pingclair/compare/v0.1.7...HEAD

### 🎨 `fmt` is a check, and its flags are Caddy's

`pingclair fmt` always exited 0, so it could not be used as the gate
`caddy fmt --overwrite && git diff --exit-code` is. It now exits 1 when the
input was not already formatted, keeps stdout as the preview, and still exits 0
for `--overwrite`, which rewrites the file as its job. `--config <path>` and
`-w` are accepted as Caddy's spellings of the positional path and `--overwrite`.
**The indent is now one tab per level rather than two spaces**, so a file
previously formatted by `pingclair fmt --overwrite` shows a whole-file diff the
next time — and, in the other direction, `caddy fmt` reports a file this
formats as clean.
