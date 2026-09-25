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

### ⚠️ Before you upgrade

Most configurations keep working unchanged. These are the changes most
likely to alter what an existing configuration does; each links to its entry
below, which ends with what to write instead.

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

The full list of breaking changes is under [Breaking](#️-breaking); the one
known defect that ships is under
[Known defect — WebSocket upgrades under load](#-known-defect--websocket-upgrades-under-load).

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
They used to render empty, on HTTP/3 as well as HTTP/1.1–2. `{remote_ip}`,
this project's own spelling, keeps meaning the verified client. A file or
`vars` matcher reads `{remote_host}` and `{client_ip}` the same way. FastCGI
`REMOTE_ADDR` was already the peer and stays so; in a `php_fastcgi` `env`
template, `{remote_ip}` is now the verified client as everywhere else, where
it used to be the peer.

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
before. The Admin API itself still answers `503` for the moment a reload is
publishing.

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
