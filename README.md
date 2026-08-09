<div align="center">

<img src="assets/logo.png" alt="Pingclair" width="520">

**A modern, high-performance web server and reverse proxy built on Pingora**  
*Cloudflare Pingora's raw performance, wrapped in Caddy's minimalist developer experience*

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.97%2B-orange.svg)](https://www.rust-lang.org/)
[![Status](https://img.shields.io/badge/status-active-green.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/dorianverlaine/pingclair/pulls)

**English** · [中文](README.zh.md) · [Français](README.fr.md)

</div>

---

## 📖 Overview

**Pingclair** is a next-generation web server and reverse proxy. Its core idea is to take the power of **Cloudflare Pingora** — the Rust proxy framework that serves trillions of requests — and wrap it in a shell as approachable as **Caddy**.

Nginx configuration is notoriously cryptic, while Caddy is pleasant to use but built on Go. Pingclair aims to fill that gap: **100% Rust**, **memory-safe**, **fast**, and **intuitive to configure**.

Whether you need a simple static file server or an enterprise gateway with load balancing, automatic HTTPS, and HTTP/3, Pingclair handles it.

## ✨ Features

*   🚀 **Powered by Pingora** — Standing on the shoulders of giants, backed by Cloudflare's battle-tested infrastructure for enterprise-grade stability and throughput. Plaintext listeners accept HTTP/1.1 and prior-knowledge h2c; TLS listeners negotiate HTTP/2 through ALPN.
*   🔒 **Memory safe** — Rust eliminates buffer overflows and the rest of the classic memory-safety vulnerability class.
*   📝 **Caddyfile-compatible config** — A minimal configuration DSL with **automatic HTTPS**, **multiple listeners**, and **named matchers**, compatible with mainstream Caddyfile syntax.
*   ⚡ **Native HTTP/3 (QUIC)** — Built on [quiche](https://github.com/cloudflare/quiche), the production QUIC stack that powers Cloudflare's edge. Lower latency and better connection migration on unreliable networks. Explicit `tls` configuration enables HTTPS and H3 on any listen port; 443 and 8443 remain automatic conventions. Declared request trailers are not forwarded on any downstream protocol: Pingclair returns `501` before response commitment or resets an already committed H3 stream. Upstream responses advertising trailers return `502` until end-to-end trailer forwarding is supported. H3 CONNECT and extended CONNECT return `501` until tunnel support is implemented.
*   🔄 **Smart load balancing** — Several built-in algorithms (round-robin, least-connections, and more) with health checks and automatic failover.
*   🔐 **Automatic and private HTTPS** — Built-in ACME (Let's Encrypt) support issues public certificates, while `tls internal` provides a persistent local CA for private origins and tunnels.
*   📁 **Fast static file serving** — Gzip/Brotli compression, range requests, and efficient file transfer.
*   📊 **Observability** — Prometheus metrics export and OpenTelemetry tracing out of the box.

## ⚡ Benchmarks

Latest comparison: Pingclair HEAD `43ec589` vs nginx 1.31.3, measured on
three `c7i-flex.large` instances (2 vCPU each, non-burstable) in AWS
`us-west-2a`, with the reverse-proxy backend on a dedicated host. 1 KiB
file; H1 via `wrk -t2 -c100`, H2/H1S via `h2load -t2 -c50`; all recorded
rounds had zero failures.

| Scenario | Pingclair | nginx 1.31.3 |
| --- | ---: | ---: |
| H1 static | 84,208 | 105,588 |
| H2 static (50×10) | 74,587 | 94,712 |
| H1S static | 70,004 | 55,304 |
| H1 reverse proxy | 38,938 | 85,744 |
| H2 reverse proxy (50×10) | 33,516 | 45,872 |
| H1S reverse proxy | 34,418 | 55,894 |

Pingclair leads on H1S static (+27 %). Static H1/H2 trail about 20 %;
reverse-proxy H1/H1S remain the largest gaps, with H2 proxy trailing about
27 %. Raw per-run evidence is kept locally under
`benchmarks/results/20260803_c7iflex_nocase/` and is not part of the
repository.

## 📦 Installation

### Prerequisites

*   **Rust toolchain** — Rust 1.97 or newer.

### Build from source

Building from source is recommended, since it produces a binary tuned for your CPU:

```bash
# 1. Clone the repository
git clone https://github.com/dorianverlaine/pingclair.git
cd pingclair

# 2. Build and install (release mode)
cargo install --path ./pingclair
```

Once installed, the `pingclair` command is available on your `PATH`.

### One-line install on Linux

On any Linux distribution the install script works — it downloads (or builds) the binary, sets up a `systemd` service, and creates an unprivileged `pingclair` user that binds low ports via `setcap`. After installation, manage the service with the `pc` command (short for `pingclair`).

```bash
curl -fsSL https://raw.githubusercontent.com/dorianverlaine/pingclair/main/scripts/install.sh | sudo bash
```

The script accepts two flags for tracking `main` instead of the stable release:

Install the latest development build of main (prebuilt binary):

```bash
curl -fsSL https://raw.githubusercontent.com/dorianverlaine/pingclair/main/scripts/install.sh | sudo bash -s -- --dev
```

Clone main and compile it locally (requires Rust 1.97+):

```bash
curl -fsSL https://raw.githubusercontent.com/dorianverlaine/pingclair/main/scripts/install.sh | sudo bash -s -- --main
```

### Development builds (unstable)

While Pingclair is in rapid iteration, every push to `main` also publishes
snapshots for deployment testing — **not** stable releases:

- **Container image** on GHCR: `dev` follows the latest push, and each build
  is also tagged with its full commit SHA so a specific snapshot can be pinned.

  ```bash
  docker pull ghcr.io/dorianverlaine/pingclair:dev
  docker run --rm -p 8080:80 \
    -v "$PWD/Pingclairfile:/etc/pingclair/Pingclairfile:ro" \
    ghcr.io/dorianverlaine/pingclair:dev
  ```

- **Linux binaries** (x86_64 and aarch64): attached to the corresponding
  GitHub Actions run and kept for 14 days; download them from that run's
  artifact list.

Treat every development build as a snapshot of a moving tree — verify it
before deploying anywhere that matters.

### Production deployment with Docker Compose

For a production-style container deployment, run the config-file mode and
keep the TLS store on a persistent volume (it holds certificates, ACME
account keys, and the internal CA — deleting it means re-issuing everything):

```yaml
services:
  pingclair:
    image: ghcr.io/dorianverlaine/pingclair:dev
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
      - "443:443/udp"   # HTTP/3
    volumes:
      - ./conf:/etc/pingclair:ro
      - ./site:/srv
      - pingclair_tls:/var/lib/pingclair/certs
    command: ["pingclair", "run", "/etc/pingclair/Pingclairfile"]

volumes:
  pingclair_tls:
```

Place your `Pingclairfile` in `./conf/`, static files under `./site/`, and
reference them with `root /srv` in the config. The container runs Pingclair
with the configuration file, so HTTPS, automatic port-80 redirects and
HTTP/3 all behave exactly like a host deployment.

### Trusting `tls internal` roots

`tls internal` signs leaves with a persistent local CA. Clients that verify
certificates must trust its root, published at
`$PINGCLAIR_TLS_STORE/internal/root.crt` (inside a container:
`docker compose cp pingclair:/var/lib/pingclair/certs/internal/root.crt
./root.crt`). Install it into the system trust store:

- Linux: copy to `/usr/local/share/ca-certificates/root.crt` and run
  `sudo update-ca-certificates`.
- macOS: `sudo security add-trusted-cert -d -r trustRoot -k
  /Library/Keychains/System.keychain root.crt`.
- Browsers that keep their own trust store (Firefox, Chrome on some
  platforms) need the root imported manually under Authorities.

Only do this for origins you control; the internal CA is not a public
authority.

## 🏃 Quick start

Pingclair runs in two modes: **CLI mode** for quick tests, and **config-file mode** for production.

### 1. CLI mode

**Serve static files**  
Serve the current directory over HTTP on port 8080:
```bash
pingclair file-server --listen :8080 --root .
```

**Run a reverse proxy**  
Forward traffic from local port 8080 to a backend on port 3000:
```bash
pingclair reverse-proxy --from :8080 --to localhost:3000
```

**Manage the system service (Linux)**  
After installation, the built-in commands manage the `systemd` unit:
```bash
pc service start    # start
pc service stop     # stop
pc service status   # status
pc service reload   # graceful config reload (SIGHUP)
pc service restart  # restart
```

### 2. Config-file mode (recommended)

Create a file named `Pingclairfile` in your project root, then run:

```bash
pingclair run Pingclairfile
```

## 🛠️ Configuration (Pingclairfile)

The Pingclair DSL is a structured configuration language purpose-built for describing server behavior. Like Caddy's `Caddyfile`, its conventional filename is `Pingclairfile`.

### Basic structure

The simplest configuration is one or more site blocks:

```caddyfile
# A server listening on localhost
localhost:8080 {
    # Static file serving
    file_server ./public
}
```

### Automatic HTTPS for public names

`tls auto` obtains and renews a public certificate over ACME (Let's Encrypt).
No `listen` is needed:

```caddyfile
{
    email admin@example.com
}

example.com {
    tls auto
    reverse_proxy app:8080
}
```

That is the whole configuration. A site with TLS and no `listen` serves HTTPS on
443, and Pingclair provisions a second, plaintext listener on port 80 that does
two jobs: it answers the ACME HTTP-01 challenge, which the CA fetches over
**cleartext** HTTP on that exact port (RFC 8555 §8.3), and it redirects every
other request to HTTPS with a 308. Port 80 therefore stays unencrypted even
inside a block that configures TLS — a TLS listener there would reject the CA's
plaintext probe and no certificate could ever be issued.

Control it from the global block:

| `auto_https` | Effect |
| --- | --- |
| `on` (default) | Provision port 80, answer ACME challenges, redirect to HTTPS. |
| `disable_redirects` | Provision port 80 and answer ACME challenges, but do not redirect. |
| `off` | Provision nothing; certificate management is disabled too. |

Writing your own `listen :80` in the block opts out of the automatic listener —
Pingclair then serves that port exactly as configured. If port 80 cannot be
bound (already in use, or unprivileged), the automatic listener is skipped with
a warning and HTTPS still serves; ACME HTTP-01 validation will not work.

The certificate Pingclair installs includes the intermediates the CA issued with
it. A server that sends only its leaf certificate appears to work in a browser —
browsers cache intermediates and fetch missing ones over AIA — while `curl`, Go,
and Java reject it outright.

To redirect by hand, `redir` expands `{host}` and `{uri}`. Quote the target so
the `{` is not read as the start of a block:

```caddyfile
http://example.com {
    redir "https://{host}{uri}" 308
}
```

### Internal TLS for private origins

Use `tls internal` when the TLS client is a trusted tunnel, load balancer, or
private service and public ACME validation is unavailable:

```caddyfile
https://origin.example.test:6688 {
    tls internal
    reverse_proxy app:8080
}
```

Pingclair persists one ten-year local authority and renewable 90-day leaf
certificates below `PINGCLAIR_TLS_STORE` — a bare binary defaults to
`$XDG_DATA_HOME/pingclair` (`~/.local/share/pingclair`), the container image
to `/var/lib/pingclair/certs`. Install
`$PINGCLAIR_TLS_STORE/internal/root.crt` in clients that verify the origin;
the authority private key remains in the owner-only `authority.json`.
H1/H2 and H3 use the same persisted leaf. `tls internal` requires a concrete
site name and cannot be combined with `tls auto`, ACME email, or manual
certificate paths.

The global `local_certs` option applies the same choice to every site that
has no certificate management of its own: all default automation uses the
persisted local authority instead of public ACME.

When Pingclair is behind a load balancer or CDN that you operate, list only
those proxy networks in the global block. Untrusted peers cannot supply
`X-Forwarded-For`, `X-Real-IP`, or `X-Forwarded-Proto` identity:

```caddyfile
{
    trusted_proxies 10.0.0.0/8 2001:db8::/32
}

example.com {
    listen :8443 proxy_protocol
    reverse_proxy app:8080
}
```

The verified client IP is shared by access control, rate limiting, IP-hash
load balancing, upstream forwarding, placeholders, and access logs. Changes
to `trusted_proxies` currently require a restart. `listen … proxy_protocol`
requires PROXY v1 or v2 on that listener and rejects transport peers outside
`trusted_proxies` before TLS or HTTP parsing. It is per-listener, as in nginx,
so a port behind an L4 balancer and a port reached directly can coexist in one
server. XFF and RFC 7239 `Forwarded`
chains are bounded; malformed or conflicting identities fail closed. PROXY
protocol does not apply to the UDP HTTP/3 listener.

### Resource limits and timeouts

Set downstream limits at site scope and upstream timeout phases inside
`reverse_proxy`. Durations require a unit. Long-connection overrides apply to
WebSocket upgrades, `flush_interval -1`, and `text/event-stream`; `off`
explicitly removes that long-connection deadline.

```caddyfile
example.com {
    limits {
        header_timeout 5s
        body_timeout 30s
        idle_timeout 30s
        request_timeout 2m
        max_headers 100
        max_header_bytes 65536
        max_connections 10000
        upload_bytes_per_sec 10485760
        download_bytes_per_sec 52428800
        long_connections {
            idle_timeout 5m
            request_timeout off
        }
    }

    reverse_proxy app:8080 {
        retry {
            max_attempts 4
            total_timeout 2s
            backoff 50ms
            status_codes 429 502 503 504
            methods GET HEAD
        }
        overload {
            max_in_flight 256
            max_pending 64
            pending_timeout 250ms
            upstream_max_connections 64
        }
        circuit_breaker {
            consecutive_failures 5
            error_rate_percent 50
            minimum_requests 20
            window_requests 100
            open_for 30s
            half_open_requests 1
            failure_statuses 429 502 503 504
        }
        transport http {
            connect_timeout 3s
            first_byte_timeout 30s
            between_reads_timeout 15s
        }
    }
}
```

`max_attempts` includes the initial attempt. Connect failures remain safe to
retry because no request bytes reached that peer. Status retries require a
configured idempotent method and an actually bodyless request; Pingclair never
buffers or replays a request body for this policy. Omitting `retry` preserves
the legacy connect-failover limit and does not retry response statuses.

`max_in_flight` bounds work executing inside the route, while `max_pending`
adds a bounded wait queue. A full queue fails fast with 429 and an expired
pending wait returns 503. `upstream_max_connections` is a conservative
per-backend request-occupancy cap; it also bounds multiplexed H2 use rather
than attempting to count physical sockets. Circuit breakers track each
concrete backend independently. They open on either configured threshold,
fail fast with 503, and admit only the configured number of half-open probes
after `open_for`. An empty `failure_statuses` list counts every 5xx response.
Compatible Admin/SIGHUP reloads retain live circuit state; changing the
protection policy or configured upstream set starts fresh state.

Exceeded header, body, and request budgets receive an explicit HTTP error when
the protocol can still send one; idle transports and excess HTTP/2 or HTTP/3
connections are closed. Pingora 0.8 exposes one upstream read timer for H1/H2,
so the stricter of `first_byte_timeout` and `between_reads_timeout` governs
both phases there. The H3 bridge switches timers after receiving the response
header. Changing the H1/H2 pre-routing `header_timeout`, H2 field-section cap,
or H1/H2 connection limit currently requires a listener restart.

### Routing and matching

Pingclair has a powerful matcher system — route requests by path, host, headers, and more.

```caddyfile
example.com {
    # 1. A named matcher for API paths
    @api {
        path /api/v1/*
    }

    # Logic for API requests
    handle @api {
        header {
            set Content-Type "application/json"
        }
        reverse_proxy localhost:3000
    }

    # 2. Match static assets
    handle /assets/* {
        header {
            set Cache-Control "public, max-age=86400"
        }
        file_server ./assets
    }

    # 3. Fallback
    handle {
        respond "Page Not Found" 404
    }
}
```

### Advanced: macros

Macros are one of Pingclair's most powerful features. Define a macro to encapsulate a repeated configuration fragment, then reuse it across servers and routes to keep configuration DRY.

```rust
// A macro that adds security headers
macro security_headers!() {
    headers {
        remove: ["Server", "X-Powered-By"];
        set: {
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000",
        };
    }
}

// A shared logging macro
macro standard_log!(path) {
    log {
        output: File(path);
        format: Json;
        level: Info;
    }
}

server "blog.example.com" {
    listen: "0.0.0.0:443";

    // Use the macros
    use security_headers!();
    use standard_log!("/var/log/pingclair/blog.log");

    route {
        _ => { file_server "./blog"; }
    }
}

server "shop.example.com" {
    listen: "0.0.0.0:443";

    // Reuse the same security configuration
    use security_headers!();
    use standard_log!("/var/log/pingclair/shop.log");

    route {
        _ => { proxy "http://shop-backend:8000"; }
    }
}
```

### Reverse proxy and load balancing

```caddyfile
:80 :8080 {
    reverse_proxy {
        lb_policy least_conn
        to 10.0.0.1:8080 { weight 3 }
        to 10.0.0.2:8080
        # 🛟 Used only when every primary is unavailable.
        to 10.0.0.3:8080 { backup }
        health_check {
            path /health
            interval 5s
            timeout 2s
            status 200 204
            consecutive_failure 3
            consecutive_success 2
            max_response_body_bytes 65536
            slow_start 30s
        }
    }
}
```

Active checks run out of band, so an idle failed backend leaves rotation before
a user request reaches it and rejoins after the configured successful probes.
Checks support a custom method, Host, headers, status set, bounded body match,
health port, connection reuse, thresholds, and slow-start. HTTPS checks reuse
the route's pinned CA, client certificate, SNI, and protocol policy.

### Exact local rate limiting

```caddyfile
api.example.com {
    @api path /api/*
    route @api {
        rate_limit 100 60s {
            burst 20
            key tenant X-Tenant-ID
        }
        reverse_proxy app:8080
    }
}
```

The token bucket reports exact `RateLimit-Limit`, `RateLimit-Remaining`, and
`RateLimit-Reset` response fields, with `Retry-After` on a rejected request.
Use `dry_run` in the block to count and report without returning 429. Keys may
be `ip`, `global`, `route`, `api_key`, `header <name>`, or `tenant [name]`.
This limiter is process-local; Redis-backed distributed limiting is outside
v0.2.

The upstream scheme selects the connection protocol: a bare address or `http://`
uses HTTP/1.1, `https://` negotiates HTTP/2 with HTTP/1.1 fallback through ALPN,
`h2c://` requires prior-knowledge plaintext HTTP/2, and `h2://` requires HTTP/2
over TLS. Use `h2c://` or `h2://` for native gRPC so response trailers remain
end-to-end metadata.

A Unix-socket upstream is written `unix//path/to.sock` and dials that socket;
`unix+h2c//path/to.sock` speaks prior-knowledge HTTP/2 over it. Unix upstreams
are never handed to the DNS refresher.

Upstreams can also be discovered from DNS while the server runs:
`dynamic a name port` resolves every address record of `name`, and
`dynamic srv _svc._tcp.example.com` resolves SRV records whose targets carry
their own ports. Lookups happen on a background refresher, never on the
request path. A dial may also contain request placeholders —
`reverse_proxy {re.dial.1}` — expanded per request and cached by host and port.

Retry policy accepts Caddy's `lb_retry_match` spellings: `method`, `path`,
`header`, and CEL expressions. Method, path, and status-code expressions are
evaluated at runtime; expressions the runtime cannot evaluate are kept in the
compiled configuration and logged at startup. `lb_policy weighted_round_robin`
carries one weight per upstream, and a reverse_proxy `method`/`rewrite` block
changes the upstream request before it is sent.

Upstreams written as hostnames are re-resolved while the server runs, so a
container that restarts on a new address is picked up without a reload. A
lookup that fails leaves the previous address in rotation — a resolver outage
should not take the site down — and a name that does not resolve at startup
joins the pool as soon as it does, which lets the proxy start before its app.
IP literals never reach a resolver at all.

```caddyfile
{
    # Default 30s. `dns_refresh off` pins every upstream to the address it
    # had at startup. A unit is required: `30` is not `30s`.
    dns_refresh 15s
}
```

### Single-page applications: `try_files`

`try_files` rewrites the request to the first candidate that exists under the
site `root`, and serves nothing itself — the `file_server` after it does that.
The standard single-page-application pattern works as written:

```caddyfile
example.com {
    root * /srv
    encode gzip
    try_files {path} /index.html
    file_server
}
```

A request for a real file gets that file; anything else is rewritten to
`/index.html` so the application can route it. The query string survives the
rewrite.

A candidate ending in `/` matches only a directory, and one without matches
only a regular file — the trailing slash that decides is the one in the
configuration, not the one the request arrived with.

Four differences from Caddy, all of which **fail closed** with a message
naming the reason rather than compiling into something subtly different:

| Not supported | Why |
| --- | --- |
| Placeholders other than `{path}` | Only `{path}` is expanded; anything else would be looked up as a literal directory name. |
| A candidate with a query string (`/index.php?{query}`) | The query would be dropped silently. |
| Glob characters in a candidate | Caddy expands globs; Pingclair matches literally. |
| The `{ policy … }` block | Only first-match is implemented. |
| A `..` segment in a candidate | Confinement is lexical, so a candidate that could leave the root is refused outright. |

`try_files {path} {path}/ /index.html` works too: the second candidate matches
a directory, so a request for `/docs` finds `/docs/` and the file server takes
it from there.

### Path surgery: `uri`

```caddyfile
example.com {
    uri strip_prefix /api
    uri strip_suffix .php
    uri path_regexp /{2,} /
    reverse_proxy 127.0.0.1:3000
}
```

`uri replace` and `uri query` are **refused by name**. `replace` substitutes a
substring of the path in Caddy, while Pingclair's rewrite replaces the whole
path; accepting it would compile and serve a different URL than the one
written, so it errors instead. Query-string rewriting does not exist here yet.

### Caddy parity controls

```caddyfile
example.com {
    error_page 404 /srv/errors/404.html

    @legacy path /legacy/*
    redir @legacy https://example.com/new permanent

    handle /api/* {
        cors https://app.example.com {
            methods GET POST
            allow_credentials
        }
        access_control {
            allow_ip 10.0.0.0/8
            deny_user_agent "(?i)bot"
        }
        # Regex captures use $1, $2, ... and preserve query strings.
        rewrite "^/api/(.*)$" "/v1/$1"
        reverse_proxy 127.0.0.1:3000
    }
}
```

### Snippets and imports

A snippet is a reusable fragment `(name) { … }` pulled in with `import name`.
An import can hand the snippet a block, which is spliced where the snippet
writes `{block}`; named sub-blocks are addressed as `{blocks.<key>}`:

```caddyfile
(site) {
    https://{args[0]} {
        {block}
    }
}

import site test.domain {
    reverse_proxy 127.0.0.1:3000 {
        header_up Host {host}
    }
}
```

A placeholder fed nothing splices nothing, so a snippet written with `{block}`
still compiles when a call supplies no block. A placeholder inside an argument
list is refused: Caddy's token layer re-parses the line after splicing, while
the directive tree cannot, so Pingclair says so instead of guessing. Snippet
definitions in an imported file are visible to imports that come later.

### Logging grammar

`log <name> { … }` follows Caddy: the block configures a **named per-site
logger**, and the name is its handle. `log <name>` without a block still
references a global channel declared in the global options, and a bare `log`
enables the site's default access sink. Log blocks accept `hostnames`,
`include`/`exclude` (global), `sampling`, and the file rotation options
(`mode`, `dir_mode`, `roll_*`); `log_skip` excludes matching requests from
access logging.

### What is not supported yet

Pingclair calls itself Caddyfile-compatible, so the honest half of that claim
is saying where it stops. Every name below is **recognised**: writing one is
refused with a message saying the feature is missing, never mistaken for a
typo and never quietly ignored. A configuration using them does not start.

Directives:

  `abort` `acme_server` `copy_response` `copy_response_headers` `forward_auth`
  `fs` `intercept` `invoke` `log_append` `log_name`
  `map` `method` `metrics` `php_fastcgi` `push`
  `request_body` `request_header` `skip_log` `tracing`

Global options:

  `acme_ca` `acme_ca_root` `acme_dns` `acme_eab` `cert_issuer` `cert_lifetime`
  `default_bind` `default_sni` `dns` `ech` `events` `fallback_sni`
  `filesystem` `frankenphp` `key_type` `ocsp_interval` `ocsp_stapling`
  `on_demand_tls` `pki` `preferred_chains` `renew_interval` `renewal_window_ratio`
  `shutdown_delay` `skip_install_trust` `storage` `storage_clean_interval`

Three consequences worth stating plainly, because they decide whether
Pingclair fits at all rather than being details you discover later:

- **No DNS-01 challenge** (`acme_dns`, `tls { dns … }`), so **no wildcard
  certificates**, and no issuance on a host where port 80 is unreachable.
- **No PHP** (`php_fastcgi`) and **no forward authentication**
  (`forward_auth`).
- **Certificates and state are stored on local disk only** (`storage`), so
  several instances cannot share one certificate store.

`handle_errors` deserves its own line: the type exists in this codebase and
does nothing, so it is refused rather than accepted. A custom error page comes
from `error_page`, which is a Pingclair directive rather than a Caddy one.

> 🔁 A test fails if the parser refuses a name this file never mentions, so
> the list cannot quietly fall behind the table the parser consults. A README
> that claims support the binary does not have is worse than one that claims
> less.

## 🏗️ Architecture

Pingclair is organized as a modular Cargo workspace:

| Crate | Description |
|-------|-------------|
| **`pingclair`** | **CLI entry point.** Parses arguments, initializes logging, bootstraps the system. |
| **`pingclair-core`** | **Core runtime.** Core data structures, traits, and server lifecycle management. |
| **`pingclair-config`** | **Configuration compiler.** Lexes, parses, and semantically checks the `Pingclairfile`, producing runtime config objects. |
| **`pingclair-proxy`** | **Proxy implementation.** HTTP/TCP proxy logic built on Pingora's proxy trait, including the load balancer, plus the HTTP/3 (QUIC) listener built on Cloudflare's quiche. |
| **`pingclair-static`** | **Static file serving.** Efficient file reads, MIME type inference, and streaming. |
| **`pingclair-tls`** | **TLS management.** Manual certificates, persistent internal CA issuance, and automatic ACME issuance (Let's Encrypt). |
| **`pingclair-api`** | **Admin API.** A RESTful interface for inspecting state and hot-reloading configuration at runtime. |
| **`pingclair-plugin`** | 🚧 **Stub — not usable.** A skeleton for a future plugin interface, with no callers anywhere in the workspace. A configuration naming a `plugin` handler is **rejected**, rather than accepted and silently ignored. Planned for v0.3. |

## 🤝 Contributing

Contributions are very welcome — whether you're fixing a bug, adding a feature, or just improving the docs.

Read **[CONTRIBUTING.md](CONTRIBUTING.md)** first. It covers the four-command gate every commit has to pass, what counts as adequately tested for a web server, and the architecture constraints that are not obvious from the code (BoringSSL linking, the HTTP/3 path, bounded memory).

What changed between releases — and what is on `main` but not released yet — is in **[CHANGELOG.md](CHANGELOG.md)**.

First-time contributors sign a one-time [CLA](CLA.md). You keep the copyright to your work.

## 📄 License

Licensed under the **Apache License 2.0**. See [LICENSE](LICENSE) for the full terms and [NOTICE](NOTICE) for attribution requirements and third-party components.

---

<div align="center">
  <sub>Built with ❤️ and Rust</sub>
</div>
