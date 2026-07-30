<div align="center">

<img src="assets/logo.png" alt="Pingclair" width="520">

**A modern, high-performance web server and reverse proxy built on Pingora**  
*Cloudflare Pingora's raw performance, wrapped in Caddy's minimalist developer experience*

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.88%2B-orange.svg)](https://www.rust-lang.org/)
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

Full methodology, raw results, and — importantly — the bugs this process
found and fixed live in [`benchmarks/README.md`](benchmarks/README.md).
Read the full writeup before drawing conclusions.

**Test environment**: bare-metal VPS (Aliyun, 2 vCPU / 1.6GB, Ubuntu
24.04), each server on `127.0.0.1:8080` in turn, `wrk -t2 -d15s` over
loopback (`results/20260725_vps_onbox/`).

| Scenario | Pingclair | Nginx | Caddy |
|----------|-----------|-------|-------|
| Static 1KB, plain (c100) | 50,145 req/s | **53,579 req/s** | 17,337 req/s |
| Static 1KB, gzip (c100) | **42,982 req/s** | 42,510 req/s | 15,302 req/s |
| Reverse proxy (c100) | 20,154 req/s | **21,961 req/s** | 9,870 req/s |
| Large 20MB, gzip (c20) | **703 req/s, 0 timeouts** | 9.1 req/s, 110 timeouts | 10.1 req/s, 65 timeouts |

**How to read this**

- Small-file static is now essentially tied with nginx (94% plain, 101%
  gzip) and ~2.9x Caddy. This was not always so: earlier runs showed a
  ~2.9x gap to nginx, root-caused to `tokio::fs` — every `tokio::fs`
  call is a `spawn_blocking` cross-thread round-trip, so each request
  paid ~8 futex wake/waits. The static hot path now uses synchronous
  `std::fs` (the nginx model: local file reads don't meaningfully
  block), which took futex from 8/request to ~0 and throughput from
  18.7k to 50k req/s. Full story in `benchmarks/README.md`.
- Reverse proxying is ~92% of nginx and ~2x Caddy, with zero errors on
  all three.
- Large compressible bodies are the compressed-body cache's home turf:
  pingclair serves ~70x nginx/caddy's throughput with **0 timeouts**
  because repeat hits skip compression entirely, while nginx and caddy
  re-compress the 20MB file on every request. The cache costs memory by
  design (74 MiB peak RSS vs nginx's 21 MiB — a bounded 64MB budget).
- Compression levels aren't perfectly matched across engines (nginx
  `gzip_comp_level 1` vs defaults elsewhere), so gzip comparisons are
  informative, not exact.

An earlier Docker-bridge run (2 vCPU / 512MB containers, Apple M2) with
the full matrix and the complete list of **20 bugs found and fixed
through benchmarking** — including a static-compression bug that turned
a 20-second test into 16 minutes — is documented in
[`benchmarks/README.md`](benchmarks/README.md).

## 📦 Installation

### Prerequisites

*   **Rust toolchain** — Rust 1.88 or newer.

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

### One-line install on Ubuntu/Debian (recommended)

On Ubuntu or Debian you can use the install script. It downloads (or builds) the binary, sets up a `systemd` service, and creates an unprivileged `pingclair` user that binds low ports via `setcap`.

```bash
curl -fsSL https://raw.githubusercontent.com/dorianverlaine/pingclair/main/scripts/install.sh | sudo bash
```

After installation, manage the service with the `pc` command (short for `pingclair`).

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
certificates below `PINGCLAIR_TLS_STORE` (default:
`/var/lib/pingclair/certs`). Install
`$PINGCLAIR_TLS_STORE/internal/root.crt` in clients that verify the origin;
the authority private key remains in the owner-only `authority.json`.
H1/H2 and H3 use the same persisted leaf. `tls internal` requires a concrete
site name and cannot be combined with `tls auto`, ACME email, or manual
certificate paths.

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
| **`pingclair-plugin`** | **Plugin system.** The plugin interface for third-party extensions. |

## 🤝 Contributing

Contributions are very welcome — whether you're fixing a bug, adding a feature, or just improving the docs.

Read **[CONTRIBUTING.md](CONTRIBUTING.md)** first. It covers the four-command gate every commit has to pass, what counts as adequately tested for a web server, and the architecture constraints that are not obvious from the code (BoringSSL linking, the HTTP/3 path, bounded memory).

First-time contributors sign a one-time [CLA](CLA.md). You keep the copyright to your work.

## 📄 License

Licensed under the **Apache License 2.0**. See [LICENSE](LICENSE) for the full terms and [NOTICE](NOTICE) for attribution requirements and third-party components.

---

<div align="center">
  <sub>Built with ❤️ and Rust</sub>
</div>
