<div align="center">

# 🦀 Pingclair

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
```

The verified client IP is shared by access control, rate limiting, IP-hash
load balancing, upstream forwarding, placeholders, and access logs. Changes
to `trusted_proxies` currently require a restart.

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
        # Used only when every primary is unavailable.
        to 10.0.0.3:8080 { backup }
    }
}
```

The upstream scheme selects the connection protocol: a bare address or `http://`
uses HTTP/1.1, `https://` negotiates HTTP/2 with HTTP/1.1 fallback through ALPN,
`h2c://` requires prior-knowledge plaintext HTTP/2, and `h2://` requires HTTP/2
over TLS. Use `h2c://` or `h2://` for native gRPC so response trailers remain
end-to-end metadata.

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

### Workflow

1.  **Fork** the repository.
2.  **Create a branch**: `git checkout -b feature/my-cool-feature`
3.  **Write code** following standard Rust style.
4.  **Run the tests** and make sure they pass:
    ```bash
    cargo test --workspace
    ```
5.  **Open a PR** describing your change.

## 📄 License

Licensed under the **Apache License 2.0**. See [LICENSE](LICENSE) for details.

---

<div align="center">
  <sub>Built with ❤️ and Rust</sub>
</div>
