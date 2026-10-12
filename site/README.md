# Pingclair Official Website

**English** · [Français](README.fr.md) · [简体中文](README.zh-CN.md) · [繁體中文](README.zh-TW.md)

## Overview

Official website: [https://pingclair.com](https://pingclair.com)

The website's source code lives in its own repository,
**[dorianverlaine/pingclair-docs](https://github.com/dorianverlaine/pingclair-docs)**.
This directory keeps only the production configuration, [`Pingclairfile`](Pingclairfile),
as a worked example of deploying a static documentation site with Pingclair:

- automatic TLS certificates and HTTP/3
- name-based virtual hosting for three hostnames
- static files, a custom 404 page, and compression
- reverse proxying with a response cache
- Markdown for AI agents on the same URLs
- a permanent redirect to the canonical domain
- JSON access logs with built-in rotation

The site runs on a FreeBSD server. `pingclair.pingclair.com` is kept as a
staging hostname, and `www.pingclair.com` redirects permanently to the apex.
The file is a Pingclairfile — the Caddyfile syntax — and the excerpts below are
taken from it.

## Configuration walkthrough

### 1. Global options

```caddyfile
{
    email team@pingclair.com
    storage file_system /var/db/pingclair
    admin 127.0.0.1:2019
}
```

`email` is the ACME account contact for automatic certificates. `storage`
names the directory that keeps certificates, account keys and related state.
`admin` publishes the Admin API on loopback only, which is what lets
`pingclair reload` apply an edited file without dropping connections.

### 2. Snippets for what repeats

The file defines its repeated pieces once, as snippets, and imports them:

| Snippet | What it holds |
| --- | --- |
| `(edge_headers)` | The security headers and the agent-discovery `Link` header the Cloudflare deployment stated in its `_headers` file |
| `(installer)` | The proxy that serves `install.sh` from the release bucket |
| `(worker)` | The proxy for the `/mcp` and `/a2a` agent endpoints |
| `(access_log)` | The access log every site writes to |
| `(docs)` | The whole documentation site, shared by the apex and staging hosts |

### 3. Virtual hosts

```caddyfile
pingclair.com {
    import docs
}

pingclair.pingclair.com {
    import docs
}

www.pingclair.com {
    import access_log
    redir https://pingclair.com{uri} 308
}
```

A site address with a hostname gets automatic HTTPS on port 443, HTTP/3 on
UDP 443, and a port-80 listener that redirects to HTTPS and answers ACME
challenges.

| Hostname | Purpose |
| --- | --- |
| `pingclair.com` | The website and its agent endpoints |
| `pingclair.pingclair.com` | Staging, serving the same site |
| `www.pingclair.com` | A permanent redirect to the apex |

### 4. Route order

```caddyfile
handle /install.sh {
    import installer
}
…
@markdown header Accept *text/markdown*
handle @markdown {
    …
}
handle {
    import edge_headers
    file_server
}
```

`handle` blocks are mutually exclusive: the first one that matches answers the
request. They are ordered by how specific their path is, so the exact paths and
prefixes — the installer, the agent endpoints, the build assets, the search
index, Markdown files and the `/.well-known` documents — come first; the block
that matches on the `Accept` header comes after every path, and the block with
no matcher comes last. None of the paths overlap, so that order is the order
the site needs.

### 5. Proxying the installer, with a cache

```caddyfile
(installer) {
    rewrite * /pingclair/install.sh
    reverse_proxy releases.pingclair.com:443 {
        header_up Host releases.pingclair.com
        header_down ?X-Installer-Source r2
        transport http {
            tls
            tls_server_name releases.pingclair.com
        }
        cache {
            ttl 5m
            max_size 16777216
        }
    }
}
```

The site keeps no copy of the installer; every release publishes it to the
release bucket, and the site proxies to it. The request path is rewritten to
the bucket's path, the upstream `Host` and TLS server name are set explicitly,
responses are cached for five minutes in up to 16 MiB, and
`X-Installer-Source: r2` is added when the upstream did not set it.

The explicit `Host` matters here: an upstream request that kept
`pingclair.com` could be routed by Cloudflare back to this server, a loop.

The `/mcp` and `/a2a` endpoints are still served by a Cloudflare Worker; the
`(worker)` snippet proxies them the same way, without a cache, so their URLs
did not change when the site moved.

### 6. Edge rules

```caddyfile
handle /_astro/* {
    import edge_headers
    header Cache-Control "public, max-age=31536000, immutable"
    file_server
}
```

The Cloudflare deployment applied these at the edge; here each is one
`handle` block: an immutable cache for build assets, a one-hour cache for the
search index, `text/plain` for direct Markdown fetches, and cross-origin access
to the `/.well-known` documents, with the RFC 9727 media type for the API
catalog.

### 7. Markdown for AI agents

```caddyfile
@markdown header Accept *text/markdown*
handle @markdown {
    try_files {path}index.md {path}.md
    file_server
}
```

A client whose `Accept` header contains `text/markdown` gets the page's
Markdown twin on the same URL: the directory's `index.md`, or the sibling
`<name>.md`. When neither exists, the request continues with its original path,
so assets and pages without a twin are still served. Browsers keep getting
HTML. The `index.md` copies are generated at deploy time.

This is a header test, not full HTTP content negotiation. Pingclair also offers
`file_server { negotiate markdown }`, which follows RFC 9110's quality values
and sets `Vary: Accept`; the site may move to it.

For background, see Cloudflare's [Agent Readiness](https://blog.cloudflare.com/agent-readiness/).

### 8. The 404 page and compression

```caddyfile
encode zstd gzip

handle_errors 404 {
    rewrite * /404.html
    file_server
}
```

`encode` offers Zstandard and gzip to clients that accept them. A request for a
missing file answers with Starlight's `404.html`, with the 404 status kept.

### 9. Access logs

```caddyfile
(access_log) {
    log {
        output file /var/log/pingclair-access.log {
            roll_size 100MiB
            roll_keep 7
        }
        format json
        headers {
            request User-Agent
        }
    }
}
```

Each request is one JSON line in `/var/log/pingclair-access.log`, with the
request's `User-Agent`. Pingclair rotates the file itself at 100 MiB, keeps
seven rotated files, and compresses them.

## References

- **[Official documentation](https://pingclair.com)** — configuration
  reference and deployment guides.
- **`pingclair validate`** — checks a configuration and reports errors with
  their location.
- **`pingclair fmt`** — formats a Pingclairfile, keeping its comments.
- **[Website source](https://github.com/dorianverlaine/pingclair-docs)** — the
  site's own repository.
