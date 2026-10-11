# Pingclair Official Website

**English** · [Français](README.fr.md) · [简体中文](README.zh-CN.md) · [繁體中文](README.zh-TW.md)

## Overview

Official website: [https://pingclair.com](https://pingclair.com)

The source code for the Pingclair website has been moved to a dedicated repository:

**[dorianverlaine/pingclair-docs](https://github.com/dorianverlaine/pingclair-docs)**

Following this migration, this directory no longer contains the website source code. The previous directory structure and its `.gitkeep` placeholder files have also been removed.

This directory now retains only the production configuration of the official website, serving as a practical deployment example of Pingclair's native configuration language.

The configuration demonstrates how to deploy a static documentation website using a single `Pingclairfile`, including:

- Automatic TLS certificate management and HTTP/3 support
- Name-based virtual hosting
- Static file serving and custom error pages
- Reverse proxying and response caching
- Markdown content negotiation for AI agents
- Permanent redirects and canonical domain management
- Structured access logging and automatic log rotation

## Production Configuration

The following `Pingclairfile` is used by the production deployment of `pingclair.com`.

The website is served by Pingclair running on a FreeBSD server. `pingclair.pingclair.com` is retained as a staging hostname, while `www.pingclair.com` permanently redirects to the apex domain.

The original English comments are preserved to facilitate comparison with the deployed configuration.

```swift
// 🏝️ pingclair.com — the docs site, served by Pingclair from a FreeBSD
// node, with pingclair.pingclair.com kept as the staging alias and
// www redirected to the apex.

AutomaticTLS(mode: .automatic, httpPort: 80, httpsPort: 443)
Storage(root: "/var/db/pingclair")

// 🔁 The Admin API on loopback, so `pingclair reload` can hot-reload this
// file instead of a restart dropping connections.
Admin(listen: "127.0.0.1:2019")

// 🧊 The one-line install address: `https://pingclair.com/install.sh`.
//
// The script lives in the server repository and is published to the release
// bucket by every release; proxying it here rather than keeping a copy is the
// same choice the Cloudflare Worker made — there is no second file to drift.
let installerHost = "releases.pingclair.com:443"

// 🤖 The agent endpoints still served by the documentation Worker; the
// docs node proxies them so `pingclair.com/mcp` and `/a2a` keep the URL
// contract the Worker era established.
let cfWorker = "cf.pingclair.com:443"

// 🔗 The discovery links the documentation Worker published through the build
// output's `_headers` file; the native file server does not read that file, so
// the same value is stated once here and reused by every route that serves
// files. The escape keeps the real quotes in the value.
let agentLink = "</.well-known/api-catalog>; rel=\"api-catalog\", </llms.txt>; rel=\"describedby\", </sitemap.xml>; rel=\"sitemap\""

HTTPListener(on: ":443") {
    Site(host: "pingclair.com") {
        Route(when: .path(exact: "/install.sh")) {
            Rewrite(to: "/pingclair/install.sh")
            Proxy(
                to: installerHost,
                headersUp: [.set("Host", "releases.pingclair.com")],
                headersDown: [.setIfAbsent("X-Installer-Source", "r2")],
            )
            .upstreamTLS(.enabled(serverName: "releases.pingclair.com"))
            .cache(ttl: .minutes(5), maxSize: .mebibytes(16))
        }
        Route(when: .path(exact: "/install")) {
            Rewrite(to: "/pingclair/install.sh")
            Proxy(
                to: installerHost,
                headersUp: [.set("Host", "releases.pingclair.com")],
                headersDown: [.setIfAbsent("X-Installer-Source", "r2")],
            )
            .upstreamTLS(.enabled(serverName: "releases.pingclair.com"))
            .cache(ttl: .minutes(5), maxSize: .mebibytes(16))
        }
        Route(when: .path(exact: "/mcp")) {
            Proxy(to: cfWorker, headersUp: [.set("Host", "cf.pingclair.com")])
            .upstreamTLS(.enabled(serverName: "cf.pingclair.com"))
        }
        Route(when: .path(exact: "/a2a")) {
            Proxy(to: cfWorker, headersUp: [.set("Host", "cf.pingclair.com")])
            .upstreamTLS(.enabled(serverName: "cf.pingclair.com"))
        }
        // 🗂️ Rules the Cloudflare side applied at the edge — the `_headers`
        // file does not exist for the native file server — stated natively:
        // immutable cache for build assets, a short cache for the search
        // index, plain text for direct Markdown fetches, cross-origin
        // discovery catalogs, and the API catalog's RFC 9727 media type
        // (which the Worker set itself).
        Route(when: .path(prefix: "/_astro")) {
            ResponseHeader(.set("X-Content-Type-Options", "nosniff"), .set("Referrer-Policy", "strict-origin-when-cross-origin"), .set("X-Frame-Options", "DENY"), .set("Link", agentLink), .set("Cache-Control", "public, max-age=31536000, immutable"))
            ServeFiles(root: "/usr/local/www/pingclair.pingclair.com")
        }
        Route(when: .path(prefix: "/pagefind")) {
            ResponseHeader(.set("X-Content-Type-Options", "nosniff"), .set("Referrer-Policy", "strict-origin-when-cross-origin"), .set("X-Frame-Options", "DENY"), .set("Link", agentLink), .set("Cache-Control", "public, max-age=3600"))
            ServeFiles(root: "/usr/local/www/pingclair.pingclair.com")
        }
        Route(when: .path(glob: "*.md")) {
            ResponseHeader(.set("X-Content-Type-Options", "nosniff"), .set("Referrer-Policy", "strict-origin-when-cross-origin"), .set("X-Frame-Options", "DENY"), .set("Link", agentLink), .set("Content-Type", "text/plain; charset=utf-8"))
            ServeFiles(root: "/usr/local/www/pingclair.pingclair.com")
        }
        Route(when: .path(exact: "/.well-known/api-catalog")) {
            ResponseHeader(.set("X-Content-Type-Options", "nosniff"), .set("Referrer-Policy", "strict-origin-when-cross-origin"), .set("X-Frame-Options", "DENY"), .set("Link", agentLink), .set("Access-Control-Allow-Origin", "*"), .set("Content-Type", "application/linkset+json"))
            ServeFiles(root: "/usr/local/www/pingclair.pingclair.com")
        }
        Route(when: .path(prefix: "/.well-known")) {
            ResponseHeader(.set("X-Content-Type-Options", "nosniff"), .set("Referrer-Policy", "strict-origin-when-cross-origin"), .set("X-Frame-Options", "DENY"), .set("Link", agentLink), .set("Access-Control-Allow-Origin", "*"))
            ServeFiles(root: "/usr/local/www/pingclair.pingclair.com")
        }
        // 📄 Agents that ask for markdown get the twin on the same URL: the
        // directory's `index.md`, or the sibling `<name>.md`; a miss carries
        // on to the normal file server unchanged. The `index.md` copies are
        // made at deploy time.
        Route(when: .header(name: "Accept", contains: "text/markdown")) {
            TryFiles(candidates: [.requestPath(appending: "index.md"), .requestPath(appending: ".md")], root: "/usr/local/www/pingclair.pingclair.com")
            ServeFiles(root: "/usr/local/www/pingclair.pingclair.com")
        }
        Fallback {
            // 🔗 `public/_headers` states these on the Cloudflare deployment;
            // the native file server does not read that file, so the same
            // rules are stated here.
            ResponseHeader(.set("X-Content-Type-Options", "nosniff"), .set("Referrer-Policy", "strict-origin-when-cross-origin"), .set("X-Frame-Options", "DENY"), .set("Link", agentLink))
            ServeFiles(root: "/usr/local/www/pingclair.pingclair.com")
        }
    }
    // 🧾 Starlight ships a 404 page; unknown paths answer with it, the same
    // as the Cloudflare deployment's `not_found_handling`.
    .errorPage(for: [.status(404)], file: "/usr/local/www/pingclair.pingclair.com/404.html")
    .encode(.zstd, .gzip)

    Site(host: "www.pingclair.com") {
        // ➡️ 308 to the apex, the same permanent move the Cloudflare zone
        // answered. The native language has no request-time placeholders yet,
        // so the path does not ride along; a `keepPath:` argument on Redirect
        // is the design idea on file for that.
        Fallback { Redirect(to: "https://pingclair.com", status: .permanentRedirect) }
    }

    Site(host: "pingclair.pingclair.com") {
        Route(when: .path(exact: "/install.sh")) {
            Rewrite(to: "/pingclair/install.sh")
            Proxy(
                to: installerHost,
                headersUp: [.set("Host", "releases.pingclair.com")],
                headersDown: [.setIfAbsent("X-Installer-Source", "r2")],
            )
            .upstreamTLS(.enabled(serverName: "releases.pingclair.com"))
            .cache(ttl: .minutes(5), maxSize: .mebibytes(16))
        }
        Route(when: .path(exact: "/mcp")) {
            Proxy(to: cfWorker, headersUp: [.set("Host", "cf.pingclair.com")])
            .upstreamTLS(.enabled(serverName: "cf.pingclair.com"))
        }
        Route(when: .path(exact: "/a2a")) {
            Proxy(to: cfWorker, headersUp: [.set("Host", "cf.pingclair.com")])
            .upstreamTLS(.enabled(serverName: "cf.pingclair.com"))
        }
        // 🗂️ The same edge rules as the apex site.
        Route(when: .path(prefix: "/_astro")) {
            ResponseHeader(.set("X-Content-Type-Options", "nosniff"), .set("Referrer-Policy", "strict-origin-when-cross-origin"), .set("X-Frame-Options", "DENY"), .set("Link", agentLink), .set("Cache-Control", "public, max-age=31536000, immutable"))
            ServeFiles(root: "/usr/local/www/pingclair.pingclair.com")
        }
        Route(when: .path(prefix: "/pagefind")) {
            ResponseHeader(.set("X-Content-Type-Options", "nosniff"), .set("Referrer-Policy", "strict-origin-when-cross-origin"), .set("X-Frame-Options", "DENY"), .set("Link", agentLink), .set("Cache-Control", "public, max-age=3600"))
            ServeFiles(root: "/usr/local/www/pingclair.pingclair.com")
        }
        Route(when: .path(glob: "*.md")) {
            ResponseHeader(.set("X-Content-Type-Options", "nosniff"), .set("Referrer-Policy", "strict-origin-when-cross-origin"), .set("X-Frame-Options", "DENY"), .set("Link", agentLink), .set("Content-Type", "text/plain; charset=utf-8"))
            ServeFiles(root: "/usr/local/www/pingclair.pingclair.com")
        }
        Route(when: .path(exact: "/.well-known/api-catalog")) {
            ResponseHeader(.set("X-Content-Type-Options", "nosniff"), .set("Referrer-Policy", "strict-origin-when-cross-origin"), .set("X-Frame-Options", "DENY"), .set("Link", agentLink), .set("Access-Control-Allow-Origin", "*"), .set("Content-Type", "application/linkset+json"))
            ServeFiles(root: "/usr/local/www/pingclair.pingclair.com")
        }
        Route(when: .path(prefix: "/.well-known")) {
            ResponseHeader(.set("X-Content-Type-Options", "nosniff"), .set("Referrer-Policy", "strict-origin-when-cross-origin"), .set("X-Frame-Options", "DENY"), .set("Link", agentLink), .set("Access-Control-Allow-Origin", "*"))
            ServeFiles(root: "/usr/local/www/pingclair.pingclair.com")
        }
        // 📄 The same markdown negotiation as the apex site.
        Route(when: .header(name: "Accept", contains: "text/markdown")) {
            TryFiles(candidates: [.requestPath(appending: "index.md"), .requestPath(appending: ".md")], root: "/usr/local/www/pingclair.pingclair.com")
            ServeFiles(root: "/usr/local/www/pingclair.pingclair.com")
        }
        Fallback {
            // 🔗 The same header set as the apex site.
            ResponseHeader(.set("X-Content-Type-Options", "nosniff"), .set("Referrer-Policy", "strict-origin-when-cross-origin"), .set("X-Frame-Options", "DENY"), .set("Link", agentLink))
            ServeFiles(root: "/usr/local/www/pingclair.pingclair.com")
        }
    }
    .errorPage(for: [.status(404)], file: "/usr/local/www/pingclair.pingclair.com/404.html")
    .encode(.zstd, .gzip)
}
.tls(.automatic(email: "team@pingclair.com"))
// 📓 One JSON line per request, rotated by Pingclair itself.
.accessLog(
    output: .file("/var/log/pingclair-access.log"),
    format: .json,
    headers: [.request("User-Agent")],
    rotation: .roll(size: .mebibytes(100), keep: 7, compress: true),
)
```

## Configuration Reference

### 1. Global Configuration and Upstream Definitions

`AutomaticTLS` and `Storage` define service-level TLS management and persistent storage behavior.

```swift
AutomaticTLS(mode: .automatic, httpPort: 80, httpsPort: 443)
Storage(root: "/var/db/pingclair")
Admin(listen: "127.0.0.1:2019")
```

`AutomaticTLS` enables automatic certificate management and configures the HTTP and HTTPS ports used to support certificate issuance and renewal.

`Storage` specifies the persistent data directory for TLS certificates, ACME account keys, and related state information.

`Admin` publishes the administration API on the loopback address; that is what makes a hot reload possible, so configuration edits do not require a restart.

The configuration also uses `let` declarations to define two upstream addresses:

```swift
let installerHost = "releases.pingclair.com:443"
let cfWorker = "cf.pingclair.com:443"
```

Centralizing upstream definitions reduces duplication and ensures consistent references across multiple routes.

In Pingclair's native configuration language, strings are treated as literals. Runtime variable interpolation within strings is intentionally unsupported. Upstream addresses are referenced through explicit bindings, allowing the configuration to be resolved and inspected at load time.

### 2. HTTP Listeners and Virtual Hosts

```swift
HTTPListener(on: ":443") {
    Site(host: "pingclair.com") { ... }
    Site(host: "www.pingclair.com") { ... }
    Site(host: "pingclair.pingclair.com") { ... }
}
```

`HTTPListener` defines a listening endpoint, while `Site` configures virtual hosts based on the requested hostname.

Multiple `Site` definitions can share a single listener without requiring separate network listening endpoints.

The current deployment defines three virtual hosts:

| Hostname | Purpose |
|---|---|
| `pingclair.com` | Official website and primary API endpoints |
| `www.pingclair.com` | Permanent redirect to the apex domain |
| `pingclair.pingclair.com` | Staging and compatibility endpoint |

This structure separates network listener configuration from site-specific routing logic, allowing TLS, logging, and other listener-level functionality to be managed centrally.

### 3. Route Matching and Execution Order

Pingclair evaluates `Route` declarations in their defined order. The first matching route is responsible for handling the request.

If no route matches, the request is handled by `Fallback`.

The official website uses the following routing precedence:

1. Installation scripts: `/install.sh` and `/install`
2. Agent endpoints: `/mcp` and `/a2a`
3. Markdown selection based on the `Accept` request header
4. Standard static file serving through `Fallback`

Exact-path routes are evaluated before the more general header-based route. This prevents static file handling or content negotiation from interfering with dedicated endpoints.

Route execution order is explicitly represented in the configuration file, without additional priority values or implicit ordering rules.

### 4. Upstream Proxying and Response Caching

The official website does not maintain a separate copy of the installation script. Instead, the script is distributed through an independent release service.

Both `/install.sh` and `/install` are served through a reverse proxy to `releases.pingclair.com`:

```swift
Rewrite(to: "/pingclair/install.sh")
Proxy(
    to: installerHost,
    headersUp: [.set("Host", "releases.pingclair.com")],
    headersDown: [.setIfAbsent("X-Installer-Source", "r2")],
)
.upstreamTLS(.enabled(serverName: "releases.pingclair.com"))
.cache(ttl: .minutes(5), maxSize: .mebibytes(16))
```

The configuration performs the following operations:

1. **Path rewriting:** `Rewrite` transforms the incoming request path into the resource path expected by the release service.
2. **Upstream proxying:** `Proxy` forwards the request to the designated HTTPS upstream.
3. **Host header configuration:** `headersUp` explicitly sets the `Host` header of the upstream request.
4. **TLS server name:** `upstreamTLS` specifies the server name used for the upstream TLS connection.
5. **Response caching:** `cache` configures a five-minute time-to-live and a 16 MiB size limit.
6. **Response source identification:** `headersDown` adds `X-Installer-Source: r2` when the response header is not already present.

Explicitly configuring the upstream `Host` header and TLS server name is particularly important for this deployment.

If the upstream request retained the original hostname, `pingclair.com`, Cloudflare could route it back to the website server, potentially creating an unintended proxy loop.

The configuration therefore distinguishes the public-facing hostname from the upstream service hostname.

Distributing the installer through a dedicated release service also eliminates the need to maintain synchronized copies across the website deployment and software release infrastructure.

#### Agent Endpoint Proxying

The `/mcp` and `/a2a` endpoints use the same reverse proxy mechanism, without response caching.

```swift
Route(when: .path(exact: "/mcp")) {
    Proxy(to: cfWorker, headersUp: [.set("Host", "cf.pingclair.com")])
    .upstreamTLS(.enabled(serverName: "cf.pingclair.com"))
}
```

These endpoints continue to be served by a Cloudflare Worker. The website server forwards incoming requests to the existing upstream service.

This arrangement preserves established endpoint paths, allowing the website infrastructure to migrate without requiring corresponding changes to client-facing API URLs.

### 5. Markdown Content Negotiation for AI Agents

The official website supports serving either HTML or Markdown content at the same URL, depending on the HTTP `Accept` request header.

```swift
Route(when: .header(name: "Accept", contains: "text/markdown")) {
    TryFiles(
        candidates: [
            .requestPath(appending: "index.md"),
            .requestPath(appending: ".md")
        ],
        root: "/usr/local/www/pingclair.pingclair.com"
    )
    ServeFiles(root: "/usr/local/www/pingclair.pingclair.com")
}
```

*The example above has been reformatted for readability. Its behavior is equivalent to the production configuration.*

When a client sends an `Accept` header containing `text/markdown`, Pingclair attempts to locate the corresponding Markdown file.

`TryFiles` checks the following candidate paths in order:

1. An `index.md` file within the directory corresponding to the requested path
2. A corresponding `.md` file derived from the requested path

When a matching file is found, the subsequent `ServeFiles` handler serves the selected resource.

If neither candidate exists, `TryFiles` does not immediately return an error. Processing continues using the original request path.

As a result, ordinary static assets and resources without Markdown equivalents remain accessible through the standard file server.

During deployment, the build process also generates the required `index.md` files from their corresponding Markdown source files to support directory-based documentation URLs.

For ordinary browser requests, the website continues to serve HTML. Markdown files are excluded from the file server's default directory index list and therefore do not replace the standard HTML index pages.

It is important to note that the current implementation selects Markdown by checking whether the `Accept` header contains `text/markdown`. This is a header-based representation selection mechanism rather than a complete implementation of HTTP content negotiation.

The purpose of this mechanism is to allow AI agents to retrieve structured textual representations of documentation pages directly, while preserving existing URLs and standard browser behavior.

For additional background on website accessibility and content organization for AI agents, see Cloudflare's article:

[Agent Readiness](https://blog.cloudflare.com/agent-readiness/)

### 6. Canonical Domains and Permanent Redirects

The official website uses `pingclair.com` as its canonical hostname. Requests to `www.pingclair.com` are permanently redirected to the apex domain using HTTP 308.

```swift
Site(host: "www.pingclair.com") {
    Fallback {
        Redirect(
            to: "https://pingclair.com",
            status: .permanentRedirect
        )
    }
}
```

HTTP 308 indicates a permanent redirect and requires clients to preserve the original request method when following the redirect.

The current configuration has one known limitation: **the original request path is not preserved.**

For example, a request to `https://www.pingclair.com/docs/example` is redirected to `https://pingclair.com`, rather than to the corresponding documentation path.

This limitation exists because the native configuration language does not yet provide a request-path reference mechanism for constructing dynamic redirect targets.

Potential improvements are tracked in [Issue #330](https://github.com/dorianverlaine/pingclair/issues/330), including a proposal to introduce a `keepPath` parameter for `Redirect`.

### 7. TLS and HTTP/3

```swift
.tls(.automatic(email: "team@pingclair.com"))
```

The listener uses automatic TLS configuration to manage certificate issuance and renewal.

`team@pingclair.com` serves as the contact email address for the associated ACME account.

The current deployment also supports HTTP/3, providing QUIC-based HTTP connections over UDP/443.

HTTP/3 and conventional TLS-over-TCP connections can share the same numerical port while using different transport protocols: UDP and TCP, respectively.

### 8. Custom Error Pages and Content Compression

The official website uses the `404.html` page generated by Starlight as its custom error page.

```swift
.errorPage(
    for: [.status(404)],
    file: "/usr/local/www/pingclair.pingclair.com/404.html"
)
.encode(.zstd, .gzip)
```

`errorPage` associates HTTP 404 responses with the specified static error page, providing consistent presentation when a requested resource cannot be found.

`encode` enables Zstandard and Gzip content encoding, allowing compatible clients to receive compressed responses according to their supported encodings.

### 9. Access Logging and Log Rotation

```swift
.accessLog(
    output: .file("/var/log/pingclair-access.log"),
    format: .json,
    headers: [.request("User-Agent")],
    rotation: .roll(
        size: .mebibytes(100),
        keep: 7,
        compress: true
    ),
)
```

The configuration enables JSON-formatted access logs written to:

`/var/log/pingclair-access.log`

Each request is recorded as an individual JSON entry, facilitating log collection, querying, and automated analysis.

The logs additionally include the request's `User-Agent` header. Log file management is handled by Pingclair's built-in rotation mechanism:

- Rotate the log file when it reaches 100 MiB
- Retain up to seven rotated files
- Compress rotated log files

This allows the deployment to manage the configured log lifecycle without relying on an external log rotation utility.

## References

For further information about Pingclair's native configuration language and supported components, consult the following resources:

- **[Official Documentation](https://pingclair.com)**: Configuration language reference, feature documentation, and deployment guides
- **`pingclair describe`**: Inspect the configuration components and definitions supported by the parser
- **`pingclair validate`**: Validate configuration files and report syntax or configuration errors with their corresponding source locations
- **[Website Source Repository](https://github.com/dorianverlaine/pingclair-docs)**: Source code and documentation for the official website

The configuration presented here illustrates a real-world production deployment of Pingclair. For authoritative information about configuration parameters and feature availability, refer to the documentation corresponding to the version in use.
