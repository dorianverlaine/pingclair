# 🧩 Native configuration language

The native language is a declarative configuration surface beside the
Caddy-style Pingclairfile. It borrows Swift's argument labels and SwiftUI's
component composition; it is not executable Swift, and nothing in it is
evaluated at request time. Native files are selected by the `.pingclair`
extension or, for `Pingclairfile`, `Caddyfile` and standard input, by content
shape: a `let`, an `@` attribute, or a top-level `Component(`. A file that
carries one language's extension and the other language's content is refused
with the rename that fixes it, and malformed native input is never
reinterpreted as a Caddyfile. There is no version header.

One concept has exactly one spelling. The names the Caddyfile uses belong to
the compatibility frontend, which stays supported during migration; the native
frontend refuses them instead of growing aliases. Both frontends produce the
same `PingclairConfig` through one validation and publication path.

`pingclair describe` prints the catalogue the parser accepts — every component,
modifier and attribute, each with an example and a refusal — and
`examples/*.pingclair` is the corpus the test suite compiles. This document
owns what the language is allowed to be; it is not a second copy of the
catalogue.

## 🧭 Composition and types

A native file holds `let` bindings, file-level declarations and listeners, in
that order of scope: bindings and declarations come first, and the listeners
that use them follow.

### 🔌 L4

```pingclair
TCPListener(on: ":443") {
    Route(when: .tls(sni: ["tunnel.example"], alpn: ["h2"])) {
        Proxy(to: "127.0.0.1:10001")
    }
    Fallback {
        Proxy(to: "fallback.example:443")
    }
}
.limits(connections: 1024, preread: .kibibytes(16), relay: .kibibytes(16))
.timeouts(preread: .seconds(30), connect: .seconds(5), idle: .minutes(5))
.halfClose(enabled: true)
```

`TCPListener` contains ordered `Route` and `Fallback` components. A `Route`
takes `when: .tls(sni: [...], alpn: [...])`, `from: ["CIDR", ...]`, or both.
Conditions combine with AND; values within an array combine with OR. `.tls()`
requires a ClientHello without selecting a particular name. Each route contains
exactly one `Proxy(to: "host:port")`. `Fallback` is unconditional and must come
last.

L4 listener modifiers are `.limits(connections:, preread:, relay:)`,
`.timeouts(preread:, connect:, idle:)` and `.halfClose(enabled:)`. Each modifier
may appear once, and their order does not change behavior. Defaults and runtime
behavior remain those in the [L4 guardrail](layer4.md), including static DNS
resolution and bounded dialing.

### 🌐 L7

```pingclair
UnderscoreHeaders(["X_Probe", "Webhook_*"])

HTTPListener(on: ":8443") {
    Site(host: "www.example.test") {
        Route(when: .path(prefix: "/api")) {
            Rewrite(stripPrefix: "/api")
            Proxy(to: ["10.0.0.10:8080", "10.0.0.11:8080"]).loadBalance(.roundRobin)
        }
        ErrorRoute(for: [.anyError]) { Respond(status: 502, body: "upstream is down") }
        Fallback { ServeFiles(root: "./public") }
    }
}
.tls(.automatic(email: "admin@example.test"))
.accessLog(output: .file("/var/log/pingclair/access.log"), format: .json)
```

`HTTPListener(on: ":8443")` serves HTTP: each `Site(host: "example.com")`
(`host: "*"` for the catch-all) is a virtual host, and its body is an ordered
list of `Route`, `ErrorRoute` and one final `Fallback`.

**Writing order is execution order.** A route body is a pipeline. Middleware
components (`RequestHeader`, `ResponseHeader`, `Rewrite`, `CORS`, `BasicAuth`,
`RateLimit`, `SetVariable`, `LimitRequestBody`, `SkipLog`, `Templates`,
`ForwardAuth`, `Intercept`) and the path step `TryFiles` act on what follows
them. The components that answer end the route: `Respond`, `Proxy`, `Redirect`,
`Fail`, `ServeMetrics` and `ACMEServer` always do, and `ServeFiles` does unless
it is written `passThru: true`. `ServeFiles(passThru: true)` and `PHPFastCGI`
answer only part of the traffic, so a route may continue past them. A route
that ends in middleware alone is a load error, because nothing in it answered.

Conditions are typed values on `when:`, not directives of their own:
`.path(exact:…)`, `.path(prefix:…)`, `.path(glob:…)`, `.path(.regex(…))`,
`.host`, `.method`, `.query`, `.header`, `.protocol`, `.clientIP`,
`.remoteIP`, `.variable` and `.file`, combined with `.all`, `.any` and `.not`.
`.path(prefix: "/api")` matches whole path segments — `/api` and `/api/users`,
never `/apiv2`. A condition is a pure value, and `@Matcher` names one for
reuse:

```pingclair
@Matcher
let api = .path(prefix: "/api")

HTTPListener(on: ":8080") {
    Site(host: "*") {
        Route(when: api) { Respond(body: "api") }
        Fallback { Respond(body: "site") }
    }
}
```

Listener modifiers are `.bind([...])`, `.protocols([...])`, `.limits(...)`,
`.tls(...)`, `.accessLog(...)`, `.underscoreHeaders([...])` and
`.trustedProxies(ranges:, headers:)`. Sites add `.encode(...)`,
`.errorPage(for:, file:)`, `.tls(...)` and `.http3(enabled:)`. `Proxy` policy
travels on its own chain: `.loadBalance`, `.healthCheck`, `.upstreamTLS`,
`.timeouts`, `.retry`, `.cache`, `.flush`, `.versions`, `.buffers`,
`.overload` and `.circuitBreaker`.

### 🌍 File-level declarations

```pingclair
Admin(listen: "127.0.0.1:2019")
Metrics(enabled: true)
Shutdown(grace: .seconds(10))
TrustedProxies(ranges: [.privateRanges], headers: [.xForwardedFor, .xRealIP])
UnderscoreHeaders(["X_Probe", "Webhook_*"])
Storage(root: "/var/lib/pingclair")
Log(output: .file("/var/log/pingclair/server.log"), level: .info)
AutomaticTLS(mode: .automatic, httpPort: 80, httpsPort: 443)
```

Each declaration may appear once per file, and belongs to exactly one file: two
files declaring the same option are refused, and the message names both files.
The refusal is by *declaration*, not by value — `Metrics(enabled: false)` and
saying nothing compile to the same configuration, and only the syntax tells
them apart. A file holding nothing but declarations is allowed, which is how a
directory keeps its server-wide options in one place.

These declarations are the defaults for every listener. Only
`.underscoreHeaders` and `.trustedProxies` may override them per listener, and
`.trustedProxies` replaces only the half it writes — `ranges:` or `headers:` —
because the two halves answer the same question about who stands in front of
one socket. Every other declaration written as a listener modifier is refused.

### 🧷 Bindings and attributes

```pingclair
let names = ["tunnel.example"]
let backend = Proxy(to: "127.0.0.1:10001")
let secure = Fallback { backend }

TCPListener(on: ":443") {
    Route(when: .tls(sni: names)) { backend }
    secure
}
```

Bindings are immutable, declared before use, and a duplicate name is refused.
Expansion is bounded (4096 components and 8 MiB per file) and happens before
adaptation, so the component converters see a fully expanded tree. There are no
snippets and no parameter substitution: reuse is by name only. `@Matcher`
marks a condition binding. `@Secret` marks a value whose contents never appear
in diagnostics, JSON or logs, and which may flow only into the fields that
store secrets — the DNS-01 provider arguments. Any other position is refused
rather than masked after the fact, because writing the value into the
configuration is what would break the promise.

### 🔢 Values

Durations require `.milliseconds(n)`, `.seconds(n)`, `.minutes(n)` or
`.hours(n)`; sizes require `.bytes(n)`, `.kibibytes(n)` or `.mebibytes(n)`, and
integer multiplication is checked. Strings use double quotes and JSON escapes
and are never interpolated. Arrays and argument lists allow trailing commas,
and integers may use internal underscores. `//` introduces a line comment;
block comments and semicolons are not supported.

## 🛡️ Boundaries

The frontend has no function execution, loops, network imports or mutable
state. Parsing accepts at most 1 MiB of source, 65,536 tokens and 16 nesting
levels. Unknown labels, repeated labels and wrong value types fail closed.
Diagnostics carry a line and a column, and a `@Secret` value is never echoed
into one. A `Pingclair(version: ...)` header is refused with a message that
points declarations to the top level.

Both frontends produce `PingclairConfig` and use the same validation and publication
path. `adapt` converts without provisioning validation; `validate`, `run`, and
Admin reload validate. Admin accepts native text as `Content-Type: text/pingclair`.
The configuration is fully compiled at load time; no component tree is interpreted
in a request. `fmt` formats native input canonically — comments preserved,
four-space indentation, one declaration per line — and `describe` prints the
component table the parser accepts, in text, JSON, or one compressed JSON line
per entry for agents (`--format agents`).

References: [Swift API guidelines](https://www.swift.org/documentation/api-design-guidelines/),
[SwiftUI ViewBuilder](https://developer.apple.com/documentation/swiftui/viewbuilder),
[SwiftUI modifiers](https://developer.apple.com/documentation/swiftui/configuring-views).
