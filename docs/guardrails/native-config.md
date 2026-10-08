# 🧩 Native configuration language

The 0.3 alpha introduces a declarative configuration language inspired
by Swift argument labels and SwiftUI component composition. It is not executable
Swift. Native files are selected by the `.pingclair` extension or by the content
shape: a top-level `Component(...)` declaration, after any `//` comments. There
is no version header. Existing Caddy-style files remain supported during
migration. Do not mix both syntaxes inside one file. Directory loading can
combine separate files through the existing shared merge and validation path.

```swift
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

## 🧭 Composition and types

`TCPListener` contains ordered `Route` and `Fallback` components. A `Route` takes
`when: .tls(sni: [...], alpn: [...])`, `from: ["CIDR", ...]`, or both. Conditions
combine with AND; values within an array combine with OR. `.tls()` requires a
ClientHello without selecting a particular name. Each route contains exactly one
`Proxy(to: "host:port")`. `Fallback` is unconditional and must come last.

Listener modifiers are `.limits(connections:, preread:, relay:)`,
`.timeouts(preread:, connect:, idle:)`, and `.halfClose(enabled:)`. Each modifier
may appear once. Their order does not change behavior. Modifiers on other
component types are rejected. Defaults and runtime behavior remain those in the
[L4 guardrail](layer4.md), including static DNS resolution and bounded dialing.

Durations require `.milliseconds(n)`, `.seconds(n)`, or `.minutes(n)`; sizes require
`.bytes(n)`, `.kibibytes(n)`, or `.mebibytes(n)`. Integer multiplication is checked.
Strings use double quotes and JSON escapes; interpolation is unavailable. Arrays
and argument lists allow trailing commas. Integers may use internal underscores.
`//` introduces a line comment. Block comments and semicolons are not supported.

The top level also accepts `Admin(listen: "127.0.0.1:2019")`,
`Metrics(enabled: true)`, and `Shutdown(grace: .seconds(5))`. Grace requires whole
seconds. These declarations are optional and cannot repeat. This first frontend
covers TCP configuration; HTTP, access-log declarations and dynamic DNS are not
accepted yet. Unsupported components are errors, not ignored placeholders.

## 🛡️ Boundaries

The frontend has no function execution, loops, network imports or mutable state.
Parsing accepts at most 1 MiB of source, 65,536 tokens and 16 nesting levels.
Diagnostics include line and column without echoing literal values. Unknown
labels, repeated labels and wrong value types fail closed. A
`Pingclair(version: ...)` header is refused with a message that points
declarations to the top level; malformed native input never falls back to Caddy
interpretation.

Both frontends produce `PingclairConfig` and use the same validation and publication
path. `adapt` converts without provisioning validation; `validate`, `run`, and
Admin reload validate. Admin accepts native text as `Content-Type: text/pingclair`.
The configuration is fully compiled at load time; no component tree is interpreted
in a TCP session. `fmt` currently refuses native input without modifying the file.

References: [Swift API guidelines](https://www.swift.org/documentation/api-design-guidelines/),
[SwiftUI ViewBuilder](https://developer.apple.com/documentation/swiftui/viewbuilder),
[SwiftUI modifiers](https://developer.apple.com/documentation/swiftui/configuring-views).
