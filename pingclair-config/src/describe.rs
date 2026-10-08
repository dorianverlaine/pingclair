// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 📇 What the language accepts, as data: the source `pingclair describe` prints.
//!
//! Every entry carries a canonical example and a refusal. Tests compile the
//! examples and refuse the refusals, so this table cannot drift from the parser
//! without turning red.

use serde_json::json;

/// What a described name is.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Component,
    Modifier,
    Attribute,
}

impl Kind {
    fn label(self) -> &'static str {
        match self {
            Kind::Component => "component",
            Kind::Modifier => "modifier",
            Kind::Attribute => "attribute",
        }
    }
}

/// One described name.
#[derive(Clone, Copy)]
pub struct Entry {
    pub name: &'static str,
    pub kind: Kind,
    pub summary: &'static str,
    pub example: &'static str,
    pub refusal: &'static str,
    /// 🏷️ The argument labels this name accepts, **taken from the parser's own
    /// list** rather than written out again here.
    ///
    /// 📌 The review found the gap this closes: a hand-written catalogue cannot
    /// promise it lists what the parser accepts. One constant per component,
    /// read by both sides, is the smallest thing that can.
    pub labels: &'static [&'static str],
}

pub const ENTRIES: &[Entry] = &[
    Entry {
        name: "TCPListener",
        kind: Kind::Component,
        summary: "Raw TCP listener; routes by TLS ClientHello or peer address.",
        example: r#"TCPListener(on: "127.0.0.1:9443") {
    Route(when: .tls(sni: ["example.test"])) { Proxy(to: "127.0.0.1:8443") }
    Fallback { Proxy(to: "127.0.0.1:8080") }
}"#,
        refusal: r#"TCPListener(on: "127.0.0.1:9443") {
    Unknown { Proxy(to: "127.0.0.1:8080") }
}"#,
        labels: crate::frontend::tcp::L4_ROUTE_LABELS,
    },
    Entry {
        name: "Route",
        kind: Kind::Component,
        summary: "A conditional route: L4 takes `when:`/`from:` plus one `Proxy`; HTTP takes a typed `when:` condition.",
        example: r#"TCPListener(on: "127.0.0.1:9443") {
    Route(when: .tls(sni: ["example.test"]), from: ["127.0.0.0/8"]) {
        Proxy(to: "127.0.0.1:8443")
    }
}"#,
        refusal: r#"TCPListener(on: "127.0.0.1:9443") {
    Route(when: .tls(sni: ["example.test"])) { }
}"#,
        labels: crate::frontend::tcp::L4_ROUTE_LABELS,
    },
    Entry {
        name: "Fallback",
        kind: Kind::Component,
        summary: "The unconditional final route of a listener.",
        example: r#"TCPListener(on: "127.0.0.1:9443") {
    Fallback { Proxy(to: "127.0.0.1:8080") }
}"#,
        refusal: r#"TCPListener(on: "127.0.0.1:9443") {
    Fallback(when: .tls()) { Proxy(to: "127.0.0.1:8080") }
}"#,
        labels: &[],
    },
    Entry {
        name: "Proxy",
        kind: Kind::Component,
        summary: "The upstream connection: `Proxy(to: \"host:port\")`.",
        example: r#"TCPListener(on: "127.0.0.1:9443") {
    Fallback { Proxy(to: "127.0.0.1:8080") }
}"#,
        refusal: r#"TCPListener(on: "127.0.0.1:9443") {
    Fallback { Proxy(to: 8080) }
}"#,
        labels: crate::frontend::http::PROXY_LABELS,
    },
    Entry {
        name: "HTTPListener",
        kind: Kind::Component,
        summary: "A plaintext HTTP listener serving one or more sites.",
        example: r#"HTTPListener(on: ":8080") {
    Site(host: "*") {
        Fallback { Respond(body: "hello", status: 200) }
    }
}"#,
        refusal: r#"HTTPListener(on: ":8080") {}"#,
        labels: crate::frontend::http::HTTP_LISTENER_LABELS,
    },
    Entry {
        name: "Site",
        kind: Kind::Component,
        summary: "One virtual host inside an HTTP listener.",
        example: r#"HTTPListener(on: ":8080") {
    Site(host: "example.test") {
        Fallback { Respond(body: "hello") }
    }
}"#,
        refusal: r#"HTTPListener(on: ":8080") {
    Site(host: "example.test") { }
}"#,
        labels: crate::frontend::http::SITE_LABELS,
    },
    Entry {
        name: "Respond",
        kind: Kind::Component,
        summary: "A fixed HTTP response: `Respond(body:, status:)`.",
        example: r#"HTTPListener(on: ":8080") {
    Site(host: "*") {
        Fallback { Respond(body: "hello", status: 200) }
    }
}"#,
        refusal: r#"HTTPListener(on: ":8080") {
    Site(host: "*") {
        Fallback { Respond(body: "hello", status: 999999) }
    }
}"#,
        labels: crate::frontend::http::RESPOND_LABELS,
    },
    Entry {
        name: "tls",
        kind: Kind::Modifier,
        summary: "TLS for an HTTP listener: `.automatic`, `.internal` or `.files`.",
        example: r#"HTTPListener(on: ":8443") {
    Site(host: "localhost") { Fallback { Respond(body: "hello") } }
}
.tls(.internal)"#,
        refusal: r#"HTTPListener(on: ":8443") {
    Site(host: "localhost") { Fallback { Respond(body: "hello") } }
}
.tls(.acme(email: "admin@example.com"))"#,
        labels: &[],
    },
    Entry {
        name: "ServeFiles",
        kind: Kind::Component,
        summary: "Static files: `ServeFiles(root:, index:, browse:, hide:, precompressed:, status:, passThru:, …)`.",
        example: r#"HTTPListener(on: ":8080") {
    Site(host: "*") {
        Fallback { ServeFiles(root: "./public", browse: false) }
    }
}"#,
        refusal: r#"HTTPListener(on: ":8080") {
    Site(host: "*") {
        Fallback { ServeFiles(browse: true) }
    }
}"#,
        labels: crate::frontend::http::FILE_SERVER_LABELS,
    },
    Entry {
        name: "Proxy",
        kind: Kind::Component,
        summary: "Reverse proxy: `Proxy(to:, headersUp:, headersDown:)` with one address or a list.",
        example: r#"HTTPListener(on: ":8080") {
    Site(host: "*") {
        Fallback { Proxy(to: ["127.0.0.1:9000", "127.0.0.1:9001"]) }
    }
}"#,
        refusal: r#"HTTPListener(on: ":8080") {
    Site(host: "*") {
        Fallback { Proxy(to: []) }
    }
}"#,
        labels: &[],
    },
    Entry {
        name: "Redirect",
        kind: Kind::Component,
        summary: "A redirect: `Redirect(to:, status:)` with a typed status.",
        example: r#"HTTPListener(on: ":8080") {
    Site(host: "*") {
        Route(when: .path(prefix: "/old")) {
            Redirect(to: "/new", status: .permanent)
        }
    }
}"#,
        refusal: r#"HTTPListener(on: ":8080") {
    Site(host: "*") {
        Fallback { Redirect(to: "/new", status: .moved) }
    }
}"#,
        labels: crate::frontend::http::REDIRECT_LABELS,
    },
    Entry {
        name: "Fail",
        kind: Kind::Component,
        summary: "Raise an error response: `Fail(status:, message:)`.",
        example: r#"HTTPListener(on: ":8080") {
    Site(host: "*") {
        Fallback { Fail(status: 503, message: "maintenance") }
    }
}"#,
        refusal: r#"HTTPListener(on: ":8080") {
    Site(host: "*") {
        Fallback { Fail(status: 999999) }
    }
}"#,
        labels: crate::frontend::http::FAIL_LABELS,
    },
    Entry {
        name: "ServeMetrics",
        kind: Kind::Component,
        summary: "Answer with the Prometheus metrics endpoint.",
        example: r#"HTTPListener(on: ":8080") {
    Site(host: "*") {
        Route(when: .path(exact: "/metrics")) { ServeMetrics() }
    }
}"#,
        refusal: r#"HTTPListener(on: ":8080") {
    Site(host: "*") {
        Fallback { ServeMetrics(unknown: true) }
    }
}"#,
        labels: crate::frontend::http::METRICS_LABELS,
    },
    Entry {
        name: "accessLog",
        kind: Kind::Modifier,
        summary: "The listener's access log: `output` and `format`.",
        example: r#"HTTPListener(on: ":8080") {
    Site(host: "*") { Fallback { Respond(body: "hello") } }
}
.accessLog(output: .file("/tmp/access.log"), format: .json)"#,
        refusal: r#"HTTPListener(on: ":8080") {
    Site(host: "*") { Fallback { Respond(body: "hello") } }
}
.accessLog(output: .socket)"#,
        labels: crate::frontend::http::ACCESS_LOG_LABELS,
    },
    Entry {
        name: "RequestHeader",
        kind: Kind::Component,
        summary: "Sets request headers for later components: `.set`, `.append`, `.remove`, `.replace`.",
        example: r#"HTTPListener(on: ":8080") {
    Site(host: "*") {
        Fallback {
            RequestHeader(.set("X-Trace", "probe"), .append("X-Forwarded-For", "10.0.0.1"))
            Proxy(to: "127.0.0.1:9000")
        }
    }
}"#,
        refusal: r#"HTTPListener(on: ":8080") {
    Site(host: "*") {
        Fallback {
            RequestHeader(.setIfAbsent("X-Trace", "probe"))
            Proxy(to: "127.0.0.1:9000")
        }
    }
}"#,
        labels: &[],
    },
    Entry {
        name: "ResponseHeader",
        kind: Kind::Component,
        summary: "Rewrites the response on its way out: `.set`, `.append`, `.remove`, `.setIfAbsent`, `.replace`.",
        example: r#"HTTPListener(on: ":8080") {
    Site(host: "*") {
        Fallback {
            ResponseHeader(.setIfAbsent("X-Served-By", "pingclair"), .remove("Server"))
            Respond(body: "hello")
        }
    }
}"#,
        refusal: r#"HTTPListener(on: ":8080") {
    Site(host: "*") {
        Fallback {
            ResponseHeader(.replace("X-Served-By", pattern: "clair"))
            Respond(body: "hello")
        }
    }
}"#,
        labels: &[],
    },
    Entry {
        name: "Rewrite",
        kind: Kind::Component,
        summary: "One path or method edit, applied where it is written: `to:`, `stripPrefix:`, `stripSuffix:`, `path:`, `method:`.",
        example: r#"HTTPListener(on: ":8080") {
    Site(host: "*") {
        Route(when: .path(prefix: "/api")) {
            Rewrite(stripPrefix: "/api")
            Proxy(to: "127.0.0.1:9000")
        }
    }
}"#,
        refusal: r#"HTTPListener(on: ":8080") {
    Site(host: "*") {
        Fallback {
            Rewrite(to: "/new", method: .put)
            Respond(body: "hello")
        }
    }
}"#,
        labels: crate::frontend::http::REWRITE_LABELS,
    },
    Entry {
        name: "BasicAuth",
        kind: Kind::Component,
        summary: "Password-protected routes: `BasicAuth(users:, algorithm:, realm:)`.",
        example: r#"HTTPListener(on: ":8080") {
    Site(host: "*") {
        Route(when: .path(prefix: "/admin")) {
            BasicAuth(users: [.user("alice", hash: "$2y$04$BjuNmKvAV.mEi7.yFrazX.S6w6OO7H0BzQfyVVFZBq/qbVXCVNX4W")])
            Respond(body: "welcome")
        }
    }
}"#,
        refusal: r#"HTTPListener(on: ":8080") {
    Site(host: "*") {
        Fallback {
            BasicAuth(users: [.user("alice", hash: "plaintext-password")])
            Respond(body: "welcome")
        }
    }
}"#,
        labels: crate::frontend::http::BASIC_AUTH_LABELS,
    },
    Entry {
        name: "RateLimit",
        kind: Kind::Component,
        summary: "A request budget: `RateLimit(requests:, per:, key:, burst:, dryRun:)`.",
        example: r#"HTTPListener(on: ":8080") {
    Site(host: "*") {
        Route(when: .path(prefix: "/api")) {
            RateLimit(requests: 100, per: .minutes(1), key: .ip, burst: 10)
            Proxy(to: "127.0.0.1:9000")
        }
    }
}"#,
        refusal: r#"HTTPListener(on: ":8080") {
    Site(host: "*") {
        Fallback {
            RateLimit(requests: 0, per: .minutes(1))
            Respond(body: "hello")
        }
    }
}"#,
        labels: crate::frontend::http::RATE_LIMIT_LABELS,
    },
    Entry {
        name: "AccessControl",
        kind: Kind::Component,
        summary: "Allow and deny rules by address, referer, or user agent.",
        example: r#"HTTPListener(on: ":8080") {
    Site(host: "*") {
        Route(when: .path(prefix: "/internal")) {
            AccessControl(allowedIPs: ["10.0.0.0/8"], deniedUserAgents: ["(curl)"])
            Respond(body: "inside")
        }
    }
}"#,
        refusal: r#"HTTPListener(on: ":8080") {
    Site(host: "*") {
        Fallback {
            AccessControl()
            Respond(body: "hello")
        }
    }
}"#,
        labels: crate::frontend::http::ACCESS_CONTROL_LABELS,
    },
    Entry {
        name: "CORS",
        kind: Kind::Component,
        summary: "Cross-origin policy: `CORS(origins:, methods:, headers:, …)`.",
        example: r#"HTTPListener(on: ":8080") {
    Site(host: "*") {
        Route(when: .path(prefix: "/api")) {
            CORS(origins: ["https://example.com"], methods: [.get, .post], allowCredentials: true)
            Proxy(to: "127.0.0.1:9000")
        }
    }
}"#,
        refusal: r#"HTTPListener(on: ":8080") {
    Site(host: "*") {
        Fallback {
            CORS(origins: ["https://example.com"], methods: ["GET"])
            Respond(body: "hello")
        }
    }
}"#,
        labels: crate::frontend::http::CORS_LABELS,
    },
    Entry {
        name: "SetVariable",
        kind: Kind::Component,
        summary: "One request-scoped variable: `SetVariable(name:, value:)`.",
        example: r#"HTTPListener(on: ":8080") {
    Site(host: "*") {
        Route(when: .path(prefix: "/api")) {
            SetVariable(name: "tier", value: "free")
            Proxy(to: "127.0.0.1:9000")
        }
    }
}"#,
        refusal: r#"HTTPListener(on: ":8080") {
    Site(host: "*") {
        Fallback {
            SetVariable(name: "tier")
            Respond(body: "hello")
        }
    }
}"#,
        labels: crate::frontend::http::SET_VARIABLE_LABELS,
    },
    Entry {
        name: "LimitRequestBody",
        kind: Kind::Component,
        summary: "One route's body ceiling and deadlines: `LimitRequestBody(max:, …)`.",
        example: r#"HTTPListener(on: ":8080") {
    Site(host: "*") {
        Route(when: .path(exact: "/upload")) {
            LimitRequestBody(max: .mebibytes(10), readTimeout: .seconds(30))
            Respond(body: "stored")
        }
    }
}"#,
        refusal: r#"HTTPListener(on: ":8080") {
    Site(host: "*") {
        Fallback {
            LimitRequestBody(set: "")
            Respond(body: "hello")
        }
    }
}"#,
        labels: crate::frontend::http::LIMIT_BODY_LABELS,
    },
    Entry {
        name: "SkipLog",
        kind: Kind::Component,
        summary: "Leaves this request out of the access log.",
        example: r#"HTTPListener(on: ":8080") {
    Site(host: "*") {
        Route(when: .path(exact: "/health")) {
            SkipLog()
            Respond(body: "ok")
        }
    }
}"#,
        refusal: r#"HTTPListener(on: ":8080") {
    Site(host: "*") {
        Fallback {
            SkipLog(enabled: true)
            Respond(body: "hello")
        }
    }
}"#,
        labels: &[],
    },
    Entry {
        name: "Templates",
        kind: Kind::Component,
        summary: "Renders the files later components serve: `Templates(root:)`.",
        example: r#"HTTPListener(on: ":8080") {
    Site(host: "*") {
        Fallback {
            Templates(root: "./public")
            ServeFiles(root: "./public")
        }
    }
}"#,
        refusal: r#"HTTPListener(on: ":8080") {
    Site(host: "*") {
        Fallback {
            Templates()
        }
    }
}"#,
        labels: crate::frontend::http::TEMPLATES_LABELS,
    },
    Entry {
        name: "ForwardAuth",
        kind: Kind::Component,
        summary: "One auth round trip before the route continues: `ForwardAuth(to:, uri:, copyHeaders:)`.",
        example: r#"HTTPListener(on: ":8080") {
    Site(host: "*") {
        Route(when: .path(prefix: "/app")) {
            ForwardAuth(to: "127.0.0.1:9001", uri: "/verify", copyHeaders: ["X-User"])
            Proxy(to: "127.0.0.1:9000")
        }
    }
}"#,
        refusal: r#"HTTPListener(on: ":8080") {
    Site(host: "*") {
        Fallback {
            ForwardAuth(to: "127.0.0.1:9001")
            Respond(body: "hello")
        }
    }
}"#,
        labels: crate::frontend::http::FORWARD_AUTH_LABELS,
    },
    Entry {
        name: "ACMEServer",
        kind: Kind::Component,
        summary: "A site that answers ACME requests: `ACMEServer(ca:, lifetime:, allow:, deny:, …)`.",
        example: r#"HTTPListener(on: ":8080") {
    Site(host: "*") {
        Fallback {
            ACMEServer(ca: "local", lifetime: .hours(12), allow: .policy(domains: ["internal.example"]))
        }
    }
}"#,
        refusal: r#"HTTPListener(on: ":8080") {
    Site(host: "*") {
        Fallback {
            ACMEServer(allow: .policy(domains: []))
        }
    }
}"#,
        labels: crate::frontend::http::ACME_SERVER_LABELS,
    },
    Entry {
        name: "ErrorRoute",
        kind: Kind::Component,
        summary: "What to answer once a handler raised a status: `ErrorRoute(for: [.status(404), .serverError])`.",
        example: r#"HTTPListener(on: ":8080") {
    Site(host: "example.test") {
        Route(when: .path(prefix: "/api")) { Proxy(to: "127.0.0.1:9000") }
        ErrorRoute(for: [.status(404), .serverError]) {
            Respond(status: 404, body: "no such route")
        }
        Fallback { ServeFiles(root: "./public") }
    }
}"#,
        refusal: r#"HTTPListener(on: ":8080") {
    Site(host: "example.test") {
        ErrorRoute(for: [.success]) {
            Respond(status: 500, body: "never runs")
        }
        Fallback { ServeFiles(root: "./public") }
    }
}"#,
        labels: crate::frontend::http::ERROR_ROUTE_LABELS,
    },
    Entry {
        name: "errorPage",
        kind: Kind::Modifier,
        summary: "The file served for one error status: `.errorPage(for: [.status(404)], file: \"./404.html\")`.",
        example: r#"HTTPListener(on: ":8080") {
    Site(host: "*") {
        Fallback { ServeFiles(root: "./public") }
    }
    .errorPage(for: [.status(404)], file: "./errors/404.html")
}"#,
        refusal: r#"HTTPListener(on: ":8080") {
    Site(host: "*") {
        Fallback { ServeFiles(root: "./public") }
    }
    .errorPage(for: [.serverError], file: "./errors/500.html")
}"#,
        labels: crate::frontend::http::ERROR_PAGE_LABELS,
    },
    Entry {
        name: "TryFiles",
        kind: Kind::Component,
        summary: "Rewrites to the first candidate that exists, then lets the next component serve it: `TryFiles(candidates:, root:, policy:)`.",
        example: r#"HTTPListener(on: ":8080") {
    Site(host: "app.example.test") {
        Fallback {
            TryFiles(candidates: [.requestPath, .requestPath(appending: "/index.html"), "/index.html"], root: "./public")
            ServeFiles(root: "./public")
        }
    }
}"#,
        refusal: r#"HTTPListener(on: ":8080") {
    Site(host: "app.example.test") {
        Fallback {
            TryFiles(candidates: ["{path}"], root: "./public")
            ServeFiles(root: "./public")
        }
    }
}"#,
        labels: crate::frontend::http::TRY_FILES_LABELS,
    },
    Entry {
        name: "PHPFastCGI",
        kind: Kind::Component,
        summary: "PHP through FastCGI: `PHPFastCGI(to:, root:, index:, split:, env:, …)`.",
        example: r#"HTTPListener(on: ":8080") {
    Site(host: "app.example.test") {
        Fallback {
            PHPFastCGI(to: "unix//run/php-fpm.sock", root: "./public", env: [.env("APP_ENV", "production")])
        }
    }
}"#,
        refusal: r#"HTTPListener(on: ":8080") {
    Site(host: "app.example.test") {
        Fallback {
            PHPFastCGI(to: "unix//run/php-fpm.sock", split: [".phpé"])
        }
    }
}"#,
        labels: &[],
    },
    Entry {
        name: "Intercept",
        kind: Kind::Component,
        summary: "Rewrites the response of the components after it: `Intercept { Respond(when: …, …) }`.",
        example: r#"HTTPListener(on: ":8080") {
    Site(host: "app.example.test") {
        Fallback {
            Intercept {
                Response(when: .status(404)) {
                    Respond(status: 200, body: "soft 404")
                }
                Response(when: .status(.serverError)) {
                    ResponseHeader(.remove("Set-Cookie"))
                    CopyResponse(status: 503)
                }
            }
            Proxy(to: "127.0.0.1:9000")
        }
    }
}"#,
        refusal: r#"HTTPListener(on: ":8080") {
    Site(host: "app.example.test") {
        Fallback {
            Intercept {
                Response(when: .status(.serverError)) {
                    CopyResponseHeaders(include: ["Etag"], exclude: ["Set-Cookie"])
                    Respond(status: 503, body: "retry later")
                }
            }
            Proxy(to: "127.0.0.1:9000")
        }
    }
}"#,
        labels: &[],
    },
    Entry {
        name: "encode",
        kind: Kind::Modifier,
        summary: "The codings a site offers, most preferred first: `.encode(.zstd, .gzip)`.",
        example: r#"HTTPListener(on: ":8080") {
    Site(host: "*") {
        Fallback { ServeFiles(root: "./public") }
    }
    .encode(.zstd, .gzip)
}"#,
        refusal: r#"HTTPListener(on: ":8080") {
    Site(host: "*") {
        Fallback { ServeFiles(root: "./public") }
    }
    .encode(.br)
}"#,
        labels: &[],
    },
    Entry {
        name: "Admin",
        kind: Kind::Component,
        summary: "The admin endpoint; one declaration per file.",
        example: r#"Admin(listen: "127.0.0.1:2019")
TCPListener(on: "127.0.0.1:9443") { Fallback { Proxy(to: "127.0.0.1:8080") } }"#,
        refusal: r#"Admin(listen: "127.0.0.1:2019")
Admin(listen: "127.0.0.1:2020")
TCPListener(on: "127.0.0.1:9443") { Fallback { Proxy(to: "127.0.0.1:8080") } }"#,
        labels: &[],
    },
    Entry {
        name: "Metrics",
        kind: Kind::Component,
        summary: "The metrics collection switch.",
        example: r#"Metrics(enabled: true)
TCPListener(on: "127.0.0.1:9443") { Fallback { Proxy(to: "127.0.0.1:8080") } }"#,
        refusal: r#"Metrics(enabled: 1)
TCPListener(on: "127.0.0.1:9443") { Fallback { Proxy(to: "127.0.0.1:8080") } }"#,
        labels: &[],
    },
    Entry {
        name: "Shutdown",
        kind: Kind::Component,
        summary: "The shutdown grace period; whole seconds.",
        example: r#"Shutdown(grace: .seconds(5))
TCPListener(on: "127.0.0.1:9443") { Fallback { Proxy(to: "127.0.0.1:8080") } }"#,
        refusal: r#"Shutdown(grace: 5)
TCPListener(on: "127.0.0.1:9443") { Fallback { Proxy(to: "127.0.0.1:8080") } }"#,
        labels: &[],
    },
    Entry {
        name: "limits",
        kind: Kind::Modifier,
        summary: "Connection count and buffer bounds for a TCP listener.",
        example: r#"TCPListener(on: "127.0.0.1:9443") {
    Fallback { Proxy(to: "127.0.0.1:8080") }
}
.limits(connections: 1024, preread: .kibibytes(16), relay: .kibibytes(16))"#,
        refusal: r#"TCPListener(on: "127.0.0.1:9443") {
    Fallback { Proxy(to: "127.0.0.1:8080") }
}
.limits(connections: 0)"#,
        labels: &[],
    },
    Entry {
        name: "timeouts",
        kind: Kind::Modifier,
        summary: "Preread, connect, and idle deadlines for a TCP listener.",
        example: r#"TCPListener(on: "127.0.0.1:9443") {
    Fallback { Proxy(to: "127.0.0.1:8080") }
}
.timeouts(preread: .seconds(30), connect: .seconds(5), idle: .minutes(5))"#,
        refusal: r#"TCPListener(on: "127.0.0.1:9443") {
    Fallback { Proxy(to: "127.0.0.1:8080") }
}
.timeouts(connect: 5)"#,
        labels: &[],
    },
    Entry {
        name: "halfClose",
        kind: Kind::Modifier,
        summary: "Whether each direction propagates EOF independently.",
        example: r#"TCPListener(on: "127.0.0.1:9443") {
    Fallback { Proxy(to: "127.0.0.1:8080") }
}
.halfClose(enabled: true)"#,
        refusal: r#"TCPListener(on: "127.0.0.1:9443") {
    Fallback { Proxy(to: "127.0.0.1:8080") }
}
.halfClose(enabled: 1)"#,
        labels: &[],
    },
    Entry {
        name: "Matcher",
        kind: Kind::Attribute,
        summary: "Marks a condition binding so `when:` accepts it.",
        example: r#"@Matcher
let secure = .tls(sni: ["example.test"])
TCPListener(on: "127.0.0.1:9443") {
    Route(when: secure) { Proxy(to: "127.0.0.1:8443") }
}"#,
        refusal: r#"@Matcher
let secure = "text"
TCPListener(on: "127.0.0.1:9443") { Fallback { Proxy(to: "127.0.0.1:8080") } }"#,
        labels: &[],
    },
    Entry {
        name: "Secret",
        kind: Kind::Attribute,
        summary: "Marks a value binding as a secret; using one is refused until a field can hold it.",
        example: r#"@Secret
let token = "placeholder"
TCPListener(on: "127.0.0.1:9443") { Fallback { Proxy(to: "127.0.0.1:8080") } }"#,
        refusal: r#"@Secret
let backend = Proxy(to: "127.0.0.1:8080")
TCPListener(on: "127.0.0.1:9443") { Fallback { Proxy(to: "127.0.0.1:8080") } }"#,
        labels: &[],
    },
];

/// Finds an entry by name; attributes may be written with or without `@`.
pub fn find(name: &str) -> Option<&'static Entry> {
    ENTRIES.iter().find(|entry| {
        entry.name == name
            || (entry.kind == Kind::Attribute && name.strip_prefix('@') == Some(entry.name))
    })
}

fn select(name: Option<&str>) -> Result<Vec<&'static Entry>, String> {
    match name {
        None => Ok(ENTRIES.iter().collect()),
        Some(name) => {
            let entries: Vec<_> = ENTRIES
                .iter()
                .filter(|entry| {
                    entry.name == name
                        || (entry.kind == Kind::Attribute
                            && name.strip_prefix('@') == Some(entry.name))
                })
                .collect();
            if entries.is_empty() {
                Err(format!(
                    "unknown component '{name}'; run `pingclair describe` for the full list"
                ))
            } else {
                Ok(entries)
            }
        }
    }
}

/// Renders the entries for humans.
pub fn render_text(name: Option<&str>) -> Result<String, String> {
    let entries = select(name)?;
    let mut rendered = String::new();
    for (index, entry) in entries.iter().enumerate() {
        if index > 0 {
            rendered.push('\n');
        }
        rendered.push_str(&format!("{} — {}\n", entry.name, entry.kind.label()));
        rendered.push_str(&format!("  {}\n", entry.summary));
        rendered.push_str("  example:\n");
        for line in entry.example.lines() {
            rendered.push_str(&format!("    {line}\n"));
        }
        rendered.push_str("  refused:\n");
        for line in entry.refusal.lines() {
            rendered.push_str(&format!("    {line}\n"));
        }
    }
    Ok(rendered)
}

/// Renders the entries as JSON for tools and agents.
pub fn render_json(name: Option<&str>) -> Result<String, String> {
    let entries = select(name)?;
    let value = json!({
        "entries": entries
            .iter()
            .map(|entry| json!({
                "name": entry.name,
                "kind": entry.kind.label(),
                "summary": entry.summary,
                "example": entry.example,
                "refusal": entry.refusal,
                "labels": entry.labels,
            }))
            .collect::<Vec<_>>(),
    });
    serde_json::to_string_pretty(&value).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_example_compiles_and_every_refusal_is_refused() {
        for entry in ENTRIES {
            crate::compile(entry.example).unwrap_or_else(|error| {
                panic!("{} example failed to compile: {error}", entry.name)
            });
            assert!(
                crate::compile(entry.refusal).is_err(),
                "{} refusal compiled",
                entry.name
            );
        }
    }

    #[test]
    fn every_entry_names_itself_in_its_example() {
        for entry in ENTRIES {
            assert!(
                entry.example.contains(entry.name),
                "{} example does not name the entry",
                entry.name
            );
        }
    }

    /// 🏷️ The catalogue cannot silently drop a component's arguments.
    ///
    /// 📌 The review's complaint about a hand-written catalogue was that it
    /// promises a schema it cannot prove. The halves are now one constant: the
    /// parser validates against the list `describe` prints, so this test only
    /// has to insist that every component taking arguments was wired to one.
    #[test]
    fn every_component_that_takes_arguments_names_them() {
        for name in [
            "HTTPListener",
            "Site",
            "Respond",
            "ServeFiles",
            "Proxy",
            "Redirect",
            "Fail",
            "ServeMetrics",
            "Rewrite",
            "BasicAuth",
            "RateLimit",
            "AccessControl",
            "CORS",
            "SetVariable",
            "LimitRequestBody",
            "Templates",
            "ForwardAuth",
            "TryFiles",
            "ACMEServer",
            "ErrorRoute",
            "TCPListener",
            "Route",
            "errorPage",
            "accessLog",
        ] {
            let entry = find(name).unwrap_or_else(|| panic!("{name} is not described"));
            assert!(!entry.labels.is_empty(), "{name} names no arguments");
        }
        // …and the ones that take none say so by carrying none.
        for name in ["SkipLog", "Intercept", "Fallback"] {
            let entry = find(name).unwrap_or_else(|| panic!("{name} is not described"));
            assert!(entry.labels.is_empty(), "{name} should name no arguments");
        }
    }

    #[test]
    fn the_labels_are_the_parsers_own_lists() {
        // 🏷️ Not a copy: the same constants the frontend validates against.
        let proxy = find("Proxy").expect("described");
        assert_eq!(proxy.labels, crate::frontend::http::PROXY_LABELS);
        let files = find("ServeFiles").expect("described");
        assert_eq!(files.labels, crate::frontend::http::FILE_SERVER_LABELS);
    }

    #[test]
    fn lookups_accept_attributes_with_at_signs() {
        assert!(find("TCPListener").is_some());
        assert!(find("@Matcher").is_some());
        assert!(find("Matcher").is_some());
        assert!(find("tcpListener").is_none());
    }

    #[test]
    fn unknown_names_are_refused_with_the_list_hint() {
        let error = render_text(Some("Unknown")).unwrap_err();
        assert!(error.contains("unknown component 'Unknown'"), "{error}");
    }

    #[test]
    fn json_lists_every_entry() {
        let rendered = render_json(None).unwrap();
        for entry in ENTRIES {
            assert!(rendered.contains(entry.name), "json missing {}", entry.name);
        }
    }
}
