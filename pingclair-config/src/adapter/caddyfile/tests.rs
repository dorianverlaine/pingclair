// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧪 The adapter's end-to-end tests.
//!
//! These drive whole configurations through `compile`/`adapt` and assert on
//! the result, so they belong to no single layer. Tests that do belong to one
//! sit beside it — address semantics in [`super::addresses`], directive order
//! in [`super::sites`], the `log` block in [`super::logs`].

use super::*;

#[cfg(test)]
mod global_tests {
    use super::*;
    use crate::parser::parse;

    #[test]
    fn test_global_block_parsing() {
        let source = r#"{
            email admin@example.com
            auto_https off
            debug
        }"#;
        let directives = parse(source).unwrap();
        let ast = adapt(directives).unwrap();

        let global = ast.global.unwrap().inner;
        assert_eq!(global.email, Some("admin@example.com".to_string()));
        assert_eq!(global.auto_https, Some(AutoHttpsMode::Off));
        assert_eq!(global.debug, Some(true));
    }

    #[test]
    fn test_multi_listener_adaptation() {
        let source = ":8080 :8081 { respond \"Hello\" }";
        let directives = parse(source).unwrap();
        let ast = adapt(directives).unwrap();

        assert_eq!(ast.servers.len(), 1);
        let server = &ast.servers[0].inner;
        assert_eq!(server.listens.len(), 2);
        assert_eq!(server.listens[0].port, Some(8080));
        assert_eq!(server.listens[1].port, Some(8081));
    }

    #[test]
    fn test_snippet_expansion() {
        let source = r#"
            (security_headers) {
                header -Server
                header X-Content-Type-Options "nosniff"
            }

            example.com {
                listen :80
                import security_headers
                respond "Hello"
            }
        "#;
        let directives = parse(source).unwrap();
        let ast = adapt(directives).unwrap();

        assert_eq!(ast.servers.len(), 1);
        let server = &ast.servers[0].inner;
        // After expansion, the server should have handler directives from the snippet
        assert!(server.routes.is_some());
    }

    #[test]
    fn test_respond_with_status_code() {
        let source = r#"
            example.com {
                listen :80
                respond "Access Denied" 403
            }
        "#;
        let directives = parse(source).unwrap();
        let ast = adapt(directives).unwrap();

        let server = &ast.servers[0].inner;
        let routes = server.routes.as_ref().unwrap();
        let handler = &routes.inner.arms[0].inner.handler;
        if let Handler::Respond(cfg) = handler {
            assert_eq!(cfg.status, 403);
        } else {
            panic!("Expected Respond handler");
        }
    }

    #[test]
    fn test_reverse_proxy_block_parsing() {
        let source = r#"
            api.example.com {
                listen :80
                reverse_proxy 127.0.0.1:3000 {
                    header_up X-Forwarded-Proto https
                    header_up X-Real-IP {http.request.header.CF-Connecting-IP}
                    flush_interval -1
                    transport http {
                        read_timeout 300s
                        write_timeout 300s
                    }
                }
            }
        "#;
        let directives = parse(source).unwrap();
        let ast = adapt(directives).unwrap();

        let server = &ast.servers[0].inner;
        let routes = server.routes.as_ref().unwrap();
        let handler = &routes.inner.arms[0].inner.handler;
        if let Handler::Proxy(proxy) = handler {
            assert_eq!(proxy.upstreams, vec!["127.0.0.1:3000"]);
            assert!(proxy.header_up.contains_key("X-Forwarded-Proto"));
            assert!(proxy.header_up.contains_key("X-Real-IP"));
            assert!(matches!(
                proxy.flush_interval,
                Some(FlushInterval::Immediate)
            ));
            assert!(proxy.transport.is_some());
            let t = proxy.transport.as_ref().unwrap();
            assert_eq!(t.read_timeout, Some(300_000));
            assert_eq!(t.write_timeout, Some(300_000));
        } else {
            panic!("Expected Proxy handler");
        }
    }

    #[test]
    fn reverse_proxy_bare_path_is_a_matcher_not_an_upstream() {
        // 🧭 Caddy treats any leading `/` in the matcher position as a path
        // matcher: `/ws` proxies exactly that path (exact match, no `*`),
        // while every other request falls through to the file server.
        let routes = compiled_routes(
            r#"
            example.com {
                reverse_proxy /ws 127.0.0.1:9001
                file_server /var/www/html
            }
        "#,
        );

        let proxy = routes
            .iter()
            .find(|r| {
                matches!(
                    &r.handler,
                    pingclair_core::config::HandlerConfig::ReverseProxy(_)
                )
            })
            .expect("proxy route should exist");
        assert_eq!(proxy.path, "/ws", "bare /ws must scope the proxy route");
        match &proxy.handler {
            pingclair_core::config::HandlerConfig::ReverseProxy(proxy) => {
                assert_eq!(proxy.upstreams, vec!["127.0.0.1:9001".to_string()]);
            }
            other => panic!("expected a proxy handler, got {other:?}"),
        }

        let fs = routes
            .iter()
            .find(|r| {
                matches!(
                    &r.handler,
                    pingclair_core::config::HandlerConfig::FileServer { .. }
                )
            })
            .expect("file server route should exist");
        assert_eq!(
            fs.path, "/*",
            "file_server /var/www/html stays the catch-all"
        );
    }

    #[test]
    fn reverse_proxy_bare_path_matcher_works_with_to_block() {
        let routes = compiled_routes(
            r#"
            example.com {
                reverse_proxy /ws {
                    to 127.0.0.1:9001
                }
            }
        "#,
        );
        assert_eq!(routes.len(), 1, "only the /ws route should be emitted");
        assert_eq!(routes[0].path, "/ws");
        match &routes[0].handler {
            pingclair_core::config::HandlerConfig::ReverseProxy(proxy) => {
                assert_eq!(proxy.upstreams, vec!["127.0.0.1:9001".to_string()]);
            }
            other => panic!("expected a proxy handler, got {other:?}"),
        }
    }

    #[test]
    fn reverse_proxy_wildcard_token_stays_a_matcher() {
        // 🌐 `reverse_proxy * 127.0.0.1:9000` is Caddy's explicit spelling
        // of the default matcher; the `*` must not be dialed as an upstream.
        let routes = compiled_routes(
            r#"
            example.com {
                reverse_proxy * 127.0.0.1:9000
            }
        "#,
        );
        assert_eq!(
            routes.len(),
            1,
            "only the catch-all route should be emitted"
        );
        assert_eq!(routes[0].path, "/*");
        match &routes[0].handler {
            pingclair_core::config::HandlerConfig::ReverseProxy(proxy) => {
                assert_eq!(proxy.upstreams, vec!["127.0.0.1:9000".to_string()]);
            }
            other => panic!("expected a proxy handler, got {other:?}"),
        }
    }

    /// 🧪 Adapts one `reverse_proxy` source and returns its proxy handler.
    fn proxy_from(source: &str) -> ProxyConfig {
        let directives = parse(source).expect("parses");
        let ast = adapt(directives).expect("adapts");
        let routes = ast.servers[0].inner.routes.as_ref().expect("routes");
        match &routes.inner.arms[0].inner.handler {
            Handler::Proxy(proxy) => (**proxy).clone(),
            other => panic!("expected a Proxy handler, got {other:?}"),
        }
    }

    #[test]
    fn upstream_tls_directives_reach_the_transport_block() {
        // Setup scenarios
        let proxy = proxy_from(
            r#"
            api.example.com {
                listen :80
                reverse_proxy https://backend.internal:8443 {
                    transport http {
                        tls
                        tls_server_name origin.internal
                        tls_trusted_ca_certs /etc/pingclair/internal-ca.pem
                        tls_client_auth /etc/pingclair/client.crt /etc/pingclair/client.key
                    }
                }
            }
        "#,
        );

        // Verification
        let tls = &proxy.transport.as_ref().expect("transport").tls;
        assert!(tls.enable);
        assert_eq!(tls.server_name.as_deref(), Some("origin.internal"));
        assert_eq!(tls.trusted_ca_certs, vec!["/etc/pingclair/internal-ca.pem"]);
        assert_eq!(
            tls.client_cert.as_deref(),
            Some("/etc/pingclair/client.crt")
        );
        assert_eq!(tls.client_key.as_deref(), Some("/etc/pingclair/client.key"));
        assert!(
            !tls.insecure_skip_verify,
            "verification must stay on unless it is asked for by name"
        );
    }

    #[test]
    fn several_trusted_ca_bundles_accumulate_in_order() {
        // Setup scenarios
        let proxy = proxy_from(
            r#"
            :80 {
                reverse_proxy https://backend:8443 {
                    transport http {
                        tls_trusted_ca_certs /a.pem /b.pem
                        tls_trusted_ca_certs /c.pem
                    }
                }
            }
        "#,
        );

        // Verification
        assert_eq!(
            proxy
                .transport
                .as_ref()
                .expect("transport")
                .tls
                .trusted_ca_certs,
            vec!["/a.pem", "/b.pem", "/c.pem"]
        );
    }

    /// 🧪 Adapts a source expected to be rejected, returning the error.
    fn adapt_error(source: &str) -> AdapterError {
        let directives = parse(source).expect("parses");
        adapt(directives).expect_err("must be rejected")
    }

    #[test]
    fn a_lone_client_certificate_is_rejected_at_config_time() {
        // Setup scenarios & Verification
        //
        // Accepting this would produce an anonymous handshake, and the
        // upstream's rejection would arrive as an opaque TLS alert at the
        // first request rather than as a message about the config.
        let error = adapt_error(
            r#"
            :80 {
                reverse_proxy https://backend:8443 {
                    transport http { tls_client_auth /only.crt }
                }
            }
        "#,
        );
        assert!(
            matches!(&error, AdapterError::ArgumentCount(name, 2, 1) if name == "tls_client_auth"),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn skipping_verification_cannot_be_combined_with_pinned_roots() {
        // Setup scenarios & Verification
        let error = adapt_error(
            r#"
            :80 {
                reverse_proxy https://backend:8443 {
                    transport http {
                        tls_trusted_ca_certs /internal-ca.pem
                        tls_insecure_skip_verify
                    }
                }
            }
        "#,
        );
        let message = format!("{error}");
        assert!(
            message.contains("tls_trusted_ca_certs"),
            "the diagnostic must name the directive being cancelled: {message}"
        );
    }

    #[test]
    fn skipping_verification_cannot_be_combined_with_an_sni_override() {
        // Setup scenarios & Verification
        let error = adapt_error(
            r#"
            :80 {
                reverse_proxy https://backend:8443 {
                    transport http {
                        tls_server_name origin.internal
                        tls_insecure_skip_verify
                    }
                }
            }
        "#,
        );
        let message = format!("{error}");
        assert!(
            message.contains("tls_server_name"),
            "the diagnostic must name the directive being cancelled: {message}"
        );
    }

    #[test]
    fn a_bare_tls_flag_rejects_stray_arguments() {
        // Setup scenarios & Verification
        //
        // Caddy's `tls` inside `transport http` takes no arguments. Dropping
        // an argument silently would let a typo such as `tls off` read as
        // "enable TLS".
        let error = adapt_error(
            r#"
            :80 {
                reverse_proxy backend:8443 {
                    transport http { tls off }
                }
            }
        "#,
        );
        assert!(
            matches!(&error, AdapterError::ArgumentCount(name, 0, 1) if name == "tls"),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn test_http_url_address_parsing() {
        let source = r#"
            http://ai.408timeout.com:20615 {
                bind 127.0.0.1
                respond "OK"
            }
        "#;
        let directives = parse(source).unwrap();
        let ast = adapt(directives).unwrap();

        let server = &ast.servers[0].inner;
        assert_eq!(server.name, "ai.408timeout.com");
        assert_eq!(server.bind, Some("127.0.0.1".to_string()));
    }

    #[test]
    fn test_hostname_address_binds_wildcard_not_hostname() {
        // A named site address must not be bound literally: the listener
        // goes on all interfaces and the hostname is used for Host-header
        // routing (Caddy/nginx semantics). Binding the hostname itself
        // crashed startup for any name that doesn't resolve locally.
        let source = r#"
            bench.local:8080 {
                respond "OK"
            }
        "#;
        let directives = parse(source).unwrap();
        let ast = adapt(directives).unwrap();

        let server = &ast.servers[0].inner;
        assert_eq!(server.name, "bench.local");
        assert_eq!(server.listens.len(), 1);
        assert_eq!(server.listens[0].host, "[::]");
        assert_eq!(server.listens[0].port, Some(8080));
    }

    #[test]
    fn test_ip_literal_address_binds_to_that_ip() {
        // An IP literal *is* a bind address — only hostnames get the
        // bind-wildcard treatment.
        for (source, expected) in [
            ("127.0.0.1:8080 { respond \"OK\" }", "127.0.0.1"),
            ("192.168.1.10 { respond \"OK\" }", "192.168.1.10"),
        ] {
            let directives = parse(source).unwrap();
            let ast = adapt(directives).unwrap();
            let server = &ast.servers[0].inner;
            assert_eq!(
                server.listens[0].host, expected,
                "IP literal must stay the bind host"
            );
        }
    }

    #[test]
    fn test_servers_nested_global() {
        let source = r#"{
            servers {
                protocols h1 h2
            }
        }"#;
        let directives = parse(source).unwrap();
        let ast = adapt(directives).unwrap();
        let global = ast.global.unwrap().inner;
        assert_eq!(global.protocols.len(), 2);
        assert!(global.protocols.contains(&Protocol::H1));
        assert!(global.protocols.contains(&Protocol::H2));
    }

    #[test]
    fn test_nested_import() {
        let source = r#"
            (inner) {
                header X-Inner "true"
            }
            (outer) {
                import inner
                header X-Outer "true"
            }
            example.com {
                listen :80
                import outer
            }
        "#;
        let directives = parse(source).unwrap();
        let ast = adapt(directives).unwrap();
        assert_eq!(ast.servers.len(), 1);
    }

    #[test]
    fn test_header_deletion_syntax() {
        let source = r#"
            example.com {
                listen :80
                header {
                    -Server
                    X-Content-Type-Options "nosniff"
                }
            }
        "#;
        let directives = parse(source).unwrap();
        let ast = adapt(directives).unwrap();
        let server = &ast.servers[0].inner;
        let routes = server.routes.as_ref().unwrap();
        let handler = &routes.inner.arms[0].inner.handler;
        if let Handler::Headers(cfg) = handler {
            assert!(cfg.remove.contains(&"Server".to_string()));
            assert!(cfg.set.contains_key("X-Content-Type-Options"));
        } else {
            panic!("Expected Headers handler, got {handler:?}");
        }
    }

    #[test]
    fn test_header_wildcard_matcher() {
        // Caddy: `header Cf-Access-Jwt-Assertion *` means header exists
        let source = r#"
            example.com {
                listen :80
                @cf_access {
                    header Cf-Access-Jwt-Assertion *
                }
                handle @cf_access {
                    respond "OK"
                }
            }
        "#;
        let directives = parse(source).unwrap();
        let ast = adapt(directives).unwrap();
        let server = &ast.servers[0].inner;
        assert!(server.matchers.contains_key("@cf_access"));
    }

    // ---- Regression: `handle`/`route` with an inline path matcher ----
    //
    // `handle /api/*` and `route "/api/*"` must keep their path. The old
    // adapter only recognised `@name` matchers, so an inline path was
    // dropped and the block collapsed into the server's catch-all — every
    // request matched it regardless of URL. These use the full public
    // `compile()` pipeline so they assert the final RouteConfig.path, which
    // is what the runtime router actually keys on.

    fn compiled_routes(source: &str) -> Vec<pingclair_core::config::RouteConfig> {
        crate::compile(source).unwrap().servers.remove(0).routes
    }

    #[test]
    fn handle_with_inline_path_keeps_its_path() {
        let routes = compiled_routes(
            r#"
            :8080 {
                handle /proxy/* {
                    reverse_proxy 127.0.0.1:9000
                }
                file_server /var/www/html
            }
        "#,
        );

        // The proxy route must be keyed on /proxy/*, NOT collapsed to /*.
        let proxy = routes
            .iter()
            .find(|r| {
                matches!(
                    &r.handler,
                    pingclair_core::config::HandlerConfig::ReverseProxy(_)
                        | pingclair_core::config::HandlerConfig::Handle { .. }
                        | pingclair_core::config::HandlerConfig::Pipeline { .. }
                )
            })
            .expect("proxy route should exist");
        assert_eq!(proxy.path, "/proxy/*", "handle /proxy/* lost its path");

        // The bare file_server is the catch-all.
        let fs = routes
            .iter()
            .find(|r| {
                matches!(
                    &r.handler,
                    pingclair_core::config::HandlerConfig::FileServer { .. }
                )
            })
            .expect("file_server route should exist");
        assert_eq!(fs.path, "/*");
    }

    #[test]
    fn route_with_quoted_path_keeps_its_path() {
        let routes = compiled_routes(
            r#"
            example.com {
                route "/api/*" {
                    respond "api" 200
                }
                route "/health" {
                    respond "ok" 200
                }
            }
        "#,
        );
        let paths: Vec<_> = routes.iter().map(|r| r.path.as_str()).collect();
        assert!(
            paths.contains(&"/api/*"),
            "route \"/api/*\" lost its path; got {paths:?}"
        );
        assert!(
            paths.contains(&"/health"),
            "route \"/health\" lost its path; got {paths:?}"
        );
    }

    #[test]
    fn bare_file_server_root_is_not_mistaken_for_a_matcher() {
        // `file_server /var/www/html` at server level: the leading-'/' arg
        // is the ROOT, not a path matcher. It must stay the catch-all and
        // keep its root — the scoped fix must not leak into this branch.
        let routes = compiled_routes(
            r#"
            :8080 {
                file_server /var/www/html
            }
        "#,
        );
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].path, "/*");
        match &routes[0].handler {
            pingclair_core::config::HandlerConfig::FileServer { root, .. } => {
                assert_eq!(
                    root, "/var/www/html",
                    "file_server root was swallowed as a matcher"
                );
            }
            other => panic!("expected FileServer, got {other:?}"),
        }
    }

    // ---- tls server directive ----

    #[test]
    fn test_tls_cert_key() {
        let source = r#"
            example.com {
                listen :443
                tls /etc/ssl/cert.pem /etc/ssl/key.pem
            }
        "#;
        let directives = parse(source).unwrap();
        let ast = adapt(directives).unwrap();

        let tls = ast.servers[0].inner.tls.as_ref().expect("tls directive");
        assert_eq!(tls.cert.as_deref(), Some("/etc/ssl/cert.pem"));
        assert_eq!(tls.key.as_deref(), Some("/etc/ssl/key.pem"));
        assert!(!tls.auto);
        assert!(!tls.off);
    }

    #[test]
    fn test_tls_auto() {
        let source = r#"
            example.com {
                listen :443
                tls auto
            }
        "#;
        let directives = parse(source).unwrap();
        let ast = adapt(directives).unwrap();

        let tls = ast.servers[0].inner.tls.as_ref().expect("tls directive");
        assert!(tls.auto);
        assert!(tls.cert.is_none());
    }

    #[test]
    fn test_tls_internal() {
        let source = r#"
            example.com {
                listen :443
                tls internal
            }
        "#;
        let directives = parse(source).unwrap();
        let ast = adapt(directives).unwrap();

        let tls = ast.servers[0].inner.tls.as_ref().expect("tls directive");
        assert!(tls.internal);
        assert!(!tls.auto);
        assert!(tls.cert.is_none());
    }

    #[test]
    fn test_tls_internal_block_can_disable_http3() {
        let source = r#"
            example.com {
                listen :443
                tls {
                    internal
                    http3 off
                }
            }
        "#;
        let directives = parse(source).unwrap();
        let ast = adapt(directives).unwrap();

        let tls = ast.servers[0].inner.tls.as_ref().expect("tls directive");
        assert!(tls.internal);
        assert_eq!(tls.http3, Some(false));
    }

    #[test]
    fn test_tls_internal_rejects_public_or_manual_issuers() {
        for source in [
            "example.com { tls { internal auto } }",
            "example.com { tls { internal acme_email admin@example.com } }",
            "example.com { tls { internal cert cert.pem key key.pem } }",
        ] {
            let directives = parse(source).unwrap();
            assert!(matches!(
                adapt(directives),
                Err(AdapterError::InvalidArgument(..))
            ));
        }
    }

    #[test]
    fn test_tls_off() {
        let source = r#"
            example.com {
                listen :443
                tls off
            }
        "#;
        let directives = parse(source).unwrap();
        let ast = adapt(directives).unwrap();

        let tls = ast.servers[0].inner.tls.as_ref().expect("tls directive");
        assert!(tls.off);
    }

    #[test]
    fn test_tls_block_form() {
        let source = r#"
            example.com {
                listen :443
                tls {
                    cert /etc/ssl/cert.pem
                    key /etc/ssl/key.pem
                    acme_email admin@example.com
                    http3
                }
            }
        "#;
        let directives = parse(source).unwrap();
        let ast = adapt(directives).unwrap();

        let tls = ast.servers[0].inner.tls.as_ref().expect("tls directive");
        assert_eq!(tls.cert.as_deref(), Some("/etc/ssl/cert.pem"));
        assert_eq!(tls.key.as_deref(), Some("/etc/ssl/key.pem"));
        assert_eq!(tls.acme_email.as_deref(), Some("admin@example.com"));
        assert_eq!(tls.http3, Some(true));
    }

    #[test]
    fn test_tls_cert_without_key_is_an_error() {
        let source = r#"
            example.com {
                listen :443
                tls /etc/ssl/cert.pem
            }
        "#;
        let directives = parse(source).unwrap();
        let result = adapt(directives);
        assert!(matches!(result, Err(AdapterError::InvalidArgument(..))));
    }

    // ---- Global admin directive ----

    #[test]
    fn test_admin_listen() {
        let source = r#"{
            admin 127.0.0.1:2019
        }"#;
        let directives = parse(source).unwrap();
        let ast = adapt(directives).unwrap();

        let admin = ast.global.unwrap().inner.admin.expect("admin directive");
        assert_eq!(admin.listen, "127.0.0.1:2019");
        assert!(admin.enabled);
    }

    #[test]
    fn test_admin_off() {
        let source = r#"{
            admin off
        }"#;
        let directives = parse(source).unwrap();
        let ast = adapt(directives).unwrap();

        let admin = ast.global.unwrap().inner.admin.expect("admin directive");
        assert!(!admin.enabled);
    }

    /// 🌐 `admin` with a block but no address keeps the default endpoint,
    /// the way Caddy parses it — an origin allowlist is not a reason to
    /// demand an address the format does not.
    #[test]
    fn test_admin_without_an_address_uses_the_default_listen() {
        let source = r#"{
            admin {
                origins localhost:2019
            }
        }"#;
        let directives = parse(source).unwrap();
        let ast = adapt(directives).unwrap();

        let admin = ast.global.unwrap().inner.admin.expect("admin directive");
        assert_eq!(admin.listen, "127.0.0.1:2019");
        assert!(admin.enabled);
        assert_eq!(admin.origins, ["localhost:2019"]);
    }
}

// MARK: - P1 Fail-Closed Tests

/// 🛡️ Every P1 regression: a config that used to compile while silently
/// dropping part of what the operator asked for must now fail loudly.
#[cfg(test)]
mod fail_closed_tests {
    fn compile_err(source: &str) -> String {
        match crate::compile(source) {
            Ok(_) => panic!("config unexpectedly compiled:\n{source}"),
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn log_block_rejects_unknown_subdirectives() {
        let error = compile_err(
            r#"example.com {
                log {
                    rotate 7d
                }
            }"#,
        );
        assert!(
            error.contains("log: rotate"),
            "unknown log subdirective must be named; got {error}"
        );
    }

    /// 🔄 Caddy puts rotation on the destination: `output file <path> { … }`.
    ///
    /// This block used to be parsed and discarded, so the configuration below
    /// validated green and then never rotated anything — the log grew until
    /// the device filled. Day 26 measured it against Caddy 2.11.4, which
    /// compiles the same source to `roll_size_mb: 1, roll_keep: 3`.
    #[test]
    fn caddy_style_roll_settings_reach_the_rotation_config() {
        let config = crate::compile(
            r#"example.com {
                log {
                    output file /var/log/access.log {
                        roll_size 1mb
                        roll_keep 3
                    }
                }
            }"#,
        )
        .expect("Caddy's own rotation syntax must compile");
        let rotation = config.servers[0]
            .log
            .as_ref()
            .expect("log block")
            .rotation
            .clone();
        assert_eq!(rotation.max_size_bytes, Some(1024 * 1024));
        assert_eq!(rotation.keep, Some(3));
        // 📌 Caddy compresses rotated files unless told not to, so a `roll_`
        // block without `roll_uncompressed` means compression on.
        assert!(rotation.compress, "Caddy compresses unless opted out");
    }

    /// 🚫 The same block must not swallow a typo. Caddy answers
    /// `unrecognized subdirective … at <file>:<line>`; silence here would put
    /// the setting back in the category this whole path exists to leave.
    #[test]
    fn caddy_style_roll_block_rejects_unknown_subdirectives() {
        let error = compile_err(
            r#"example.com {
                log {
                    output file /var/log/access.log {
                        roll_sizes 1mb
                    }
                }
            }"#,
        );
        assert!(
            error.contains("roll_sizes"),
            "the offending subdirective must be named; got {error}"
        );
    }

    /// 🎯 `header /path Field value` scopes the header to that path.
    ///
    /// The exact-path form used to *compile* into nonsense: the path stayed in
    /// the argument list, where the field name is read from, producing a header
    /// literally named `/exact` with the field name as its value and the real
    /// value dropped. That name is not a legal header name, so the request got
    /// no response at all — a configuration that validated cleanly and then
    /// could not serve.
    ///
    /// No argument-count condition disambiguates this, and none is needed: an
    /// HTTP field name cannot contain `/`.
    #[test]
    fn header_takes_an_exact_path_matcher() {
        let config = crate::compile(
            r#"example.com {
                header /exact X-Test scoped
                respond "body"
            }"#,
        )
        .expect("must compile");
        let scoped = config.servers[0]
            .routes
            .iter()
            .find(|r| r.matcher.is_some())
            .expect("the path must become a matcher, not a field name");
        let rendered = format!("{:?}", scoped.handler);
        assert!(
            rendered.contains("X-Test") && rendered.contains("scoped"),
            "the field and its value must both survive: {rendered}"
        );
        assert!(
            !rendered.contains("\"/exact\""),
            "the path must not become a header name: {rendered}"
        );
    }

    #[test]
    fn log_block_rejects_unknown_format() {
        let error = compile_err(
            r#"example.com {
                log {
                    format jsno
                }
            }"#,
        );
        assert!(
            error.contains("jsno"),
            "`format jsno` must name the unknown format; got {error}"
        );
    }

    #[test]
    fn log_block_rejects_output_file_without_path() {
        let error = compile_err(
            r#"example.com {
                log {
                    output file
                }
            }"#,
        );
        assert!(
            error.contains("log output file"),
            "`output file` without a path must fail; got {error}"
        );
    }

    #[test]
    fn file_server_rejects_precompressed_as_unsupported() {
        let error = compile_err(
            r#"example.com {
                file_server /downloads/* {
                    precompressed
                }
            }"#,
        );
        assert!(
            error.contains("not supported by Pingclair"),
            "precompressed must be reported as unsupported Caddy syntax; got {error}"
        );
    }

    #[test]
    fn file_server_rejects_fs_as_unsupported() {
        let error = compile_err(
            r#"example.com {
                file_server /database/* {
                    fs sqlite data.sql
                }
            }"#,
        );
        assert!(
            error.contains("not supported by Pingclair"),
            "fs must be reported as unsupported Caddy syntax; got {error}"
        );
    }

    #[test]
    fn reverse_proxy_rejects_header_down_as_unsupported() {
        let error = compile_err(
            r#"example.com {
                reverse_proxy localhost:8080 {
                    header_down X-Foo bar
                }
            }"#,
        );
        assert!(
            error.contains("header_down") && error.contains("not supported"),
            "header_down must fail with a named unsupported error; got {error}"
        );
    }

    #[test]
    fn reverse_proxy_rejects_dynamic_as_unsupported() {
        let error = compile_err(
            r#"example.com {
                reverse_proxy /api/* {
                    dynamic srv _api._tcp.example.com
                }
            }"#,
        );
        assert!(
            error.contains("dynamic") && error.contains("not supported"),
            "dynamic must fail with a named unsupported error; got {error}"
        );
    }

    #[test]
    fn reverse_proxy_rejects_unknown_subdirectives() {
        let error = compile_err(
            r#"example.com {
                reverse_proxy localhost:8080 {
                    lb_try_duratoin 10s
                }
            }"#,
        );
        assert!(
            error.contains("lb_try_duratoin") && error.contains("Unknown"),
            "a typo must be named and read as a typo; got {error}"
        );
    }

    /// 🚫 A reverse-proxy option the format defines but this proxy does not
    /// implement must not read as a typo.
    ///
    /// The two need different things from the operator — one is a misspelling
    /// to correct, the other a feature to work around — and until this
    /// distinction existed both arrived as "unknown".
    #[test]
    fn reverse_proxy_names_options_it_recognises_but_lacks() {
        let error = compile_err(
            r#"example.com {
                reverse_proxy localhost:8080 {
                    request_buffers 4KB
                }
            }"#,
        );
        assert!(
            error.contains("request_buffers") && error.contains("does not implement"),
            "a real option must be reported as missing, not unknown; got {error}"
        );
    }

    /// 🛣️ `handle_path` strips the matched prefix before its handlers run.
    ///
    /// The runtime has done this the whole time, on both transports — only the
    /// adapter arm was missing, so a directive this server could already
    /// execute was reported as unimplemented. That is the shape the milestone's
    /// grading pass was looking for: a type existing is not a feature existing,
    /// and a feature existing is not a feature reachable.
    #[test]
    fn handle_path_strips_the_prefix_it_matched() {
        let config = crate::compile(
            "example.com {\n    handle_path /api/* {\n        respond \"stripped\" 200\n    }\n                 respond \"root\"\n}",
        )
        .expect("handle_path must compile");
        let route = config.servers[0]
            .routes
            .iter()
            .find(|route| route.path == "/api/*")
            .expect("the matched route");
        match &route.handler {
            pingclair_core::config::HandlerConfig::HandlePath { prefix, handlers } => {
                // 🧭 The glob is not part of the prefix: stripping `/api/*`
                // would leave a prefix nothing starts with.
                assert_eq!(prefix, "/api");
                assert_eq!(handlers.len(), 1);
            }
            other => panic!("expected a handle_path handler, got {other:?}"),
        }
    }

    /// 🚫 Without a path there is nothing to strip, and `handle` already means
    /// "group these without stripping".
    #[test]
    fn handle_path_without_a_path_is_refused() {
        let error =
            compile_err("example.com {\n    handle_path {\n        respond \"x\"\n    }\n}");
        assert!(error.contains("handle_path"), "got {error}");
    }

    /// 🔤 `header_regexp` matches a header against a regular expression.
    ///
    /// Everything it needs already existed — the condition, its compilation,
    /// and the router's compiled-regex cache. Only the adapter arm was
    /// missing, which is why three corpus configurations failed on a feature
    /// this crate could already execute.
    #[test]
    fn header_regexp_compiles_into_a_regex_condition() {
        let config = crate::compile(
            "example.com {\n    @mobile header_regexp User-Agent (?i)android\n                 respond @mobile \"mobile\" 200\n    respond \"desktop\"\n}",
        )
        .expect("header_regexp must compile");
        let matched = config.servers[0]
            .routes
            .iter()
            .find(|route| route.matcher.is_some())
            .expect("a matched route");
        match matched.matcher.as_ref().expect("a matcher") {
            pingclair_core::config::Matcher::Header { name, condition } => {
                assert_eq!(name, "User-Agent");
                assert_eq!(
                    condition,
                    &pingclair_core::config::MatcherCondition::Regex("(?i)android".into())
                );
            }
            other => panic!("expected a header matcher, got {other:?}"),
        }
    }

    /// 🚫 A pattern that cannot compile is refused while the operator is still
    /// looking at the line they wrote. Left alone it would load green and then
    /// match nothing for the lifetime of the server — a route that silently
    /// never fires.
    #[test]
    fn an_unparseable_header_regexp_is_refused() {
        let error = compile_err(
            "example.com {\n    @x header_regexp User-Agent \"(unclosed\"\n                 respond @x \"y\"\n}",
        );
        assert!(
            error.contains("not a valid regular expression"),
            "got {error}"
        );
    }

    /// 🚫 The three-argument form names capture groups so they can be read back
    /// as placeholders. We produce no placeholders from matchers, so accepting
    /// the name would accept a configuration whose whole point is a value we
    /// never generate.
    #[test]
    fn a_named_capture_group_is_refused_rather_than_ignored() {
        let error = compile_err(
            "example.com {\n    @x header_regexp mobile User-Agent android\n                 respond @x \"y\"\n}",
        );
        assert!(error.contains("capture-group name"), "got {error}");
    }

    /// 🩺 Health checking spelled flat, which is how the format spells it.
    #[test]
    fn flat_health_options_configure_the_health_check() {
        let config = crate::compile(
            r#"example.com {
                reverse_proxy localhost:8080 {
                    health_uri /healthz
                    health_interval 10s
                    health_timeout 2s
                    health_status 2xx
                    health_passes 3
                    health_fails 2
                    lb_retries 5
                }
            }"#,
        )
        .expect("the flat spelling must compile");
        match &config.servers[0].routes[0].handler {
            pingclair_core::config::HandlerConfig::ReverseProxy(proxy) => {
                let check = proxy.health_check.as_ref().expect("a health check");
                assert_eq!(check.path, "/healthz");
                assert_eq!(check.interval, 10);
                assert_eq!(check.timeout, 2);
                assert_eq!(check.consecutive_success, 3);
                assert_eq!(check.consecutive_failure, Some(2));
                // 🧭 `2xx` stands for the whole hundred, so an operator can say
                // "any success" without listing five codes.
                assert!(check.expected_statuses.contains(&200));
                assert!(check.expected_statuses.contains(&204));
                assert!(!check.expected_statuses.contains(&301));
                assert_eq!(proxy.retry.max_attempts, 5);
            }
            other => panic!("expected a proxy handler, got {other:?}"),
        }
    }

    #[test]
    fn reverse_proxy_rejects_header_up_with_extra_arguments() {
        let error = compile_err(
            r#"example.com {
                reverse_proxy localhost:8080 {
                    header_up X-Foo a b
                }
            }"#,
        );
        assert!(
            error.contains("header_up"),
            "a third header_up argument must fail; got {error}"
        );
    }

    #[test]
    fn reverse_proxy_rejects_unix_socket_upstream() {
        let error = compile_err(
            r#"example.com {
                reverse_proxy unix//run/php/php.sock
            }"#,
        );
        assert!(
            error.contains("Unix-socket"),
            "unix// upstream must be refused with a clear message; got {error}"
        );
    }

    #[test]
    fn reverse_proxy_path_matcher_inside_handle_compiles_scoped() {
        let config = crate::compile(
            r#"example.com {
                handle /ws {
                    reverse_proxy /ws 127.0.0.1:9001
                }
            }"#,
        )
        .expect("a matcher on a directive inside handle must compile");
        let route = &config.servers[0].routes[0];
        assert_eq!(
            route.path, "/ws",
            "the container matcher must stay on the route"
        );
        let pingclair_core::config::HandlerConfig::Handle { handlers } = &route.handler else {
            panic!("handle must compile to a Handle group");
        };
        let element = handlers
            .iter()
            .find(|element| {
                matches!(
                    &element.handler,
                    pingclair_core::config::HandlerConfig::ReverseProxy(_)
                )
            })
            .expect("reverse proxy element");
        assert!(
            matches!(
                &element.matcher,
                Some(pingclair_core::config::Matcher::Path { patterns })
                    if patterns == &["/ws".to_string()]
            ),
            "the inner /ws must become the element matcher, got {:?}",
            element.matcher
        );
    }

    #[test]
    fn site_address_rejects_port_range() {
        let error = compile_err("localhost:8080-8085 {\n    respond \"x\"\n}");
        assert!(
            error.contains("port range") || error.contains("not supported"),
            "a port-range site address must fail; got {error}"
        );
    }

    #[test]
    fn site_address_rejects_network_prefix() {
        let error = compile_err("tcp/localhost:8080 {\n    respond \"x\"\n}");
        assert!(
            error.contains("network prefix") || error.contains("not supported"),
            "a tcp/ site address must fail; got {error}"
        );
    }

    #[test]
    fn debug_rejects_arguments() {
        let error = compile_err("{\n    debug fales\n}\nexample.com {\n    respond \"x\"\n}");
        assert!(
            error.contains("debug"),
            "`debug fales` must fail; got {error}"
        );
    }

    #[test]
    fn auto_https_requires_an_argument() {
        let error = compile_err("{\n    auto_https\n}\nexample.com {\n    respond \"x\"\n}");
        assert!(
            error.contains("auto_https"),
            "bare auto_https must fail; got {error}"
        );
    }

    #[test]
    fn auto_https_disable_certs_is_reported_as_unsupported() {
        let error =
            compile_err("{\n    auto_https disable_certs\n}\nexample.com {\n    respond \"x\"\n}");
        assert!(
            error.contains("not supported by Pingclair"),
            "disable_certs must be reported as unsupported Caddy syntax; got {error}"
        );
    }

    #[test]
    fn method_matcher_rejects_unknown_verbs() {
        let error =
            compile_err("example.com {\n    @x method FOO\n    handle @x { respond \"x\" }\n}");
        assert!(
            error.contains("FOO"),
            "unknown method must be named; got {error}"
        );
    }

    #[test]
    fn method_matcher_accepts_every_standard_verb() {
        let config = crate::compile(
            r#"example.com {
                @x method GET POST PUT DELETE PATCH HEAD OPTIONS
                handle @x { respond "x" }
            }"#,
        )
        .expect("all standard verbs must compile");
        assert_eq!(config.servers[0].routes.len(), 1);
    }

    #[test]
    fn header_matcher_rejects_extra_arguments() {
        let error = compile_err(
            "example.com {\n    @x header Foo bar baz\n    handle @x { respond \"x\" }\n}",
        );
        assert!(
            error.contains("header"),
            "a third header-matcher argument must fail; got {error}"
        );
    }

    #[test]
    fn header_directive_rejects_key_without_value() {
        let error = compile_err("example.com {\n    header X-Only\n}");
        assert!(
            error.contains("header"),
            "`header X-Only` without a value must fail; got {error}"
        );
    }

    #[test]
    fn admin_block_rejects_unknown_subdirectives() {
        // 🌐 `origins` and `enforce_origin` are implemented as of Day 24, so
        // this test no longer asserts the whole block is refused — it asserts
        // the fail-closed property that *survives* implementation: a
        // subdirective nobody implemented must still be named, not dropped.
        let error = compile_err(
            r#"{
                admin :2019 {
                    origins http://localhost:2019
                    orgins http://typo.example
                }
            }
            example.com {
                respond "x"
            }"#,
        );
        assert!(
            error.contains("orgins"),
            "an unknown admin subdirective must be named; got {error}"
        );
    }

    #[test]
    fn known_caddy_global_options_are_reported_as_unsupported() {
        let error =
            compile_err("{\n    default_bind 127.0.0.1\n}\nexample.com {\n    respond \"x\"\n}");
        assert!(
            error.contains("not supported by Pingclair"),
            "default_bind must be reported as unsupported Caddy syntax; got {error}"
        );
    }

    #[test]
    fn known_caddy_directives_are_reported_as_unsupported() {
        let error = compile_err("example.com {\n    php_fastcgi localhost:9000\n}");
        assert!(
            error.contains("not supported by Pingclair") || error.contains("Unknown directive"),
            "php_fastcgi must be rejected; got {error}"
        );
    }

    #[test]
    fn typo_directives_stay_unknown_directive_errors() {
        let error = compile_err("example.com {\n    respnd \"x\"\n}");
        assert!(
            error.contains("Unknown directive 'respnd'"),
            "a typo must remain an unknown-directive error; got {error}"
        );
    }

    /// 🎯 A matcher on `encode` must be refused for the reason it is actually
    /// refused for.
    ///
    /// Compression here belongs to the server, so "compress only under this
    /// path" has nowhere to go. The failure was already correct; the *message*
    /// was not. It read `unknown coding /exact`, which points at the one thing
    /// in the line that is spelled exactly right and sends the operator hunting
    /// for a typo instead of restructuring the site.
    #[test]
    fn encode_with_a_matcher_explains_that_compression_is_per_server() {
        for source in [
            "example.com {\n    encode /exact gzip\n}",
            "example.com {\n    encode /assets/* gzip\n}",
            "example.com {\n    @static path /static/*\n    encode @static gzip\n}",
        ] {
            let error = compile_err(source);
            assert!(
                !error.contains("unknown coding"),
                "the matcher must not be reported as a coding; got {error}"
            );
            assert!(
                error.contains("per server"),
                "the error must say compression is a server property; got {error}"
            );
        }
    }

    /// 🌐 `*` is the matcher that matches everything, so it says nothing that
    /// the absence of a matcher does not already say. It compiles, and the
    /// codings after it are still read.
    #[test]
    fn encode_accepts_the_match_everything_token() {
        let config = crate::compile("example.com {\n    encode * zstd gzip\n}")
            .expect("`encode * zstd gzip` must compile");
        let encodings = &config.servers[0].encodings;
        assert_eq!(
            encodings,
            &[
                pingclair_core::config::Encoding::Zstd,
                pingclair_core::config::Encoding::Gzip
            ],
            "the codings after `*` must survive, in order"
        );
    }

    /// 🎯 A `respond` with nothing to respond with is refused, in all three
    /// spellings the matcher rule can produce.
    ///
    /// This used to compile to "200, empty body". The reason it must not is
    /// that `respond /health` has two readings and this project has shipped
    /// both: first the path became the response *text*, then it became a
    /// matcher with an empty body. Neither reading is more obviously right, so
    /// the config is ambiguous and the load is where that gets said.
    #[test]
    fn respond_without_a_status_or_body_is_refused() {
        for source in [
            "example.com {\n    respond\n}",
            "example.com {\n    respond /health\n}",
            "example.com {\n    @api path /api/*\n    respond @api\n}",
        ] {
            let error = compile_err(source);
            assert!(
                error.contains("status code") && error.contains("body"),
                "the error must say what is missing; got {error}"
            );
        }
    }

    /// 🎯 The first cursor-driven directive must agree with the string path it
    /// replaced, including where the two deliberately disagree.
    ///
    /// A snippet argument is that case. `import comp gzip` substitutes `gzip`
    /// into the directive's *text*, so the tokens in the file still say
    /// `{args[0]}` while `args` says `gzip`. A cursor that read the tokens here
    /// would report an unknown coding named `{args[0]}` — so a synthesised
    /// directive carries no token run, and the parser falls back. This test
    /// fails if that fallback is ever dropped.
    #[test]
    fn a_cursor_driven_directive_falls_back_for_substituted_arguments() {
        let config = crate::compile(
            "(comp) {\n    encode {args[0]}\n}\nexample.com {\n    import comp gzip\n}",
        )
        .expect("a snippet argument must reach `encode`");
        assert_eq!(
            config.servers[0].encodings,
            &[pingclair_core::config::Encoding::Gzip],
            "the substituted value must win over the token that spelled it"
        );
    }

    /// 🎯 The braceless shorthand takes directives that carry their own block.
    ///
    /// This one shape was a quarter of the format's own corpus. Nothing about a
    /// block makes something a site — the *name* does — but the classification
    /// read `block.is_some()` and called `file_server { … }` a second site, so
    /// the file was refused for a reason that had nothing to do with it.
    #[test]
    fn the_braceless_shorthand_takes_directives_with_blocks() {
        let config = crate::compile(":80\nfile_server {\n    index a.html\n}")
            .expect("a directive's own block is not a second site");
        assert_eq!(config.servers.len(), 1, "one site, not two");

        crate::compile(":80\nlog {\n    output stdout\n}\nfile_server {\n    index a.html\n}")
            .expect("several block-carrying directives are still one site");
    }

    /// 🚫 The same rule with the sign reversed, and the quieter of the two: a
    /// directive name at the top of a file is a forgotten site address, not a
    /// site named after a directive. This used to compile into a site called
    /// `handle` that served nothing at all.
    #[test]
    fn a_directive_name_is_not_a_site_address() {
        for name in ["handle", "map", "respond", "file_server"] {
            let error = compile_err(&format!("{name} {{\n    respond \"x\"\n}}"));
            assert!(
                error.contains("is a directive, not a site address"),
                "`{name}` must not become a site; got {error}"
            );
        }
        // 👍 A word that is not a directive is still an ordinary site address.
        crate::compile("localhost {\n    respond \"x\"\n}").expect("localhost is a site");
    }

    /// 🚫 Addresses that cannot mean anything are refused.
    ///
    /// All three were already covered by the corpus and all three were
    /// *passing* — the files were being rejected one layer up, by the
    /// misclassification above, rather than by any check on the address. Fixing
    /// that is what revealed these.
    #[test]
    fn impossible_site_addresses_are_refused() {
        for (address, expected) in [
            (":70000", "out of range"),
            ("foo://example.com", "unsupported URL scheme"),
            ("wss://example.com", "only exists in browsers"),
            ("ws://example.com", "only exists in browsers"),
        ] {
            let error = compile_err(&format!("{address} {{\n    respond \"x\"\n}}"));
            assert!(
                error.contains(expected),
                "`{address}` must be refused with `{expected}`; got {error}"
            );
        }
    }

    /// 📌 Port `0` means "let the operating system choose", which is a real
    /// request — so the range check must not swallow it.
    #[test]
    fn port_zero_and_the_top_of_the_range_still_compile() {
        crate::compile(":0\n    respond \"x\"").expect("port 0 is a real request");
        crate::compile(":65535\n    respond \"x\"").expect("65535 is in range");
    }

    /// 👍 The unambiguous forms still compile — an empty 200 is expressible,
    /// it just has to be asked for.
    #[test]
    fn respond_with_a_status_or_body_still_compiles() {
        for source in [
            "example.com {\n    respond 200\n}",
            "example.com {\n    respond \"ok\"\n}",
            "example.com {\n    respond /health 200\n}",
            "example.com {\n    respond /health \"ok\" 200\n}",
        ] {
            crate::compile(source).unwrap_or_else(|e| panic!("must compile:\n{source}\ngot {e}"));
        }
    }
}

// MARK: - P3 Syntax Tests

/// ✍️ P3 regressions: Caddy's single-site shorthand, environment-variable
/// expansion, glued placeholders, full durations, `root`, inline matchers
/// and the extended matcher vocabulary.
#[cfg(test)]
mod p3_syntax_tests {
    use crate::compile;
    use crate::parser::{parse, tokenize};
    use pingclair_core::config::HandlerConfig;

    fn routes(source: &str) -> Vec<pingclair_core::config::RouteConfig> {
        compile(source)
            .expect("config must compile")
            .servers
            .into_iter()
            .next()
            .expect("at least one server")
            .routes
    }

    #[test]
    fn single_site_shorthand_collects_following_directives() {
        let config = compile("localhost\n\nrespond \"Hello, world!\"").expect("shorthand compiles");
        assert_eq!(config.servers.len(), 1);
        assert_eq!(config.servers[0].name.as_deref(), Some("localhost"));
        assert_eq!(config.servers[0].routes.len(), 1);
    }

    #[test]
    fn shorthand_supports_snippets() {
        let config =
            compile("(common) {\n    header X-A b\n}\nlocalhost\n\nimport common\nrespond \"ok\"")
                .expect("snippet + shorthand compiles");
        assert_eq!(config.servers.len(), 1);
        let route = &config.servers[0].routes[0];
        match &route.handler {
            HandlerConfig::Pipeline { handlers } => {
                assert!(
                    handlers
                        .iter()
                        .any(|element| matches!(&element.handler, HandlerConfig::Headers { .. }))
                );
                assert!(
                    handlers
                        .iter()
                        .any(|element| matches!(&element.handler, HandlerConfig::Respond { .. }))
                );
            }
            other => panic!("expected a pipeline, got {other:?}"),
        }
    }

    #[test]
    fn shorthand_cannot_mix_with_braced_sites() {
        let error = compile("localhost\n\nrespond \"x\"\nexample.com {\n    respond \"y\"\n}")
            .expect_err("mixed shorthand and braced sites must fail");
        // 🧭 The shorthand runs to the end of the file, so the braced site was
        // read as a directive of the first one. The message has to name the
        // cause — a missing pair of braces — not the symptom.
        assert!(
            error.to_string().contains("looks like a second site")
                && error.to_string().contains("{ }"),
            "got {error}"
        );
    }

    #[test]
    fn env_vars_expand_before_parsing() {
        // 🛡️ These tests run single-threaded; env mutation is sound here.
        unsafe {
            std::env::set_var("PINGCLAIR_TEST_SITE", "env.example");
            std::env::set_var("PINGCLAIR_TEST_UPSTREAMS", "127.0.0.1:9001 127.0.0.1:9002");
        }
        let config = compile("{$PINGCLAIR_TEST_SITE}\n\nrespond \"env\"").expect("env site");
        assert_eq!(config.servers[0].name.as_deref(), Some("env.example"));

        let config = compile("localhost {\n    reverse_proxy {$PINGCLAIR_TEST_UPSTREAMS}\n}")
            .expect("env upstreams");
        match &config.servers[0].routes[0].handler {
            HandlerConfig::ReverseProxy(proxy) => {
                assert_eq!(
                    proxy.upstreams,
                    vec!["127.0.0.1:9001".to_string(), "127.0.0.1:9002".to_string()]
                );
            }
            other => panic!("expected reverse proxy, got {other:?}"),
        }
    }

    #[test]
    fn env_vars_support_defaults() {
        // 🛡️ Single-threaded test; see env_vars_expand_before_parsing.
        unsafe {
            std::env::remove_var("PINGCLAIR_TEST_ABSENT_VAR");
        }
        let config =
            compile("{$PINGCLAIR_TEST_ABSENT_VAR:fallback.example} {\n    respond \"d\"\n}")
                .expect("default value expands");
        assert_eq!(config.servers[0].name.as_deref(), Some("fallback.example"));
    }

    #[test]
    fn placeholders_glued_to_words_stay_one_token() {
        let tokens = tokenize("redir https://www.{host}{uri}").unwrap();
        let words: Vec<String> = tokens
            .iter()
            .filter_map(|t| match &t.value {
                crate::parser::Token::Word(w) => Some(w.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(words, vec!["redir", "https://www.{host}{uri}"]);
    }

    #[test]
    fn glued_placeholder_redirect_compiles() {
        let config = compile("example.com {\n    redir https://www.{host}{uri}\n}")
            .expect("glued placeholders compile");
        match &config.servers[0].routes[0].handler {
            HandlerConfig::Redirect { to, .. } => {
                assert_eq!(to, "https://www.{host}{uri}");
            }
            other => panic!("expected redirect, got {other:?}"),
        }
    }

    #[test]
    fn full_duration_units_parse() {
        let config = compile(
            "example.com {\n    limits {\n        header_timeout 1.5h\n        body_timeout 2h45m\n        idle_timeout 90d\n    }\n}",
        )
        .expect("compound and fractional durations compile");
        let limits = &config.servers[0].limits;
        assert_eq!(limits.header_timeout_ms, Some(5_400_000));
        assert_eq!(limits.body_timeout_ms, Some(9_900_000));
        assert_eq!(limits.idle_timeout_ms, Some(7_776_000_000));
    }

    #[test]
    fn bare_duration_numbers_are_rejected() {
        let error = compile("example.com {\n    limits {\n        header_timeout 30\n    }\n}")
            .expect_err("a bare number must not silently mean milliseconds");
        assert!(error.to_string().contains("30"));
    }

    #[test]
    fn root_directive_reaches_bare_file_server() {
        let config = compile("example.com {\n    root /var/www\n    file_server\n}")
            .expect("root + file_server compile");
        match &config.servers[0].routes[0].handler {
            HandlerConfig::FileServer { root, .. } => {
                assert_eq!(root, "/var/www");
            }
            other => panic!("expected file server, got {other:?}"),
        }
    }

    #[test]
    fn file_server_browse_inline_enables_listings() {
        let config =
            compile("example.com {\n    file_server browse\n}").expect("inline browse compiles");
        match &config.servers[0].routes[0].handler {
            HandlerConfig::FileServer { browse, root, .. } => {
                assert!(*browse, "inline browse must enable directory listings");
                assert_eq!(root, ".", "browse must not be mistaken for a root");
            }
            other => panic!("expected file server, got {other:?}"),
        }
    }

    #[test]
    fn file_server_glob_argument_becomes_a_path_matcher() {
        let routes =
            routes("example.com {\n    file_server /downloads/* {\n        browse\n    }\n}");
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].path, "/downloads/*");
    }

    #[test]
    fn header_matcher_understands_negation_and_single_stars() {
        let config = compile(
            "example.com {\n    @a header !Foo\n    @b header Foo *.example\n    @c header Foo example*\n    @d header Foo *bar*\n    handle @a { respond \"a\" }\n    handle @b { respond \"b\" }\n    handle @c { respond \"c\" }\n    handle @d { respond \"d\" }\n}",
        )
        .expect("header matcher forms compile");
        let routes = &config.servers[0].routes;
        assert_eq!(routes.len(), 4);
    }

    #[test]
    fn same_field_header_matchers_are_ored() {
        let config = compile(
            "example.com {\n    @foo {\n        header Foo bar\n        header Foo baz\n    }\n    handle @foo { respond \"hit\" }\n}",
        )
        .expect("same-field header matchers compile");
        let matcher = config.servers[0].routes[0]
            .matcher
            .as_ref()
            .expect("matcher must survive");
        let matcher = format!("{matcher:?}");
        assert!(
            matcher.contains("Or"),
            "same-field header matchers must be OR'ed, got {matcher}"
        );
    }

    #[test]
    fn multi_path_matcher_creates_one_route_per_pattern() {
        let routes = routes(
            "example.com {\n    @assets path /js/* /css/* /images/*\n    handle @assets { respond \"asset\" }\n}",
        );
        let paths: Vec<&str> = routes.iter().map(|r| r.path.as_str()).collect();
        assert!(paths.contains(&"/js/*"), "got {paths:?}");
        assert!(paths.contains(&"/css/*"), "got {paths:?}");
        assert!(paths.contains(&"/images/*"), "got {paths:?}");
    }

    #[test]
    fn extended_matcher_vocabulary_compiles() {
        let config = compile(
            "example.com {\n    @h host sub.example.com\n    @q query q=1\n    @p protocol https\n    @r remote_ip 10.0.0.0/8\n    @c client_ip 192.168.0.0/16\n    handle @h { respond \"h\" }\n    handle @q { respond \"q\" }\n    handle @p { respond \"p\" }\n    handle @r { respond \"r\" }\n    handle @c { respond \"c\" }\n}",
        )
        .expect("host/query/protocol/remote_ip/client_ip compile");
        assert_eq!(config.servers[0].routes.len(), 5);
    }

    #[test]
    fn not_inline_multi_value_is_negated_or() {
        // `not path /css/* /js/*` must mean NOT(/css/* OR /js/*).
        let config = compile(
            "example.com {\n    @na {\n        not path /css/* /js/*\n    }\n    handle @na { respond \"ok\" }\n}",
        )
        .expect("not path compiles");
        let matcher = format!(
            "{:?}",
            config.servers[0].routes[0]
                .matcher
                .as_ref()
                .expect("matcher")
        );
        assert!(
            matcher.contains("Not") && matcher.contains("Path"),
            "expected Not(Path[..]) semantics, got {matcher}"
        );
    }

    #[test]
    fn shorthand_parses_via_public_api() {
        let directives = parse("localhost\n\nrespond \"ok\"").expect("parse shorthand");
        // 🧭 One site carrying its directives, rather than a flat run the
        // adapter had to merge afterwards.
        assert_eq!(directives.len(), 1, "one site: {directives:#?}");
        assert_eq!(directives[0].name, "localhost");
        assert_eq!(
            directives[0].block.as_ref().expect("contents").directives[0].name,
            "respond"
        );
    }
}

// MARK: - uri and try_files

/// 🗂️ The two request-manipulation directives wired up on 2026-08-07.
///
/// Every source here is written the way the format's own documentation writes
/// it, verbatim where a documented example exists. That is the point of the
/// tests: the question is never "does our parser like this", it is "does the
/// configuration someone will actually paste in work".
#[cfg(test)]
mod uri_and_try_files_tests {
    use crate::compile;
    use pingclair_core::config::HandlerConfig;

    fn handlers(source: &str) -> Vec<HandlerConfig> {
        let config = compile(source).unwrap_or_else(|error| panic!("must compile: {error}"));
        match config
            .servers
            .into_iter()
            .next()
            .unwrap()
            .routes
            .remove(0)
            .handler
        {
            HandlerConfig::Pipeline { handlers } => handlers
                .into_iter()
                .map(|element| element.handler)
                .collect(),
            single => vec![single],
        }
    }

    /// 🎯 The documented single-page-application pattern, pasted unchanged.
    /// Before this it did not compile at all: `try_files` was refused as an
    /// unimplemented directive, so the first page of the migration guide was
    /// also the first thing to fail.
    #[test]
    fn the_documented_spa_pattern_compiles() {
        let handlers = handlers(
            "example.com {\n\
             \troot * /srv\n\
             \tencode gzip\n\
             \ttry_files {path} /index.html\n\
             \tfile_server\n\
             }",
        );
        let try_files = handlers
            .iter()
            .find_map(|handler| match handler {
                HandlerConfig::TryFiles { files, root, .. } => Some((files, root)),
                _ => None,
            })
            .expect("try_files must survive into the compiled routes");
        assert_eq!(
            try_files.0,
            &["{path}".to_string(), "/index.html".to_string()]
        );
        assert_eq!(
            try_files.1.as_deref(),
            Some("/srv"),
            "try_files must capture the site root, or every candidate is looked up at the \
             filesystem root and the pattern answers 404 for every application route"
        );
    }

    /// 🔢 `try_files` runs before `file_server` however the site is written,
    /// because the order is the format's, not the file's.
    #[test]
    fn try_files_is_ordered_before_the_file_server() {
        let handlers = handlers(
            "example.com {\n\
             \troot * /srv\n\
             \tfile_server\n\
             \ttry_files {path} /index.html\n\
             }",
        );
        let position = |name: &str| {
            handlers
                .iter()
                .position(|handler| match handler {
                    HandlerConfig::TryFiles { .. } => name == "try_files",
                    HandlerConfig::FileServer { .. } => name == "file_server",
                    _ => false,
                })
                .unwrap_or_else(|| panic!("{name} missing from {handlers:?}"))
        };
        assert!(
            position("try_files") < position("file_server"),
            "try_files decides which path is asked for, so it cannot run after the handler \
             that reads it"
        );
    }

    #[test]
    fn uri_strip_prefix_and_suffix_become_rewrites() {
        let stripped_prefix =
            handlers("example.com {\n\turi strip_prefix /api\n\trespond \"ok\"\n}");
        assert!(
            matches!(
                &stripped_prefix[0],
                HandlerConfig::Rewrite { strip_prefix: Some(prefix), .. } if prefix == "/api"
            ),
            "got {:?}",
            stripped_prefix[0]
        );

        let stripped_suffix =
            handlers("example.com {\n\turi strip_suffix .php\n\trespond \"ok\"\n}");
        assert!(
            matches!(
                &stripped_suffix[0],
                HandlerConfig::Rewrite { strip_suffix: Some(suffix), .. } if suffix == ".php"
            ),
            "got {:?}",
            stripped_suffix[0]
        );
    }

    #[test]
    fn uri_path_regexp_becomes_a_regex_rewrite() {
        let handlers = handlers("example.com {\n\turi path_regexp /{2,} /\n\trespond \"ok\"\n}");
        assert!(
            matches!(
                &handlers[0],
                HandlerConfig::Rewrite {
                    regex: Some(pattern),
                    regex_replace: Some(replacement),
                    ..
                } if pattern == "/{2,}" && replacement == "/"
            ),
            "got {:?}",
            handlers[0]
        );
    }

    /// 🚫 `uri replace` substitutes a substring; this crate's rewrite replaces
    /// the whole path. Accepting it would compile and silently serve a
    /// different URL than the operator wrote, which is the one outcome worse
    /// than an error.
    #[test]
    fn uri_replace_and_query_are_refused_by_name() {
        for (source, expected) in [
            ("uri replace /docs /documentation", "uri replace"),
            ("uri query +foo bar", "uri query"),
        ] {
            let message = compile(&format!("example.com {{\n\t{source}\n}}"))
                .expect_err(&format!("`{source}` must be refused"))
                .to_string();
            assert!(
                message.contains(expected),
                "`{source}` must be refused by name rather than as a typo: {message}"
            );
            assert!(
                !message.contains("Unknown directive"),
                "`{source}` is part of the format, so it must not read as a misspelling: \
                 {message}"
            );
        }
    }

    #[test]
    fn uri_rejects_an_unknown_operation_and_a_wrong_argument_count() {
        for source in [
            "uri",
            "uri sideways /a",
            "uri strip_prefix",
            "uri strip_prefix /a /b",
            "uri path_regexp /only-one",
        ] {
            compile(&format!("example.com {{\n\t{source}\n}}"))
                .expect_err(&format!("`{source}` must be refused"));
        }
    }

    /// 🛡️ Confinement is lexical and enforced once, at configuration time.
    #[test]
    fn try_files_refuses_a_candidate_that_leaves_the_root() {
        let message = compile("example.com {\n\troot * /srv\n\ttry_files ../../etc/passwd\n}")
            .expect_err("a `..` candidate must be refused")
            .to_string();
        assert!(message.contains(".."), "got {message}");
    }

    /// 🚫 `{path}` is the only placeholder the handler expands, so any other
    /// one would be looked up as a literal directory name — a misconfiguration
    /// that behaves exactly like a missing file.
    #[test]
    fn try_files_refuses_a_placeholder_it_cannot_expand() {
        let message = compile("example.com {\n\troot * /srv\n\ttry_files {uri} /index.html\n}")
            .expect_err("an unexpandable placeholder must be refused")
            .to_string();
        assert!(message.contains("{uri}"), "got {message}");
    }

    /// 🚫 The `php_fastcgi` shape. Nothing here would do anything with the
    /// query, and dropping it silently is how a configuration written for that
    /// pattern comes to look like it works.
    #[test]
    fn try_files_refuses_a_candidate_carrying_a_query() {
        let message =
            compile("example.com {\n\troot * /srv\n\ttry_files {path} /index.php?{query}\n}")
                .expect_err("a candidate with a query must be refused")
                .to_string();
        assert!(message.contains("query"), "got {message}");
    }

    /// 🔗 The directory-candidate form, which needs the lexer to keep
    /// `{path}/` as one word. It used to tokenize into `{path}` and `/`, and
    /// the stray `/` matched the site root on every request — so the site
    /// served its shell for every URL and looked like it worked.
    #[test]
    fn a_slashed_placeholder_candidate_stays_one_candidate() {
        let handlers = handlers(
            "example.com {\n\troot * /srv\n\ttry_files {path} {path}/ /index.html\n\tfile_server\n}",
        );
        let files = handlers
            .iter()
            .find_map(|handler| match handler {
                HandlerConfig::TryFiles { files, .. } => Some(files),
                _ => None,
            })
            .expect("try_files must survive into the compiled routes");
        assert_eq!(
            files,
            &[
                "{path}".to_string(),
                "{path}/".to_string(),
                "/index.html".to_string()
            ],
            "`{{path}}/` is one candidate; splitting it adds a `/` that matches the site root \
             on every request"
        );
    }

    #[test]
    fn try_files_refuses_a_glob_candidate() {
        compile("example.com {\n\troot * /srv\n\ttry_files {path}*.html\n}")
            .expect_err("a glob candidate must be refused");
    }

    #[test]
    fn try_files_requires_at_least_one_candidate() {
        compile("example.com {\n\troot * /srv\n\ttry_files\n}")
            .expect_err("try_files with no candidate must be refused");
    }
}

// MARK: - basic_auth grammar

/// 🔐 The `basic_auth` grammar, as the format defines it.
///
/// Every source here is written the way the documentation writes it. The whole
/// point of the 2026-08-07 rewrite was that the documented form did not work:
/// this crate read the arguments as inline credentials and the realm as a
/// subdirective, so `basic_auth bcrypt "Admin Area" { … }` was refused with
/// "cannot mix inline credentials with a block".
#[cfg(test)]
mod basic_auth_grammar_tests {
    use crate::compile;
    use pingclair_core::config::HandlerConfig;

    /// 🔑 bcrypt hash of `change-me`, cost 12.
    const HASH: &str = "$2y$12$iKzVHkDoCr2oz1DAOzX9wec0yf3A.FZM3SmsP9dYHmhE2O.3TSpSW";

    fn basic_auth_of(source: &str) -> (String, Vec<(String, String)>) {
        let config = compile(source).unwrap_or_else(|error| panic!("must compile: {error}"));
        let handler = match config
            .servers
            .into_iter()
            .next()
            .unwrap()
            .routes
            .remove(0)
            .handler
        {
            HandlerConfig::Pipeline { handlers } => handlers
                .into_iter()
                .find(|element| matches!(&element.handler, HandlerConfig::BasicAuth { .. }))
                .map(|element| element.handler)
                .expect("a basic_auth handler"),
            single => single,
        };
        let HandlerConfig::BasicAuth { realm, credentials } = handler else {
            panic!("expected basic_auth");
        };
        (
            realm,
            credentials
                .into_iter()
                .map(|credential| (credential.username, credential.password))
                .collect(),
        )
    }

    #[test]
    fn the_documented_form_compiles() {
        let (realm, accounts) = basic_auth_of(&format!(
            "example.com {{\n\tbasic_auth bcrypt \"Admin Area\" {{\n\t\tadmin {HASH}\n\t}}\n\trespond \"ok\"\n}}"
        ));
        assert_eq!(realm, "Admin Area");
        assert_eq!(accounts, vec![("admin".to_string(), HASH.to_string())]);
    }

    #[test]
    fn the_algorithm_and_realm_are_both_optional() {
        for source in [
            format!(
                "example.com {{\n\tbasic_auth {{\n\t\tadmin {HASH}\n\t}}\n\trespond \"ok\"\n}}"
            ),
            format!(
                "example.com {{\n\tbasic_auth bcrypt {{\n\t\tadmin {HASH}\n\t}}\n\trespond \"ok\"\n}}"
            ),
        ] {
            let (_, accounts) = basic_auth_of(&source);
            assert_eq!(accounts.len(), 1, "{source}");
        }
    }

    /// 🛡️ `realm` used to be a block line here. Under the real grammar a block
    /// line *is* an account, so silently accepting it would create a working
    /// login named `realm` whose password is the realm string — a credential
    /// the operator never wrote. The error names the replacement.
    #[test]
    fn a_realm_block_line_is_refused_rather_than_becoming_an_account() {
        let message = compile(&format!(
            "example.com {{\n\tbasic_auth {{\n\t\trealm \"Admin Area\"\n\t\tadmin {HASH}\n\t}}\n}}"
        ))
        .expect_err("a `realm` block line must be refused")
        .to_string();
        assert!(
            message.contains("second argument"),
            "the message must point at the replacement spelling: {message}"
        );
    }

    /// 🚫 We verify bcrypt only. A hash we cannot verify is compared as a
    /// literal string, so accepting the word would create a login whose
    /// password is the hash text.
    #[test]
    fn argon2id_is_refused_by_name() {
        let message = compile(
            "example.com {\n\tbasic_auth argon2id {\n\t\tadmin $argon2id$v=19$m=65536,t=1,p=4$a$b\n\t}\n}",
        )
        .expect_err("argon2id must be refused")
        .to_string();
        assert!(message.contains("argon2id"), "got {message}");
        assert!(
            !message.contains("Unknown directive"),
            "argon2id is part of the format, so it must not read as a typo: {message}"
        );
    }

    #[test]
    fn malformed_shapes_are_refused() {
        for source in [
            // 🚫 More than `<hash_algorithm> <realm>`; upstream errors too.
            format!(
                "example.com {{\n\tbasic_auth bcrypt \"A\" extra {{\n\t\tadmin {HASH}\n\t}}\n}}"
            ),
            // 🚫 An algorithm the format does not define.
            format!("example.com {{\n\tbasic_auth md5 {{\n\t\tadmin {HASH}\n\t}}\n}}"),
            // 🚫 An account line with two passwords.
            format!("example.com {{\n\tbasic_auth {{\n\t\tadmin {HASH} extra\n\t}}\n}}"),
            // 🚫 No accounts at all would deny every request.
            "example.com {\n\tbasic_auth bcrypt \"A\" {\n\t}\n}".to_string(),
            // 🚫 Credentials as arguments: the old spelling, now read as an
            // algorithm named `alice`.
            "example.com {\n\tbasic_auth alice secret\n}".to_string(),
        ] {
            compile(&source).expect_err(&format!("must be refused:\n{source}"));
        }
    }
}

// MARK: - Matcher tokens inside route/handle

/// 🧭 Per-element matchers inside `route`/`handle`/`handle_path` blocks.
///
/// These used to be refused by the A1 blockade; C2 implements them, so every
/// former refusal becomes a "must compile and gate" assertion.
#[cfg(test)]
mod matcher_inside_route_body_tests {
    use crate::compile;
    use pingclair_core::config::{HandlerConfig, Matcher};

    fn route_handlers(source: &str) -> Vec<pingclair_core::config::HandlerElement> {
        let config = compile(source).unwrap_or_else(|error| panic!("must compile: {error}"));
        match &config.servers[0].routes[0].handler {
            HandlerConfig::Pipeline { handlers }
            | HandlerConfig::Handle { handlers }
            | HandlerConfig::HandlePath { handlers, .. } => handlers.clone(),
            other => panic!("expected a container handler, got {other:?}"),
        }
    }

    fn path_matcher(element: &pingclair_core::config::HandlerElement) -> Option<&[String]> {
        match &element.matcher {
            Some(Matcher::Path { patterns }) => Some(patterns),
            _ => None,
        }
    }

    /// 🤡 The measured case: the token used to become the response body and
    /// every request got `@admin`; now it must gate the first element.
    #[test]
    fn a_named_matcher_on_respond_gates_the_element() {
        let handlers = route_handlers(
            "example.com {\n\
             \t@admin path /admin/*\n\
             \troute {\n\
             \t\trespond @admin \"SECRET\" 200\n\
             \t\trespond \"public\" 200\n\
             \t}\n\
             }",
        );
        assert_eq!(handlers.len(), 2);
        assert_eq!(
            path_matcher(&handlers[0]),
            Some(&["/admin/*".to_string()][..])
        );
        assert!(handlers[0].matcher.is_some(), "first element must be gated");
        let HandlerConfig::Respond { body, .. } = &handlers[0].handler else {
            panic!("expected respond");
        };
        assert_eq!(
            body.as_deref(),
            Some("SECRET"),
            "the token must not become the body"
        );
        assert!(handlers[1].matcher.is_none());
    }

    /// 🛡️ The fail-open direction: the token used to be filtered out and the
    /// proxy ran unconditionally; now it must stay on the element.
    #[test]
    fn a_named_matcher_on_reverse_proxy_is_not_dropped() {
        let handlers = route_handlers(
            "example.com {\n\
             \t@api path /api/*\n\
             \troute {\n\
             \t\treverse_proxy @api 127.0.0.1:9000\n\
             \t}\n\
             }",
        );
        assert_eq!(
            path_matcher(&handlers[0]),
            Some(&["/api/*".to_string()][..])
        );
        let HandlerConfig::ReverseProxy(proxy) = &handlers[0].handler else {
            panic!("expected reverse proxy");
        };
        assert_eq!(proxy.upstreams, vec!["127.0.0.1:9000".to_string()]);
    }

    #[test]
    fn a_matcher_token_works_in_handle_and_handle_path_too() {
        for container in [
            "handle {\n\t\trespond @admin \"x\" 200\n\t}",
            "handle_path /api/* {\n\t\trespond @admin \"x\" 200\n\t}",
        ] {
            let handlers = route_handlers(&format!(
                "example.com {{\n\t@admin path /admin/*\n\t{container}\n}}"
            ));
            assert_eq!(
                path_matcher(&handlers[0]),
                Some(&["/admin/*".to_string()][..]),
                "{container} must keep its matcher"
            );
        }
    }

    /// 🏷️ A matcher definition inside a block resolves locally and does not
    /// leak upward: the same name outside the block is still undefined.
    #[test]
    fn a_matcher_definition_inside_the_block_stays_local() {
        let handlers = route_handlers(
            "example.com {\n\
             \troute {\n\
             \t\t@admin path /admin/*\n\
             \t\trespond @admin \"x\"\n\
             \t}\n\
             }",
        );
        assert_eq!(
            path_matcher(&handlers[0]),
            Some(&["/admin/*".to_string()][..])
        );

        compile(
            "example.com {\n\
             \troute {\n\
             \t\t@admin path /admin/*\n\
             \t\trespond \"x\"\n\
             \t}\n\
             \theader @admin X-A b\n\
             }",
        )
        .expect_err("a block-local matcher must not be visible outside the block");
    }

    /// 🧭 `route` preserves file order; `handle` sorts by directive order.
    #[test]
    fn route_preserves_file_order_and_handle_sorts() {
        let route = route_handlers(
            "example.com {\n\
             \troute {\n\
             \t\trespond \"b\"\n\
             \t\theader X-A b\n\
             \t\trespond \"a\"\n\
             \t}\n\
             }",
        );
        let names = |handlers: &[pingclair_core::config::HandlerElement]| {
            handlers
                .iter()
                .map(|element| match &element.handler {
                    HandlerConfig::Respond { .. } => "respond",
                    HandlerConfig::Headers { .. } => "header",
                    other => panic!("unexpected {other:?}"),
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(names(&route), vec!["respond", "header", "respond"]);

        let handle = route_handlers(
            "example.com {\n\
             \thandle {\n\
             \t\trespond \"b\"\n\
             \t\theader X-A b\n\
             \t\trespond \"a\"\n\
             \t}\n\
             }",
        );
        assert_eq!(names(&handle), vec!["header", "respond", "respond"]);
    }

    /// 🎯 A matcher on the container itself keeps working.
    #[test]
    fn a_matcher_on_the_container_still_compiles() {
        compile(
            "example.com {\n\
             \t@admin path /admin/*\n\
             \thandle @admin {\n\
             \t\trespond \"SECRET\" 200\n\
             \t}\n\
             \trespond \"public\" 200\n\
             }",
        )
        .expect("a matcher on the container is supported");
    }

    /// 🤡 A nested container carrying a matcher now compiles and gates.
    #[test]
    fn a_nested_container_carrying_a_matcher_works() {
        let handlers = route_handlers(
            "example.com {\n\
             \troute {\n\
             \t\thandle /foo/* {\n\
             \t\t\trespond \"Foo\"\n\
             \t\t}\n\
             \t\thandle {\n\
             \t\t\trespond \"Bar\"\n\
             \t\t}\n\
             \t}\n\
             }",
        );
        assert_eq!(handlers.len(), 2);
        assert_eq!(
            path_matcher(&handlers[0]),
            Some(&["/foo/*".to_string()][..])
        );
        assert!(matches!(handlers[0].handler, HandlerConfig::Handle { .. }));
        assert!(handlers[1].matcher.is_none());
        assert!(matches!(handlers[1].handler, HandlerConfig::Handle { .. }));
    }

    /// 📌 A directive whose first argument merely looks like a matcher stays
    /// data — `file_server /var/www` is a root, not a path matcher.
    #[test]
    fn a_directive_whose_argument_is_data_is_not_caught() {
        compile("example.com {\n\troute {\n\t\tfile_server /var/www\n\t}\n}")
            .expect("a file server root is data, not a matcher");
    }
}
