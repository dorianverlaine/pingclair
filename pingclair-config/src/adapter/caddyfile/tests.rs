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
    fn mixed_site_schemes_split_before_host_matchers_are_built() {
        let directives =
            parse("http://plain.example, https://secure.example { respond \"shared\" }").unwrap();
        let ast = adapt(directives).unwrap();

        assert_eq!(ast.servers.len(), 2);
        let plain = ast
            .servers
            .iter()
            .find(|server| server.inner.names == ["plain.example"])
            .expect("plaintext group");
        assert_eq!(plain.inner.listens.len(), 1);
        assert!(plain.inner.listens[0].force_plaintext);
        assert_eq!(plain.inner.listens[0].scheme, Scheme::Http);

        let secure = ast
            .servers
            .iter()
            .find(|server| server.inner.names == ["secure.example"])
            .expect("HTTPS group");
        assert_eq!(secure.inner.listens.len(), 1);
        assert!(!secure.inner.listens[0].force_plaintext);
        assert_eq!(secure.inner.listens[0].scheme, Scheme::Https);
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
                        | pingclair_core::config::HandlerConfig::FirstMatch { .. }
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
    use pingclair_core::config::HandlerConfig;

    fn compile_err(source: &str) -> String {
        match crate::compile(source) {
            Ok(_) => panic!("config unexpectedly compiled:\n{source}"),
            Err(e) => e.to_string(),
        }
    }

    /// 🧭 Every handler in a route's tree, flattened.
    ///
    /// A site with more than one directive compiles to a pipeline, so a test
    /// that matched the route's handler directly would only ever see the
    /// wrapper — and would pass or fail for reasons that have nothing to do
    /// with the directive it is about.
    fn handlers_of(handler: &HandlerConfig) -> Vec<&HandlerConfig> {
        match handler {
            HandlerConfig::Pipeline { handlers }
            | HandlerConfig::FirstMatch { handlers }
            | HandlerConfig::HandlePath { handlers, .. } => handlers
                .iter()
                .flat_map(|element| handlers_of(&element.handler))
                .collect(),
            other => vec![other],
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
        // 🔢 `1mb` parses as a million bytes — `mb` is SI in this format, the
        // upstream parser being `humanize.ParseBytes` — and rotation then
        // rounds *up* to a whole mebibyte, because that is the resolution a
        // roll threshold has. So the stored value is 1 MiB by two steps, not
        // by the one that used to produce it: this assertion once read
        // 1,048,576 because our size parser treated `mb` as binary, which was
        // the wrong reason for the right number. Both steps corrected
        // 2026-08-12, and `roll_size 1500kb` is what tells them apart.
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

    /// 🗜️ `precompressed` is implemented now, so the fail-closed rule it used
    /// to be tested for moved: an *encoding* this build cannot read must still
    /// be refused rather than quietly dropped, which would leave the operator
    /// with a sidecar list missing an entry they wrote.
    #[test]
    fn file_server_rejects_a_precompressed_encoding_it_cannot_read() {
        let error = compile_err(
            r#"example.com {
                file_server /downloads/* {
                    precompressed lz4
                }
            }"#,
        );
        assert!(
            error.contains("lz4"),
            "the rejection must name the encoding; got {error}"
        );

        // 🎯 The mirror case, so this cannot degrade into "precompressed is an
        // error".
        crate::compile(
            r#"example.com {
                file_server /downloads/* {
                    precompressed zstd gzip
                }
            }"#,
        )
        .expect("a supported encoding list compiles");
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
    fn reverse_proxy_with_a_dynamic_source_needs_no_static_upstreams() {
        let config = crate::compile(
            r#"example.com {
                reverse_proxy /api/* {
                    dynamic srv _api._tcp.example.com
                }
            }"#,
        )
        .expect("a dynamic-only reverse_proxy must compile");
        match &config.servers[0].routes[0].handler {
            pingclair_core::config::HandlerConfig::ReverseProxy(proxy) => {
                assert!(
                    proxy.dynamic_upstream.is_some(),
                    "the dynamic source must survive compilation"
                );
            }
            other => panic!("expected a proxy handler, got {other:?}"),
        }
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
                    stream_buffer_size 4KB
                }
            }"#,
        );
        assert!(
            error.contains("stream_buffer_size") && error.contains("does not implement"),
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

    /// 🔤 `header_regexp` matches a header against a regular expression and
    /// keeps the matcher's optional name so captures become placeholders.
    #[test]
    fn header_regexp_compiles_into_a_regex_matcher() {
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
            pingclair_core::config::Matcher::HeaderRegexp {
                name,
                field,
                pattern,
            } => {
                assert_eq!(name, &None);
                assert_eq!(field, "User-Agent");
                assert_eq!(pattern, "(?i)android");
            }
            other => panic!("expected a header regexp matcher, got {other:?}"),
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

    /// 🔍 The three-argument form names the capture groups so they can be
    /// read back as `{re.<name>.N}` placeholders.
    #[test]
    fn a_named_capture_group_compiles_with_its_name() {
        let config = crate::compile(
            "example.com {\n    @x header_regexp mobile User-Agent android\n                 respond @x \"y\"\n}",
        )
        .expect("a named header_regexp must compile");
        let matched = config.servers[0]
            .routes
            .iter()
            .find(|route| route.matcher.is_some())
            .expect("a matched route");
        assert!(matches!(
            matched.matcher.as_ref().expect("a matcher"),
            pingclair_core::config::Matcher::HeaderRegexp {
                name: Some(name),
                field,
                ..
            } if name == "mobile" && field == "User-Agent"
        ));
    }

    /// 🔤 `path_regexp [<name>] <pattern>` matches the path against a regular
    /// expression, with an optional name for capture placeholders.
    #[test]
    fn path_regexp_compiles_with_and_without_a_name() {
        let config = crate::compile(
            "example.com {\n    @id path_regexp item ^/item/([0-9]+)$\n    respond @id \"{re.item.1}\"\n    @any path_regexp ^/public$\n    respond @any \"public\"\n}",
        )
        .expect("path_regexp must compile");
        let matchers: Vec<_> = config.servers[0]
            .routes
            .iter()
            .filter_map(|route| route.matcher.clone())
            .collect();
        assert_eq!(matchers.len(), 2);
        assert!(matches!(
            &matchers[0],
            pingclair_core::config::Matcher::PathRegexp {
                name: Some(name),
                pattern,
            } if name == "item" && pattern == "^/item/([0-9]+)$"
        ));
        assert!(matches!(
            &matchers[1],
            pingclair_core::config::Matcher::PathRegexp {
                name: None,
                pattern,
            } if pattern == "^/public$"
        ));
    }

    /// 🚫 A path regexp that cannot compile is refused, and so is a matcher
    /// with the wrong argument count.
    #[test]
    fn malformed_path_regexp_is_refused() {
        for source in [
            "example.com {\n    @x path_regexp \"(unclosed\"\n    respond @x \"y\"\n}",
            "example.com {\n    @x path_regexp a b c\n    respond @x \"y\"\n}",
            "example.com {\n    @x path_regexp\n    respond @x \"y\"\n}",
        ] {
            compile_err(source);
        }
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

    /// 🧭 `dynamic a` and `dynamic srv` compile into their DNS source, with
    /// every block option preserved for the runtime refresher.
    #[test]
    fn dynamic_upstream_sources_compile_with_their_options() {
        let config = crate::compile(
            r#":8884 {
                reverse_proxy {
                    dynamic a foo 9000
                }
            }
            :8885 {
                reverse_proxy {
                    dynamic srv _api._tcp.example.com
                }
            }
            :8886 {
                reverse_proxy {
                    dynamic a {
                        name bar
                        port 9001
                        refresh 5m
                        resolvers 8.8.8.8 8.8.4.4
                        dial_timeout 2s
                        versions ipv6
                    }
                }
            }
            :8887 {
                reverse_proxy {
                    dynamic srv {
                        service api
                        proto tcp
                        name example.com
                        refresh 5m
                        resolvers 8.8.8.8
                        dial_timeout 1s
                        grace_period 5s
                    }
                }
            }"#,
        )
        .expect("dynamic sources must compile");
        let handlers: Vec<_> = config
            .servers
            .iter()
            .flat_map(|server| server.routes.iter())
            .map(|route| route.handler.clone())
            .collect();
        assert_eq!(handlers.len(), 4);

        let proxy = |index: usize| match &handlers[index] {
            pingclair_core::config::HandlerConfig::ReverseProxy(proxy) => proxy,
            other => panic!("expected a proxy handler, got {other:?}"),
        };

        let compact_a = proxy(0).dynamic_upstream.as_ref().expect("an A source");
        assert!(matches!(
            &**compact_a,
            pingclair_core::config::DynamicUpstreamConfig::A(source)
                if source.name == "foo" && source.port == 9000
        ));

        let compact_srv = proxy(1).dynamic_upstream.as_ref().expect("an SRV source");
        assert!(matches!(
            &**compact_srv,
            pingclair_core::config::DynamicUpstreamConfig::Srv(source)
                if source.name == "_api._tcp.example.com" && source.service.is_none()
        ));

        let block_a = proxy(2).dynamic_upstream.as_ref().expect("an A source");
        let pingclair_core::config::DynamicUpstreamConfig::A(block_a) = &**block_a else {
            panic!("expected an A source");
        };
        assert_eq!(block_a.name, "bar");
        assert_eq!(block_a.port, 9001);
        assert_eq!(block_a.refresh_secs, Some(300));
        assert_eq!(block_a.resolvers, ["8.8.8.8", "8.8.4.4"]);
        assert_eq!(block_a.dial_timeout_ms, Some(2_000));
        assert_eq!(block_a.fallback_delay_ms, None);
        assert_eq!(block_a.versions.as_deref(), Some("ipv6"));

        let block_srv = proxy(3).dynamic_upstream.as_ref().expect("an SRV source");
        let pingclair_core::config::DynamicUpstreamConfig::Srv(block_srv) = &**block_srv else {
            panic!("expected an SRV source");
        };
        assert_eq!(block_srv.service.as_deref(), Some("api"));
        assert_eq!(block_srv.proto.as_deref(), Some("tcp"));
        assert_eq!(block_srv.name, "example.com");
        assert_eq!(block_srv.refresh_secs, Some(300));
        assert_eq!(block_srv.fallback_delay_ms, None);
        assert_eq!(block_srv.grace_period_ms, Some(5_000));
    }

    /// 🚫 A malformed dynamic source is refused instead of degrading to a
    /// static peer list that never matches the operator's intent.
    #[test]
    fn malformed_dynamic_sources_are_refused() {
        for source in [
            "example.com {\n    reverse_proxy {\n        dynamic cname app\n    }\n}",
            "example.com {\n    reverse_proxy {\n        dynamic srv {\n            service api\n            name example.com\n        }\n    }\n}",
            "example.com {\n    reverse_proxy {\n        dynamic a {\n            name app\n            resolvers not-an-ip\n        }\n    }\n}",
            "example.com {\n    reverse_proxy {\n        dynamic a {\n            name app\n            versions tcp\n        }\n    }\n}",
            "example.com {\n    reverse_proxy {\n        dynamic a {\n            name app\n            dial_fallback_delay 300ms\n        }\n    }\n}",
            "example.com {\n    reverse_proxy {\n        dynamic srv {\n            name _api._tcp.example.com\n            dial_fallback_delay -1s\n        }\n    }\n}",
        ] {
            compile_err(source);
        }
    }

    /// 🔁 `lb_retry_match` folds method, path, and status expressions into the
    /// runtime retry policy while keeping unmappable CEL visible.
    #[test]
    fn lb_retry_match_folds_mappable_forms_and_keeps_expressions() {
        let config = crate::compile(
            r#":8884 {
                reverse_proxy 127.0.0.1:65535 {
                    lb_retries 5
                    lb_retry_match {
                        method POST PUT
                    }
                    lb_retry_match {
                        path /foo*
                    }
                    lb_retry_match {
                        expression `{rp.status_code} in [502, 503, 504]`
                    }
                    lb_retry_match {
                        expression `{rp.header.X-Retry} == "true"`
                    }
                    lb_retry_match `{rp.status_code} >= 500`
                    lb_retry_match path /bar*
                }
            }"#,
        )
        .expect("retry matches must compile");
        let pingclair_core::config::HandlerConfig::ReverseProxy(proxy) =
            &config.servers[0].routes[0].handler
        else {
            panic!("expected a proxy handler");
        };
        assert_eq!(proxy.retry.methods, ["POST", "PUT"]);
        assert_eq!(proxy.retry.path_patterns, ["/foo*", "/bar*"]);
        assert!(
            proxy.retry.status_codes.contains(&502)
                && proxy.retry.status_codes.contains(&503)
                && proxy.retry.status_codes.contains(&504)
                && proxy.retry.status_codes.contains(&599),
            "the folded set must cover both the `in [...]` and `>= 500` forms"
        );
        assert_eq!(proxy.retry.status_codes.len(), 100);
        assert_eq!(proxy.retry.expressions, ["{rp.header.X-Retry} == \"true\""]);
    }

    /// ⚖️ `weighted_round_robin` carries one inline weight per upstream and
    /// the weights land on the per-upstream options the runtime selects with.
    #[test]
    fn weighted_round_robin_assigns_inline_weights() {
        let config = crate::compile(
            r#":8884 {
                reverse_proxy 127.0.0.1:65535 127.0.0.1:35535 {
                    lb_policy weighted_round_robin 10 1
                }
            }"#,
        )
        .expect("weighted round robin must compile");
        let pingclair_core::config::HandlerConfig::ReverseProxy(proxy) =
            &config.servers[0].routes[0].handler
        else {
            panic!("expected a proxy handler");
        };
        assert_eq!(proxy.load_balance.strategy, "round_robin");
        assert_eq!(
            proxy
                .upstream_options
                .iter()
                .map(|upstream| upstream.weight)
                .collect::<Vec<_>>(),
            [10, 1]
        );
    }

    /// 🧭 `method`/`rewrite` mutate the upstream request; buffer ceilings stay
    /// visible in the compiled configuration.
    #[test]
    fn method_rewrite_and_buffer_ceilings_compile() {
        let config = crate::compile(
            r#"example.com {
                reverse_proxy https://localhost:54321 {
                    method GET
                    rewrite /rewritten?uri={uri}
                    request_buffers 4KB
                    response_buffers unlimited
                }
            }"#,
        )
        .expect("the options must compile");
        let pingclair_core::config::HandlerConfig::ReverseProxy(proxy) =
            &config.servers[0].routes[0].handler
        else {
            panic!("expected a proxy handler");
        };
        assert_eq!(proxy.rewrite_method.as_deref(), Some("GET"));
        assert_eq!(proxy.rewrite_uri.as_deref(), Some("/rewritten?uri={uri}"));
        assert_eq!(proxy.request_buffer_bytes, Some(4 * 1024));
        assert_eq!(proxy.response_buffer_bytes, Some(-1));
    }

    /// 🩺 A health probe may set the Host header: that is how an operator asks
    /// a different virtual host on the same origin.
    #[test]
    fn health_headers_may_set_host() {
        let config = crate::compile(
            r#"example.com {
                reverse_proxy 127.0.0.1:65535 {
                    health_headers {
                        Host example.com
                        X-Probe probe
                    }
                    health_uri /health
                }
            }"#,
        )
        .expect("Host must be allowed in health-check headers");
        let pingclair_core::config::HandlerConfig::ReverseProxy(proxy) =
            &config.servers[0].routes[0].handler
        else {
            panic!("expected a proxy handler");
        };
        let headers = proxy
            .health_check
            .as_ref()
            .expect("a health check")
            .headers
            .clone();
        assert_eq!(headers.get("Host").map(String::as_str), Some("example.com"));
        assert_eq!(headers.get("X-Probe").map(String::as_str), Some("probe"));
    }

    /// 🧭 `handle_response` and `intercept` compile into the response-handler
    /// configuration the runtime evaluates before the client sees a byte.
    #[test]
    fn handle_response_and_intercept_compile() {
        let config = crate::compile(
            r#"example.com {
                reverse_proxy localhost:8080 {
                    @err status 401 403
                    handle_response @err {
                        copy_response_headers {
                            include X-Retry
                        }
                        respond "denied" 403
                    }
                    @ok status 2xx
                    handle_response @ok {
                        copy_response 202
                    }
                }
            }
            intercept.example {
                intercept {
                    @500 status 500
                    replace_status @500 400
                    handle_response {
                        respond "any" 418
                    }
                }
                respond "wrapped"
            }"#,
        )
        .expect("response handlers must compile");

        let example = config
            .servers
            .iter()
            .find(|server| server.name.as_deref() == Some("example.com"))
            .expect("the example.com server");
        let proxy = match &example.routes[0].handler {
            pingclair_core::config::HandlerConfig::ReverseProxy(proxy) => proxy,
            other => panic!("expected a proxy handler, got {other:?}"),
        };
        assert_eq!(proxy.handle_response.len(), 2);
        let pingclair_core::config::ResponseHandlerConfig {
            matcher: Some(matcher),
            status_code: None,
            handlers,
        } = &proxy.handle_response[0]
        else {
            panic!("the first entry must carry a matcher and handlers");
        };
        assert_eq!(matcher.status_codes, [401, 403]);
        assert!(matches!(
            handlers[0],
            pingclair_core::config::HandlerConfig::CopyResponseHeaders { .. }
        ));
        assert!(matches!(
            handlers[1],
            pingclair_core::config::HandlerConfig::Respond { status: 403, .. }
        ));
        assert!(matches!(
            proxy.handle_response[1].handlers[0],
            pingclair_core::config::HandlerConfig::CopyResponse {
                status_code: Some(202)
            }
        ));

        let intercept_site = config
            .servers
            .iter()
            .find(|server| server.name.as_deref() == Some("intercept.example"))
            .expect("the intercept.example server");
        let pingclair_core::config::HandlerConfig::Pipeline { handlers } =
            &intercept_site.routes[0].handler
        else {
            panic!("expected a pipeline with intercept and respond");
        };
        let pingclair_core::config::HandlerConfig::Intercept {
            handlers: intercept,
        } = &handlers[0].handler
        else {
            panic!("expected an intercept handler");
        };
        assert_eq!(intercept.len(), 2);
        assert_eq!(
            intercept[0].status_code.as_deref(),
            Some("400"),
            "replace_status folds into the first entry"
        );
        assert!(intercept[1].matcher.is_none());
    }

    /// 🔐 `forward_auth` compiles into a GET proxy subrequest ahead of the backend.
    #[test]
    fn forward_auth_compiles_with_copy_header_renames() {
        let config = crate::compile(
            r#":8881 {
                forward_auth localhost:9000 {
                    uri /auth
                    copy_headers A>1 B C>3 {
                        D
                        E>5
                    }
                }
                reverse_proxy localhost:8080
            }"#,
        )
        .expect("forward_auth must compile");

        let found = config
            .servers
            .iter()
            .flat_map(|server| server.routes.iter())
            .find_map(|route| match &route.handler {
                pingclair_core::config::HandlerConfig::Pipeline { handlers } => {
                    handlers.first().map(|element| &element.handler)
                }
                _ => None,
            })
            .expect("a pipeline");
        let pingclair_core::config::HandlerConfig::ReverseProxy(config) = found else {
            panic!("forward_auth must compile into the leading reverse proxy");
        };
        assert_eq!(config.upstreams, ["localhost:9000"]);
        assert_eq!(config.rewrite_method.as_deref(), Some("GET"));
        assert_eq!(config.rewrite_uri.as_deref(), Some("/auth"));
        assert_eq!(
            config
                .headers_up
                .get("X-Forwarded-Method")
                .map(String::as_str),
            Some("{http.request.method}")
        );
        assert_eq!(
            config.headers_up.get("X-Forwarded-Uri").map(String::as_str),
            Some("{http.request.uri}")
        );
        let subrequest = config
            .subrequest
            .as_ref()
            .expect("forward_auth must carry a continuation policy");
        assert_eq!(subrequest.continue_status_classes, [2]);
        let maps: Vec<(&str, Option<&str>)> = config
            .subrequest
            .as_ref()
            .unwrap()
            .copy_headers
            .iter()
            .map(|mapping| (mapping.from.as_str(), mapping.to.as_deref()))
            .collect();
        assert_eq!(
            maps,
            [
                ("A", Some("1")),
                ("B", None),
                ("C", Some("3")),
                ("D", None),
                ("E", Some("5"))
            ]
        );
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

    /// 🏗️ Unix-socket upstreams keep their dial string so the proxy can build
    /// a Unix-domain peer; `unix+h2c//` additionally carries the h2c scheme.
    #[test]
    fn reverse_proxy_accepts_unix_socket_upstreams() {
        for (source, expected) in [
            (
                "example.com {\n    reverse_proxy unix//run/php/php.sock\n}",
                "unix//run/php/php.sock",
            ),
            (
                "example.com {\n    reverse_proxy unix+h2c//run/app.sock\n}",
                "unix+h2c//run/app.sock",
            ),
        ] {
            let config = crate::compile(source)
                .unwrap_or_else(|error| panic!("{source} must compile: {error}"));
            match &config.servers[0].routes[0].handler {
                pingclair_core::config::HandlerConfig::ReverseProxy(proxy) => {
                    assert_eq!(proxy.upstreams, vec![expected.to_string()]);
                }
                other => panic!("expected a proxy handler, got {other:?}"),
            }
        }
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
        let pingclair_core::config::HandlerConfig::Pipeline { handlers } = &route.handler else {
            panic!("a handle block compiles to a sequential group");
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

    /// 🔁 `header <field> <find> <replace>` is a search-and-replace.
    ///
    /// It used to compile to `set <field> <find>` with the third argument read
    /// and discarded — a configuration that loaded, started, and did something
    /// else. The regression this test guards is that silence, not the feature.
    /// 📏 The two steps `roll_size` takes, in a case where they disagree.
    ///
    /// 1,500,000 bytes is what `1500kb` parses to under the SI reading, and a
    /// rotation threshold has mebibyte resolution, so it rounds up to 2 MiB.
    /// A binary-reading parser would have produced 1,536,000 and a version
    /// that skipped the rounding would have kept 1,500,000 — three different
    /// answers, and only one of them matches what the configuration means.
    #[test]
    fn roll_size_parses_as_si_then_rounds_up_to_whole_mebibytes() {
        let config = crate::compile(
            "example.com {\n log {\n output file /tmp/x.log {\n roll_size 1500kb\n }\n }\n              respond \"x\"\n}",
        )
        .unwrap();
        let rotation = config.servers[0]
            .log
            .as_ref()
            .expect("log config")
            .rotation
            .clone();
        assert_eq!(rotation.max_size_bytes, Some(2 * 1024 * 1024));
    }

    #[test]
    fn header_three_arguments_are_a_replacement_not_a_dropped_argument() {
        let config =
            crate::compile("example.com {\n    header X-Foo ^old$ new\n    respond \"x\"\n}")
                .unwrap();
        let route = &config.servers[0].routes[0];
        let found = handlers_of(&route.handler).into_iter().any(|handler| {
            matches!(handler, HandlerConfig::Headers { set, replace, .. }
                if set.is_empty()
                    && replace.len() == 1
                    && replace[0].field == "X-Foo"
                    && replace[0].search_regexp == "^old$"
                    && replace[0].replace == "new")
        });
        assert!(found, "the third argument is the replacement");
    }

    /// 🧭 The prefix wins over the argument count on the response side too,
    /// because both directives read a line through the same function.
    #[test]
    fn header_inline_plus_appends_rather_than_naming_a_header_plus_foo() {
        let config =
            crate::compile("example.com {\n    header +X-Foo bar\n    respond \"x\"\n}").unwrap();
        let route = &config.servers[0].routes[0];
        let found = handlers_of(&route.handler).into_iter().any(|handler| {
            matches!(handler, HandlerConfig::Headers { add, set, .. }
                if add.get("X-Foo").is_some_and(|value| value == "bar") && set.is_empty())
        });
        assert!(
            found,
            "`+X-Foo bar` appends, and does not name a header `+X-Foo`"
        );
    }

    /// ❓ `?X-Foo bar` sets the header only if the response lacks one.
    #[test]
    fn header_question_mark_is_a_conditional_default() {
        let config =
            crate::compile("example.com {\n    header ?X-Foo bar\n    respond \"x\"\n}").unwrap();
        let route = &config.servers[0].routes[0];
        let found = handlers_of(&route.handler).into_iter().any(|handler| {
            matches!(handler, HandlerConfig::Headers { default_set, set, .. }
                if default_set.get("X-Foo").is_some_and(|value| value == "bar") && set.is_empty())
        });
        assert!(found, "`?X-Foo` is a default, not an unconditional set");
    }

    /// 🚫 …and on a request it is refused, because "already there" needs a
    /// response to look at. Upstream refuses it for the same reason.
    #[test]
    fn request_header_question_mark_is_refused() {
        let error = compile_err("example.com {\n request_header ?X-Foo bar\n}");
        assert!(error.contains("request_header"), "got {error}");
    }

    /// ⏭️ `>` and `defer` ask for the operation to happen after the handler
    /// chain, which is the only moment this server applies response headers
    /// anyway. Accepted, and the prefix must not end up in the header's name.
    #[test]
    fn header_defer_spellings_are_accepted_and_do_not_rename_the_header() {
        let config = crate::compile(
            "example.com {\n    header >X-Foo bar\n    header {\n        defer\n        \
             X-Baz qux\n    }\n    respond \"x\"\n}",
        )
        .unwrap();
        let route = &config.servers[0].routes[0];
        let sets: Vec<_> = handlers_of(&route.handler)
            .into_iter()
            .filter_map(|handler| match handler {
                HandlerConfig::Headers { set, .. } => Some(set),
                _ => None,
            })
            .collect();
        assert!(
            sets.iter().any(|set| set.contains_key("X-Foo")),
            "`>X-Foo` sets `X-Foo`, not `>X-Foo`"
        );
        assert!(
            sets.iter().any(|set| set.contains_key("X-Baz")),
            "a `defer` line must not swallow the rest of its block"
        );
    }

    #[test]
    fn header_names_the_shapes_it_cannot_express() {
        for source in [
            // 🚩 A response matcher gating the block: not implemented, and
            // named rather than treated as a header called `match`.
            "example.com {\n header {\n match {\n status 2xx\n }\n }\n}",
            // 🚩 Both at once has no defined order, so upstream refuses it.
            "example.com {\n header X-Foo bar {\n X-Baz qux\n }\n}",
        ] {
            let error = compile_err(source);
            assert!(
                error.contains("header"),
                "must be named rather than mangled; got {error} for {source}"
            );
        }
    }

    /// 🔤 `method` is a rewrite of one field, not a handler of its own.
    #[test]
    fn method_directive_sets_the_request_method() {
        let config = crate::compile("example.com {\n    method FOO\n    respond \"x\"\n}").unwrap();
        let route = &config.servers[0].routes[0];
        let found = handlers_of(&route.handler).into_iter().any(|handler| {
            matches!(
                handler,
                HandlerConfig::Rewrite {
                    method: Some(verb),
                    ..
                } if verb == "FOO"
            )
        });
        assert!(found, "`method FOO` must compile to a method rewrite");
    }

    #[test]
    fn method_directive_needs_exactly_one_verb() {
        for source in [
            "example.com {\n    method\n}",
            "example.com {\n    method GET POST\n}",
        ] {
            let error = compile_err(source);
            assert!(error.contains("method"), "got {error}");
        }
    }

    /// 🏷️ The three operations `request_header` offers, in one site.
    #[test]
    fn request_header_directive_sets_adds_and_removes() {
        let config = crate::compile(
            "example.com {\n    request_header Denis Ritchie\n    \
             request_header +Edsger Dijkstra\n    request_header -Wolfram\n    respond \"x\"\n}",
        )
        .unwrap();
        let route = &config.servers[0].routes[0];
        let mut saw_set = false;
        let mut saw_add = false;
        let mut saw_remove = false;
        for handler in handlers_of(&route.handler) {
            if let HandlerConfig::RequestHeaders {
                set, add, remove, ..
            } = handler
            {
                saw_set |= set.get("Denis").is_some_and(|value| value == "Ritchie");
                saw_add |= add.get("Edsger").is_some_and(|value| value == "Dijkstra");
                saw_remove |= remove.iter().any(|name| name == "Wolfram");
            }
        }
        assert!(saw_set && saw_add && saw_remove, "all three forms compile");
    }

    /// 📌 A field with no value sets it to the empty string, which is what a
    /// configuration written for the upstream format means by it. Refusing
    /// would make a working configuration stop working on the way over.
    #[test]
    fn request_header_without_a_value_sets_an_empty_one() {
        let config =
            crate::compile("example.com {\n    request_header X-Trace\n    respond \"x\"\n}")
                .unwrap();
        let route = &config.servers[0].routes[0];
        let found = handlers_of(&route.handler).into_iter().any(|handler| {
            matches!(handler, HandlerConfig::RequestHeaders { set, .. }
                if set.get("X-Trace").is_some_and(String::is_empty))
        });
        assert!(found, "`request_header X-Trace` sets an empty value");
    }

    /// 🧭 The prefix wins over the argument count, because that is the order
    /// the upstream parser tests them in. Deciding by arity instead would turn
    /// this line into a search-and-replace and silently change what it does.
    #[test]
    fn request_header_prefix_beats_a_third_argument() {
        let config =
            crate::compile("example.com {\n    request_header +Foo bar baz\n    respond \"x\"\n}")
                .unwrap();
        let route = &config.servers[0].routes[0];
        let found = handlers_of(&route.handler).into_iter().any(|handler| {
            matches!(handler, HandlerConfig::RequestHeaders { add, replace, .. }
                if add.get("Foo").is_some_and(|value| value == "bar") && replace.is_empty())
        });
        assert!(found, "`+Foo bar baz` appends `bar` and ignores `baz`");
    }

    #[test]
    fn request_header_three_arguments_are_a_replacement() {
        let config =
            crate::compile("example.com {\n    request_header Foo ^old$ new\n    respond \"x\"\n}")
                .unwrap();
        let route = &config.servers[0].routes[0];
        let found = handlers_of(&route.handler).into_iter().any(|handler| {
            matches!(handler, HandlerConfig::RequestHeaders { replace, .. }
                if replace.len() == 1
                    && replace[0].field == "Foo"
                    && replace[0].search_regexp == "^old$"
                    && replace[0].replace == "new")
        });
        assert!(found, "three arguments are a search-and-replace");
    }

    /// 🛡️ A bad pattern is refused while compiling, not on the request path.
    #[test]
    fn request_header_rejects_an_invalid_replacement_pattern() {
        let error = compile_err("example.com {\n    request_header Foo ( new\n}");
        assert!(error.contains("request_header"), "got {error}");
    }

    /// 📥 `max_size` is a per-route override of the site's body limit.
    #[test]
    fn request_body_directive_sets_a_max_size() {
        let config =
            crate::compile("example.com {\n    request_body {\n        max_size 1MB\n    }\n}")
                .unwrap();
        let route = &config.servers[0].routes[0];
        let found = handlers_of(&route.handler).into_iter().any(|handler| {
            // 🔢 A million bytes, not a mebibyte: `MB` is SI in this format,
            // and rounding it up to 1,048,576 would grant a 4.9 % larger limit
            // than the author asked for.
            matches!(
                handler,
                HandlerConfig::RequestBody {
                    max_size: Some(1_000_000)
                }
            )
        });
        assert!(found, "`max_size 1MB` is 1,000,000 bytes");
    }

    #[test]
    fn request_body_mebibytes_are_distinct_from_megabytes() {
        let config =
            crate::compile("example.com {\n    request_body {\n        max_size 1MiB\n    }\n}")
                .unwrap();
        let route = &config.servers[0].routes[0];
        let found = handlers_of(&route.handler).into_iter().any(|handler| {
            matches!(
                handler,
                HandlerConfig::RequestBody {
                    max_size: Some(1_048_576)
                }
            )
        });
        assert!(found, "`max_size 1MiB` is 1,048,576 bytes");
    }

    #[test]
    fn request_body_names_the_options_it_does_not_implement() {
        for option in ["read_timeout 5s", "write_timeout 5s", "set hello"] {
            let error = compile_err(&format!(
                "example.com {{\n request_body {{\n {option}\n }}\n}}"
            ));
            assert!(
                error.contains("request_body"),
                "`{option}` must be named, not dropped; got {error}"
            );
        }
    }

    /// 🔪 `abort` takes nothing at all.
    #[test]
    fn abort_directive_compiles_and_takes_no_arguments() {
        let config = crate::compile("example.com {\n    abort\n}").unwrap();
        let route = &config.servers[0].routes[0];
        assert!(
            handlers_of(&route.handler)
                .into_iter()
                .any(|handler| matches!(handler, HandlerConfig::Abort)),
            "`abort` compiles to the abort handler"
        );
        let error = compile_err("example.com {\n    abort 503\n}");
        assert!(error.contains("abort"), "got {error}");
    }

    /// 📊 The path in `metrics /metrics` is a matcher, not an argument.
    ///
    /// Upstream's handler parser refuses every positional argument and lets the
    /// registration helper claim the matcher token first, so a route matched on
    /// `/metrics` is the only reading. Written down because the two spellings
    /// look identical and mean opposite things: a path *argument* would make
    /// this endpoint answer every request on the site.
    #[test]
    fn metrics_directive_takes_a_path_matcher_and_not_an_argument() {
        let config = crate::compile(":80 {\n    metrics /metrics\n}").unwrap();
        let route = &config.servers[0].routes[0];
        assert_eq!(route.path, "/metrics", "the path became the route matcher");
        assert!(
            handlers_of(&route.handler)
                .into_iter()
                .any(|handler| matches!(
                    handler,
                    HandlerConfig::Metrics {
                        disable_openmetrics: false
                    }
                )),
            "`metrics` compiles to the metrics handler"
        );

        let config =
            crate::compile(":80 {\n    metrics /metrics {\n        disable_openmetrics\n    }\n}")
                .unwrap();
        assert!(
            handlers_of(&config.servers[0].routes[0].handler)
                .into_iter()
                .any(|handler| matches!(
                    handler,
                    HandlerConfig::Metrics {
                        disable_openmetrics: true
                    }
                )),
            "the subdirective reaches the handler"
        );

        let error = compile_err(":80 {\n    metrics /metrics extra\n}");
        assert!(error.contains("metrics"), "got {error}");
        let error = compile_err(":80 {\n    metrics {\n        disable_open_metrics\n    }\n}");
        assert!(
            error.contains("disable_open_metrics"),
            "a misspelled subdirective is named, not dropped; got {error}"
        );
    }

    /// 📊 A `metrics` block written twice merges instead of replacing.
    ///
    /// The same option can be written globally and again inside `servers`, and
    /// they are read at different points. Merging is what makes the order they
    /// appear in irrelevant; last-one-wins would make the meaning depend on the
    /// layout. Both fixtures upstream ships for this expect one merged answer.
    #[test]
    fn metrics_options_merge_across_global_and_servers_blocks() {
        let config = crate::compile(
            "{\n    metrics\n    servers :80 {\n        metrics {\n            per_host\n\
                     }\n    }\n}\n:80 {\n    respond \"Hello\"\n}",
        )
        .unwrap();
        assert!(config.global.metrics, "bare `metrics` still means collect");
        assert!(
            config.global.metrics_options.per_host,
            "the nested block's answer survived the flattening"
        );

        let config = crate::compile(
            "{\n    metrics {\n        observe_catchall_hosts\n        otlp\n    }\n}\n\
             :80 {\n    respond \"Hello\"\n}",
        )
        .unwrap();
        assert!(config.global.metrics_options.observe_catchall_hosts);
        assert!(config.global.metrics_options.otlp);
        assert!(
            !config.global.metrics_options.per_host,
            "an option nobody wrote stays off"
        );
    }

    /// 🚫 Inside `servers`, only `per_host` exists — and saying so beats
    /// "unrecognized", which sends an operator hunting for a typo that is not
    /// there. Flattening is what destroys the distinction, so the check has to
    /// happen before it.
    #[test]
    fn nested_servers_metrics_block_accepts_only_per_host() {
        for option in ["otlp", "observe_catchall_hosts"] {
            let error = compile_err(&format!(
                "{{\n    servers :80 {{\n        metrics {{\n            {option}\n\
                         }}\n    }}\n}}\n:80 {{\n    respond \"x\"\n}}"
            ));
            assert!(
                error.contains(option) && error.contains("servers"),
                "`{option}` must be refused by name and by place; got {error}"
            );
        }
        let error = compile_err(
            "{\n    servers :80 {\n        metrics {\n            per_hosts\n        }\n    }\n}\n\
             :80 {\n    respond \"x\"\n}",
        );
        assert!(error.contains("per_hosts"), "got {error}");
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

    /// 🧭 A global option the format defines and this build does not have
    /// must say so, rather than reading as a typo.
    ///
    /// `default_bind` used to be the example here; it is implemented now, so
    /// the test moved to one that is still missing. Keeping a *live* example
    /// is the point — a test pinned to an option that later gets implemented
    /// stops testing the property it was written for.
    #[test]
    fn known_caddy_global_options_are_reported_as_unsupported() {
        let error =
            compile_err("{\n    shutdown_delay 10s\n}\nexample.com {\n    respond \"x\"\n}");
        assert!(
            error.contains("not supported by Pingclair"),
            "shutdown_delay must be reported as unsupported Caddy syntax; got {error}"
        );
    }

    /// 🌐 `default_bind` reaches the sites that named no bind of their own,
    /// and leaves alone the ones that did.
    #[test]
    fn default_bind_fills_in_only_the_sites_that_named_none() {
        let config = crate::compile(
            "{\n default_bind 127.0.0.1\n}\nexample.com {\n respond \"a\"\n}\n             other.example {\n bind 10.0.0.1\n respond \"b\"\n}",
        )
        .unwrap();
        let bind_of = |name: &str| {
            config
                .servers
                .iter()
                .find(|server| server.names.iter().any(|host| host == name))
                .and_then(|server| server.bind.clone())
        };
        assert_eq!(bind_of("example.com").as_deref(), Some("127.0.0.1"));
        assert_eq!(
            bind_of("other.example").as_deref(),
            Some("10.0.0.1"),
            "a site's own bind wins over the global default"
        );
    }

    /// 🔄 A renewal window is a fraction, and the ends of the range are not
    /// fractions anyone means: zero renews after expiry, one renews always.
    #[test]
    fn renewal_window_ratio_takes_a_fraction_and_refuses_the_ends() {
        let config =
            crate::compile("{\n renewal_window_ratio 0.1666\n}\nexample.com {\n respond \"x\"\n}")
                .unwrap();
        assert_eq!(config.global.renewal_window_ratio, Some(0.1666));
        for bad in ["0", "1", "-0.5", "1.5", "soon"] {
            let error = compile_err(&format!(
                "{{\n renewal_window_ratio {bad}\n}}\nexample.com {{\n respond \"x\"\n}}"
            ));
            assert!(
                error.contains("renewal_window_ratio"),
                "`{bad}` must be refused; got {error}"
            );
        }
    }

    /// 🔗 The two `preferred_chains` spellings, and the combinations upstream
    /// refuses because they contradict each other.
    #[test]
    fn preferred_chains_reads_both_spellings_and_refuses_the_contradictions() {
        use pingclair_core::config::PreferredChains;

        let smallest =
            crate::compile("{\n preferred_chains smallest\n}\nexample.com {\n respond \"x\"\n}")
                .unwrap();
        assert_eq!(
            smallest.global.preferred_chains,
            Some(PreferredChains::Smallest)
        );

        let named = crate::compile(
            "{\n preferred_chains {\n root_common_name \"ISRG Root X1\"\n }\n}\n             example.com {\n respond \"x\"\n}",
        )
        .unwrap();
        assert_eq!(
            named.global.preferred_chains,
            Some(PreferredChains::RootCommonName(vec![
                "ISRG Root X1".to_string()
            ]))
        );

        for bad in [
            "{\n preferred_chains largest\n}\nexample.com {\n respond \"x\"\n}",
            "{\n preferred_chains smallest {\n root_common_name X\n }\n}\nexample.com {\n respond \"x\"\n}",
            "{\n preferred_chains {\n root_common_name X\n any_common_name Y\n }\n}\nexample.com {\n respond \"x\"\n}",
            "{\n preferred_chains {\n }\n}\nexample.com {\n respond \"x\"\n}",
        ] {
            let error = compile_err(bad);
            assert!(
                error.contains("preferred_chains"),
                "must be refused with its own name; got {error}"
            );
        }
    }

    #[test]
    fn known_caddy_directives_are_reported_as_unsupported() {
        // 🧭 Driven from the registry rather than naming one directive, because
        // the hand-picked example goes stale the day it gets implemented — and
        // then this test proves nothing while still passing. It named `metrics`
        // until `metrics` was implemented, at which point it was asserting that
        // a working directive fails.
        for directive in crate::adapter::recognised_but_unimplemented() {
            let error = compile_err(&format!("example.com {{\n    {directive}\n}}"));
            assert!(
                error.contains("not supported by Pingclair") || error.contains("Unknown directive"),
                "`{directive}` is recognised but unimplemented, so writing it must be \
                 refused by name; got {error}"
            );
        }
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

    /// 🗂️ One `try_files` group: the candidates its `file` matcher tries, the
    /// root they resolve under, the selection policy, and the URI the rewrite
    /// produces when that group is the one that matched.
    #[derive(Debug, PartialEq, Eq)]
    struct TryFilesGroup {
        candidates: Vec<String>,
        root: Option<String>,
        policy: Option<String>,
        rewrite_to: String,
    }

    /// 🗂️ Reads the groups back out of a compiled handler.
    ///
    /// `try_files` compiles to what upstream expands it into — a mutually
    /// exclusive `Handle` of `file`-matcher-guarded rewrites — so there is no
    /// `TryFiles` handler left to look for. Recognising it by *shape* is the
    /// price of having one implementation instead of two.
    fn try_files_groups(handler: &HandlerConfig) -> Option<Vec<TryFilesGroup>> {
        let HandlerConfig::FirstMatch { handlers } = handler else {
            return None;
        };
        handlers
            .iter()
            .map(|element| match (&element.matcher, &element.handler) {
                (
                    Some(pingclair_core::config::Matcher::File {
                        try_files,
                        root,
                        try_policy,
                        ..
                    }),
                    HandlerConfig::Rewrite {
                        replace: Some(target),
                        ..
                    },
                ) if target.starts_with("{http.matchers.file.relative}") => Some(TryFilesGroup {
                    candidates: try_files.clone(),
                    root: root.clone(),
                    policy: try_policy.clone(),
                    rewrite_to: target.clone(),
                }),
                _ => None,
            })
            .collect()
    }

    /// 🗂️ The single group a plain `try_files` line compiles to.
    fn only_try_files_group(source: &str) -> TryFilesGroup {
        let handlers = handlers(source);
        let mut groups = handlers
            .iter()
            .find_map(try_files_groups)
            .expect("try_files must survive into the compiled routes");
        assert_eq!(groups.len(), 1, "expected one group, got {groups:?}");
        groups.remove(0)
    }

    /// 🎯 The documented single-page-application pattern, pasted unchanged.
    /// Before this it did not compile at all: `try_files` was refused as an
    /// unimplemented directive, so the first page of the migration guide was
    /// also the first thing to fail.
    #[test]
    fn the_documented_spa_pattern_compiles() {
        let group = only_try_files_group(
            "example.com {\n\
             \troot * /srv\n\
             \tencode gzip\n\
             \ttry_files {path} /index.html\n\
             \tfile_server\n\
             }",
        );
        assert_eq!(
            group.candidates,
            ["{path}".to_string(), "/index.html".to_string()]
        );
        assert_eq!(
            group.root.as_deref(),
            Some("/srv"),
            "try_files must capture the site root, or every candidate is looked up at the \
             filesystem root and the pattern answers 404 for every application route"
        );
        assert_eq!(
            group.rewrite_to, "{http.matchers.file.relative}",
            "the rewrite target is whichever candidate the matcher picked"
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
                    HandlerConfig::FileServer { .. } => name == "file_server",
                    other => name == "try_files" && try_files_groups(other).is_some(),
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

    /// 🎯 The `*` matcher token is data-free: `rewrite * /new` must replace
    /// the path like the bare two-argument form, not reach the regex reader.
    #[test]
    fn rewrite_accepts_the_match_everything_token() {
        let handlers = handlers("example.com {\n\trewrite * /new\n\trespond \"ok\"\n}");
        assert!(
            matches!(
                &handlers[0],
                HandlerConfig::Rewrite {
                    replace: Some(target),
                    ..
                } if target == "/new"
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

    /// 🧭 A candidate may name anything the request can answer. `{uri}` was
    /// refused outright until the directive started expanding into the `file`
    /// matcher, which has resolved a wider set all along.
    #[test]
    fn try_files_accepts_the_placeholders_the_matcher_resolves() {
        for candidate in [
            "{uri}",
            "{host}",
            "{http.request.header.X-Tenant}",
            "{re.1}",
        ] {
            let group = only_try_files_group(&format!(
                "example.com {{\n\troot * /srv\n\ttry_files {candidate} /index.html\n}}"
            ));
            assert_eq!(
                group.candidates[0], candidate,
                "{candidate} must reach the matcher unchanged"
            );
        }
    }

    /// 🚫 A name the matcher cannot resolve would be looked up as a literal
    /// filename containing braces — a misconfiguration that behaves exactly
    /// like a missing file.
    #[test]
    fn try_files_refuses_a_placeholder_it_cannot_expand() {
        let message =
            compile("example.com {\n\troot * /srv\n\ttry_files {env.HOME} /index.html\n}")
                .expect_err("an unexpandable placeholder must be refused")
                .to_string();
        assert!(message.contains("{env.HOME}"), "got {message}");
    }

    /// 🧭 A candidate carrying a query string gets its own group, because the
    /// rewrite it produces is different: this candidate replaces the request's
    /// query, while the ones beside it leave it alone. The groups are mutually
    /// exclusive, so only the first matching rewrite runs.
    #[test]
    fn a_candidate_with_a_query_gets_its_own_rewrite_target() {
        let handlers = handlers(
            "example.com {\n\troot * /srv\n\ttry_files {path} /index.php?{query}\n\tfile_server\n}",
        );
        let groups = handlers
            .iter()
            .find_map(try_files_groups)
            .expect("try_files must survive into the compiled routes");
        assert_eq!(
            groups,
            vec![
                TryFilesGroup {
                    candidates: vec!["{path}".to_string()],
                    root: Some("/srv".to_string()),
                    policy: None,
                    rewrite_to: "{http.matchers.file.relative}".to_string(),
                },
                TryFilesGroup {
                    candidates: vec!["/index.php".to_string()],
                    root: Some("/srv".to_string()),
                    policy: None,
                    rewrite_to: "{http.matchers.file.relative}?{query}".to_string(),
                },
            ]
        );
    }

    /// 🎲 The `policy` block reaches the matcher that acts on it.
    #[test]
    fn try_files_carries_its_policy_to_the_matcher() {
        let group = only_try_files_group(
            "example.com {\n\
             \troot * /srv\n\
             \ttry_files {path} /index.php {\n\
             \t\tpolicy first_exist_fallback\n\
             \t}\n\
             }",
        );
        assert_eq!(group.policy.as_deref(), Some("first_exist_fallback"));
    }

    /// 🚫 An unrecognised policy matches nothing at all, which on a live site
    /// reads as "none of the candidates exist" — the symptom of a typo in a
    /// filename, not of a typo in the policy.
    #[test]
    fn try_files_refuses_an_unknown_policy() {
        compile("example.com {\n\troot * /srv\n\ttry_files {path} {\n\t\tpolicy newest\n\t}\n}")
            .expect_err("an unknown policy must be refused");
        compile("example.com {\n\troot * /srv\n\ttry_files {path} {\n\t\tsplit_path .php\n\t}\n}")
            .expect_err("an unknown subdirective must be refused");
    }

    /// 🔗 The directory-candidate form, which needs the lexer to keep
    /// `{path}/` as one word. It used to tokenize into `{path}` and `/`, and
    /// the stray `/` matched the site root on every request — so the site
    /// served its shell for every URL and looked like it worked.
    #[test]
    fn a_slashed_placeholder_candidate_stays_one_candidate() {
        let group = only_try_files_group(
            "example.com {\n\troot * /srv\n\ttry_files {path} {path}/ /index.html\n\tfile_server\n}",
        );
        assert_eq!(
            group.candidates,
            [
                "{path}".to_string(),
                "{path}/".to_string(),
                "/index.html".to_string()
            ],
            "`{{path}}/` is one candidate; splitting it adds a `/` that matches the site root \
             on every request"
        );
    }

    /// 🔍 A glob candidate compiles now that something expands it. It used to
    /// be refused, on the grounds that this crate would look for a file whose
    /// name really contained an asterisk.
    #[test]
    fn a_glob_candidate_reaches_the_matcher() {
        let group =
            only_try_files_group("example.com {\n\troot * /srv\n\ttry_files {path}*.html\n}");
        assert_eq!(group.candidates, ["{path}*.html".to_string()]);
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
    /// 🔒 Caddy's own argon2id fixture (`antitiming`, m=47104 t=1 p=1).
    const ARGON2ID: &str = "$argon2id$v=19$m=47104,t=1,p=1$P2nzckEdTZ3bxCiBCkRTyA$xQL3Z32eo5jKl7u5tcIsnEKObYiyNZQQf5/4sAau6Pg";

    fn basic_auth_of(
        source: &str,
    ) -> (
        String,
        Vec<(String, String)>,
        pingclair_core::config::BasicAuthAlgorithm,
    ) {
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
        let algorithm = credentials
            .first()
            .map(|credential| credential.algorithm)
            .expect("a basic_auth block has at least one credential");
        (
            realm,
            credentials
                .into_iter()
                .map(|credential| (credential.username, credential.password))
                .collect(),
            algorithm,
        )
    }

    #[test]
    fn the_documented_form_compiles() {
        let (realm, accounts, algorithm) = basic_auth_of(&format!(
            "example.com {{\n\tbasic_auth bcrypt \"Admin Area\" {{\n\t\tadmin {HASH}\n\t}}\n\trespond \"ok\"\n}}"
        ));
        assert_eq!(realm, "Admin Area");
        assert_eq!(accounts, vec![("admin".to_string(), HASH.to_string())]);
        assert_eq!(
            algorithm,
            pingclair_core::config::BasicAuthAlgorithm::Bcrypt
        );
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
            let (_, accounts, algorithm) = basic_auth_of(&source);
            assert_eq!(accounts.len(), 1, "{source}");
            assert_eq!(
                algorithm,
                pingclair_core::config::BasicAuthAlgorithm::Bcrypt,
                "the default algorithm is bcrypt: {source}"
            );
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

    /// 🔒 `argon2id` is a declared algorithm, and the credential is verified
    /// against it rather than compared as literal text.
    #[test]
    fn argon2id_is_accepted_by_name() {
        let (realm, accounts, algorithm) = basic_auth_of(&format!(
            "example.com {{\n\tbasic_auth argon2id \"Admin Area\" {{\n\t\tadmin {ARGON2ID}\n\t}}\n\trespond \"ok\"\n}}"
        ));
        assert_eq!(realm, "Admin Area");
        assert_eq!(accounts, vec![("admin".to_string(), ARGON2ID.to_string())]);
        assert_eq!(
            algorithm,
            pingclair_core::config::BasicAuthAlgorithm::Argon2id
        );
    }

    /// 🚫 A credential that is not a valid hash of the declared algorithm is
    /// refused — including an argon2id hash under the bcrypt default, which
    /// would otherwise authenticate anyone who typed the hash.
    #[test]
    fn a_hash_of_the_wrong_algorithm_is_refused() {
        let message = compile(&format!(
            "example.com {{\n\tbasic_auth {{\n\t\tadmin {ARGON2ID}\n\t}}\n}}"
        ))
        .expect_err("an argon2id hash under the bcrypt default must be refused")
        .to_string();
        assert!(
            message.contains("bcrypt") && message.contains("admin"),
            "the error must name the algorithm and the account: {message}"
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

// MARK: - error directive

/// 🚨 The `error` directive grammar, as upstream parses it: a lone three-digit
/// number is the status, a lone word is the message with 500, two arguments
/// are message then status, and a block may add `message <text…>`.
#[cfg(test)]
mod error_directive_tests {
    use crate::compile;
    use pingclair_core::config::HandlerConfig;

    fn error_of(source: &str) -> (u16, Option<String>) {
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
                .find(|element| matches!(&element.handler, HandlerConfig::Error { .. }))
                .map(|element| element.handler)
                .expect("an error handler"),
            single => single,
        };
        let HandlerConfig::Error { status, message } = handler else {
            panic!("expected error");
        };
        (status, message)
    }

    #[test]
    fn a_lone_three_digit_number_is_the_status() {
        let (status, message) = error_of("example.com {\n\terror 404\n}");
        assert_eq!(status, 404);
        assert_eq!(message, None);
    }

    #[test]
    fn a_lone_word_is_the_message_with_status_500() {
        let (status, message) = error_of("example.com {\n\terror \"oops\"\n}");
        assert_eq!(status, 500);
        assert_eq!(message.as_deref(), Some("oops"));
    }

    #[test]
    fn message_and_status_are_two_arguments() {
        let (status, message) = error_of("example.com {\n\terror \"Unauthorized\" 403\n}");
        assert_eq!(status, 403);
        assert_eq!(message.as_deref(), Some("Unauthorized"));
    }

    #[test]
    fn the_block_may_carry_the_message() {
        let (status, message) =
            error_of("example.com {\n\terror 404 {\n\t\tmessage \"not here\"\n\t}\n}");
        assert_eq!(status, 404);
        assert_eq!(message.as_deref(), Some("not here"));
    }

    #[test]
    fn a_two_digit_number_is_a_message_not_a_status() {
        let (status, message) = error_of("example.com {\n\terror 99\n}");
        assert_eq!(status, 500);
        assert_eq!(message.as_deref(), Some("99"));
    }

    #[test]
    fn malformed_shapes_are_refused() {
        for source in [
            // 🚫 A positional message plus a block message is contradictory.
            "example.com {\n\terror \"oops\" 404 {\n\t\tmessage \"again\"\n\t}\n}",
            // 🚫 The block's `message` needs a value.
            "example.com {\n\terror 404 {\n\t\tmessage\n\t}\n}",
            // 🚫 An unknown subdirective is a typo.
            "example.com {\n\terror 404 {\n\t\tbody \"x\"\n\t}\n}",
            // 🚫 The two-argument status must be numeric and in range.
            "example.com {\n\terror \"oops\" 12\n}",
            "example.com {\n\terror \"oops\" 999\n}",
            // 🚫 More than message + status has no reading.
            "example.com {\n\terror \"a\" 404 extra\n}",
        ] {
            compile(source).expect_err(&format!("must be refused:\n{source}"));
        }
    }
}

// MARK: - handle_errors

/// 🚨 `handle_errors [<codes…>] { … }` registers a status-selective error
/// route: three-digit statuses and `Nxx` ranges OR together, no codes means
/// every error, and the block is a route body with `handle` blocks keeping
/// their mutually exclusive semantics.
#[cfg(test)]
mod handle_errors_tests {
    use crate::compile;
    use pingclair_core::config::HandlerConfig;

    fn error_routes_of(source: &str) -> Vec<pingclair_core::config::ErrorRouteConfig> {
        let config = compile(source).unwrap_or_else(|error| panic!("must compile: {error}"));
        config
            .servers
            .into_iter()
            .next()
            .expect("one server")
            .error_routes
    }

    #[test]
    fn exact_codes_compile() {
        let routes =
            error_routes_of("example.com {\n\thandle_errors 404 410 {\n\t\trespond \"x\"\n\t}\n}");
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].codes, vec![404, 410]);
        assert!(routes[0].hundreds.is_empty());
        assert_eq!(routes[0].handlers.len(), 1);
    }

    #[test]
    fn range_codes_compile() {
        let routes =
            error_routes_of("example.com {\n\thandle_errors 4xx {\n\t\trespond \"x\"\n\t}\n}");
        assert_eq!(routes[0].hundreds, vec![4]);
    }

    #[test]
    fn codes_and_ranges_can_combine() {
        let routes =
            error_routes_of("example.com {\n\thandle_errors 500 3xx {\n\t\trespond \"x\"\n\t}\n}");
        assert_eq!(routes[0].codes, vec![500]);
        assert_eq!(routes[0].hundreds, vec![3]);
    }

    #[test]
    fn no_codes_is_the_catch_all() {
        let routes = error_routes_of("example.com {\n\thandle_errors {\n\t\trespond \"x\"\n\t}\n}");
        assert!(routes[0].codes.is_empty() && routes[0].hundreds.is_empty());
        assert!(routes[0].matches(404) && routes[0].matches(503));
    }

    /// 🧵 Nested `handle` blocks each become their own sequential group.
    ///
    /// They stay mutually exclusive with one another, but that comes from each
    /// block *answering* rather than from the block swallowing its own
    /// contents: the enclosing group stops at the first element that writes a
    /// response. Asserting the container variant here is what would catch a
    /// regression back to the first-match reading, which used to make a block
    /// whose first directive was non-terminal answer nothing at all.
    #[test]
    fn handle_blocks_inside_error_routes_are_sequential_groups() {
        let routes = error_routes_of(
            "example.com {\n\thandle_errors 404 {\n\t\thandle /en/* {\n\t\t\trespond \"en\"\n\t\t}\n\t\thandle {\n\t\t\trespond \"default\"\n\t\t}\n\t}\n}",
        );
        assert_eq!(routes[0].handlers.len(), 2);
        assert!(matches!(
            routes[0].handlers[0].handler,
            HandlerConfig::Pipeline { .. }
        ));
    }

    #[test]
    fn malformed_shapes_are_refused() {
        for source in [
            "example.com {\n\thandle_errors abc {\n\t\trespond \"x\"\n\t}\n}",
            "example.com {\n\thandle_errors 40 {\n\t\trespond \"x\"\n\t}\n}",
            "example.com {\n\thandle_errors 404\n}",
            "example.com {\n\thandle_errors {\n\t}\n}",
        ] {
            compile(source).expect_err(&format!("must be refused:\n{source}"));
        }
    }
}

// MARK: - vars

/// 🧰 `vars` gives the request a place to store values: inline and block
/// forms, optional matchers (with `*` meaning "every request"), and rules
/// sorted least specific first so the most specific value wins.
#[cfg(test)]
mod vars_tests {
    use crate::compile;
    use pingclair_core::config::Matcher;

    fn vars_routes_of(source: &str) -> Vec<pingclair_core::config::VarsRule> {
        let config = compile(source).unwrap_or_else(|error| panic!("must compile: {error}"));
        config
            .servers
            .into_iter()
            .next()
            .expect("one server")
            .vars_routes
    }

    #[test]
    fn inline_and_block_forms_compile() {
        let routes = vars_routes_of(
            "example.com {\n\tvars foo bar\n\tvars {\n\t\tabc true\n\t\tdef 1\n\t}\n}",
        );
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].values.get("foo").map(String::as_str), Some("bar"));
        assert_eq!(routes[1].values.len(), 2);
        assert_eq!(
            routes[1].values.get("abc").map(String::as_str),
            Some("true")
        );
    }

    #[test]
    fn matchers_and_the_wildcard_compile() {
        let routes = vars_routes_of("example.com {\n\tvars /foo foo middle\n\tvars * foo first\n}");
        assert_eq!(routes.len(), 2);
        let path_rule = routes
            .iter()
            .find(|rule| rule.matcher.is_some())
            .expect("a path-scoped rule");
        assert!(matches!(path_rule.matcher, Some(Matcher::Path { .. })));
        let catch_all = routes
            .iter()
            .find(|rule| rule.matcher.is_none())
            .expect("a catch-all rule");
        assert!(
            catch_all.matcher.is_none(),
            "the `*` matcher is the same as no matcher"
        );
    }

    #[test]
    fn rules_sort_least_specific_first() {
        let routes = vars_routes_of(
            "example.com {\n\tvars /foobar foo last\n\tvars /foo foo middle-last\n\t\
             vars /foo* foo middle-first\n\tvars * foo first\n}",
        );
        assert!(routes[0].matcher.is_none(), "the catch-all runs first");
        assert!(
            matches!(&routes[1].matcher, Some(Matcher::Path { patterns }) if patterns[0] == "/foo*"),
            "then the shorter glob: {:?}",
            routes[1].matcher
        );
        assert!(
            matches!(&routes[2].matcher, Some(Matcher::Path { patterns }) if patterns[0] == "/foo"),
            "then the exact path: {:?}",
            routes[2].matcher
        );
        assert!(
            matches!(&routes[3].matcher, Some(Matcher::Path { patterns }) if patterns[0] == "/foobar"),
            "the most specific runs last: {:?}",
            routes[3].matcher
        );
    }

    #[test]
    fn malformed_shapes_are_refused() {
        for source in [
            "example.com {\n\tvars\n}",
            "example.com {\n\tvars foo\n}",
            "example.com {\n\tvars foo bar baz\n}",
            "example.com {\n\tvars {\n\t\tabc\n\t}\n}",
            "example.com {\n\tvars {\n\t\tabc 1 2\n\t}\n}",
        ] {
            compile(source).expect_err(&format!("must be refused:\n{source}"));
        }
    }

    #[test]
    fn the_vars_matcher_compiles_to_a_variable_lookup() {
        let config = compile("example.com {\n\t@m vars foo bar\n\trespond @m \"hit\"\n}")
            .expect("a vars matcher must compile");
        let route = &config.servers[0].routes[0];
        assert!(matches!(
            &route.matcher,
            Some(Matcher::Vars { name, values })
                if name == "foo" && values == &["bar".to_string()]
        ));
    }

    #[test]
    fn the_vars_matcher_refuses_placeholder_keys() {
        let error = compile(
            "example.com {\n\t@m vars \"{http.request.uri}\" \"/x\"\n\trespond @m \"hit\"\n}",
        )
        .expect_err("a placeholder key must be refused")
        .to_string();
        assert!(error.contains("placeholder"), "{error}");
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
            | HandlerConfig::FirstMatch { handlers }
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
        assert!(matches!(
            handlers[0].handler,
            HandlerConfig::Pipeline { .. }
        ));
        assert!(handlers[1].matcher.is_none());
        assert!(matches!(
            handlers[1].handler,
            HandlerConfig::Pipeline { .. }
        ));
    }

    /// 📌 A directive whose first argument merely looks like a matcher stays
    /// data — `file_server /var/www` is a root, not a path matcher.
    #[test]
    fn a_directive_whose_argument_is_data_is_not_caught() {
        compile("example.com {\n\troute {\n\t\tfile_server /var/www\n\t}\n}")
            .expect("a file server root is data, not a matcher");
    }
}

// MARK: - php_fastcgi

/// 🐘 `php_fastcgi` expands into the guarded pipeline upstream's shortcut
/// produces: canonical redirect, try_files rewrite, FastCGI proxy.
#[cfg(test)]
mod php_fastcgi_tests {
    use crate::compile;
    use pingclair_core::config::{HandlerConfig, Matcher};

    fn proxy_from(source: &str) -> HandlerConfig {
        let config = compile(source).unwrap_or_else(|error| panic!("must compile: {error}"));
        let handler = &config.servers[0].routes[0].handler;
        let HandlerConfig::Pipeline { handlers } = handler else {
            panic!("php_fastcgi must compile to a pipeline, got {handler:?}");
        };
        handlers
            .iter()
            .find_map(|element| match &element.handler {
                HandlerConfig::ReverseProxy(config) => {
                    Some(HandlerConfig::ReverseProxy(config.clone()))
                }
                _ => None,
            })
            .expect("the pipeline must contain a reverse proxy")
    }

    /// 🎯 The default expansion carries the three matcher-guarded elements.
    #[test]
    fn php_fastcgi_expands_into_three_guarded_elements() {
        let config = compile("example.com {\n\tphp_fastcgi localhost:9000\n}").unwrap();
        let HandlerConfig::Pipeline { handlers } = &config.servers[0].routes[0].handler else {
            panic!("expected a pipeline");
        };
        assert_eq!(handlers.len(), 3, "redirect, rewrite, and proxy");
        assert!(matches!(&handlers[0].matcher, Some(Matcher::And(_, _))));
        assert!(matches!(
            &handlers[0].handler,
            HandlerConfig::Redirect { code: 308, .. }
        ));
        assert!(matches!(&handlers[1].matcher, Some(Matcher::File { .. })));
        assert!(matches!(
            &handlers[1].handler,
            HandlerConfig::Rewrite {
                replace: Some(_),
                ..
            }
        ));
        assert!(matches!(
            &handlers[2].matcher,
            Some(Matcher::Path { patterns }) if patterns == &["*.php"]
        ));
    }

    /// 🎯 `index off` skips the redirect and rewrite, leaving only the proxy.
    #[test]
    fn php_fastcgi_index_off_keeps_only_the_proxy() {
        let config =
            compile("example.com {\n\tphp_fastcgi localhost:9000 {\n\t\tindex off\n\t}\n}")
                .unwrap();
        let HandlerConfig::Pipeline { handlers } = &config.servers[0].routes[0].handler else {
            panic!("expected a pipeline");
        };
        assert_eq!(handlers.len(), 1);
        assert!(matches!(
            handlers[0].handler,
            HandlerConfig::ReverseProxy(_)
        ));
    }

    /// 🧵 The shortcut's subdirectives reach the FastCGI transport.
    #[test]
    fn php_fastcgi_subdirectives_reach_the_transport() {
        let handler = proxy_from(
            "example.com {\n\tphp_fastcgi localhost:9000 localhost:9001 {\n\t\tsplit .php .php5\n\t\tenv FOO bar\n\t\troot /var/www\n\t\tdial_timeout 3s\n\t\theader_up X-Method {http.request.method}\n\t\tlb_policy round_robin\n\t}\n}",
        );
        let HandlerConfig::ReverseProxy(config) = handler else {
            panic!("expected a reverse proxy");
        };
        let fastcgi = config.fastcgi.expect("fastcgi transport");
        assert_eq!(fastcgi.split_path, [".php", ".php5"]);
        assert_eq!(fastcgi.env.get("FOO").map(String::as_str), Some("bar"));
        assert_eq!(fastcgi.root.as_deref(), Some("/var/www"));
        assert_eq!(fastcgi.dial_timeout_ms, Some(3_000));
        // 🧭 Both addresses have to survive into the compiled peer list, or
        // the load balancer below has only one peer to choose between.
        assert_eq!(config.upstreams, ["localhost:9000", "localhost:9001"]);
        assert_eq!(
            config.headers_up.get("X-Method").map(String::as_str),
            Some("{http.request.method}")
        );
        assert_eq!(config.load_balance.strategy, "round_robin");
    }

    /// 🧵 `transport fastcgi` inside a plain reverse_proxy is parsed too.
    #[test]
    fn reverse_proxy_transport_fastcgi_is_parsed() {
        let config = compile(
            "example.com {\n\treverse_proxy localhost:9000 {\n\t\ttransport fastcgi {\n\t\t\tsplit .php\n\t\t\tenv FOO bar\n\t\t}\n\t}\n}",
        )
        .unwrap();
        let HandlerConfig::ReverseProxy(config) = &config.servers[0].routes[0].handler else {
            panic!("expected a reverse proxy");
        };
        let fastcgi = config.fastcgi.as_ref().expect("fastcgi transport");
        assert_eq!(fastcgi.split_path, [".php"]);
        assert_eq!(fastcgi.env.get("FOO").map(String::as_str), Some("bar"));
    }

    /// 🚫 A non-ASCII split delimiter is refused, not silently unmatched.
    #[test]
    fn fastcgi_split_path_refuses_non_ascii() {
        let error =
            compile("example.com {\n\tphp_fastcgi localhost:9000 {\n\t\tsplit .php 分割\n\t}\n}")
                .expect_err("non-ASCII split paths must be refused")
                .to_string();
        assert!(error.contains("non-ASCII"), "got {error}");
    }

    /// 🧭 `handle_response` accepts the root/rewrite/file_server shape the
    /// `php_fastcgi` error-page fixture uses.
    #[test]
    fn php_fastcgi_handle_response_accepts_an_error_page_subroute() {
        let handler = proxy_from(
            r#"example.com {
                php_fastcgi localhost:9000 {
                    @err status 4xx
                    handle_response @err {
                        root * /errors
                        rewrite * /{http.reverse_proxy.status_code}.html
                        file_server
                    }
                }
            }"#,
        );
        let HandlerConfig::ReverseProxy(config) = handler else {
            panic!("expected a reverse proxy");
        };
        let entry = config
            .handle_response
            .first()
            .expect("one handle_response entry");
        assert_eq!(
            entry
                .matcher
                .as_ref()
                .map(|matcher| matcher.status_codes.as_slice()),
            Some(&[4][..])
        );
        assert_eq!(entry.handlers.len(), 3);
        assert!(matches!(
            &entry.handlers[0],
            HandlerConfig::Vars { values } if values.get("root").is_some()
        ));
        assert!(matches!(
            &entry.handlers[1],
            HandlerConfig::Rewrite {
                replace: Some(_),
                ..
            }
        ));
        assert!(matches!(
            &entry.handlers[2],
            HandlerConfig::FileServer { .. }
        ));
    }

    /// 📂 A named `file` matcher parses at the site level.
    #[test]
    fn named_file_matcher_is_parsed() {
        let config = compile(
            "example.com {\n\t@php {\n\t\tfile {\n\t\t\ttry_files {path} index.php\n\t\t\tsplit_path .php\n\t\t}\n\t}\n\trespond @php \"x\"\n}",
        )
        .unwrap();
        let route = &config.servers[0].routes[0];
        assert!(matches!(&route.matcher, Some(Matcher::File { .. })));
    }
}
