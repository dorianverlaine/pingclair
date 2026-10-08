// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

use pingclair_core::config::{HandlerConfig, UpstreamTlsConfig};

#[test]
fn forward_auth_transport_tls_reaches_the_compiled_subrequest() {
    let config = crate::compile(
        r#"example.com {
            route {
                forward_auth https://auth.test {
                    uri /check
                    transport http {
                        tls
                        tls_server_name auth.internal
                        tls_trusted_ca_certs /ca/one.pem /ca/two.pem
                        tls_client_auth /client/cert.pem /client/key.pem
                    }
                }
                respond "allowed"
            }
        }"#,
    )
    .expect("forward_auth TLS options compile");
    let HandlerConfig::Pipeline { handlers } = &config.servers[0].routes[0].handler else {
        panic!("auth and response should form a pipeline");
    };
    let HandlerConfig::ReverseProxy(auth) = &handlers[0].handler else {
        panic!("forward_auth should become a proxy subrequest");
    };
    assert_eq!(
        *auth.upstream_tls,
        UpstreamTlsConfig {
            enable: true,
            server_name: Some("auth.internal".into()),
            trusted_ca_certs: vec!["/ca/one.pem".into(), "/ca/two.pem".into()],
            client_cert: Some("/client/cert.pem".into()),
            client_key: Some("/client/key.pem".into()),
            insecure_skip_verify: false,
        }
    );
    assert!(auth.subrequest.is_some());
}

#[test]
fn forward_auth_transport_rejects_conflicting_or_unsupported_options() {
    for (options, expected) in [
        (
            "tls_trusted_ca_certs /ca.pem\n tls_insecure_skip_verify",
            "cannot be combined",
        ),
        ("read_timeout 1s", "only TLS transport options"),
        ("tls_client_auth /client.pem", "tls_client_auth"),
    ] {
        let source = format!(
            "example.com {{\n forward_auth https://auth.test {{\n uri /check\n transport http {{\n {options}\n }}\n }}\n respond \"allowed\"\n}}"
        );
        let error = crate::compile(&source).expect_err("unsupported transport must fail");
        assert!(error.to_string().contains(expected), "{error}");
    }
}

#[test]
fn legacy_forward_auth_json_keeps_default_tls() {
    let legacy: pingclair_core::config::ForwardAuthConfig = serde_json::from_str(
        r#"{"upstream":"https://auth.test","uri":"/check","copy_headers":[]}"#,
    )
    .expect("legacy JSON remains accepted");
    assert_eq!(
        *legacy.as_reverse_proxy_subrequest().upstream_tls,
        UpstreamTlsConfig::default()
    );
    assert!(
        serde_json::to_value(legacy)
            .unwrap()
            .get("upstream_tls")
            .is_none(),
        "legacy documents retain their serialized shape"
    );
}
