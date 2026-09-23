// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔤 A site name is one name however the operator capitalized it.
//!
//! DNS names are case-insensitive, and clients send them lowercase. A site
//! written `Example.test` used to key its manual certificate on that spelling
//! while every handshake asked for `example.test`, so the lookup missed and
//! the handshake failed with no certificate at all — after the configuration
//! had validated and startup had reported success.

use super::{TestAuthority, TestServer, presented_server_certificate};

/// 🔐 A mixed-case site with `tls <cert> <key>` serves that certificate to a
/// lowercase SNI, and answers over both HTTP/1.1 and HTTP/2.
#[tokio::test]
async fn test_mixed_case_site_serves_its_manual_certificate_to_a_lowercase_sni() {
    let authority = TestAuthority::new("Mixed Case CA");
    let (cert, key) = authority.issue(&["example.test"]);
    let expected = boring::x509::X509::from_pem(cert.as_bytes())
        .unwrap()
        .to_der()
        .unwrap();
    let material = tempfile::tempdir().expect("certificate material dir");
    let cert_path = material.path().join("server.pem");
    let key_path = material.path().join("server.key");
    std::fs::write(&cert_path, cert).expect("write server certificate");
    std::fs::write(&key_path, key).expect("write server key");

    let config = format!(
        r#"
        {{
            admin off
            http_port __PINGCLAIR_TEST_HTTP_PORT__
        }}

        https://Example.test:__PINGCLAIR_TEST_PORT__ {{
            tls {cert} {key}

            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
            respond "mixed-case-site"
        }}
        "#,
        cert = cert_path.to_string_lossy(),
        key = key_path.to_string_lossy(),
    );
    let mut server = TestServer::new_pingclairfile(&config);
    assert!(
        server.wait_until_tls_ready("example.test").await,
        "a lowercase SNI found no certificate for the site written `Example.test`"
    );
    let address = server.address(0);

    let presented =
        tokio::task::spawn_blocking(move || presented_server_certificate(address, "example.test"))
            .await
            .unwrap();
    assert_eq!(
        presented, expected,
        "the site's own certificate was not served"
    );

    // 🌐 Both TCP protocols share the handshake; the request then has to route
    // to the same site by its lowercase `Host`.
    let url = format!("https://example.test:{}/", address.port());
    for (label, builder) in [
        ("HTTP/1.1", reqwest::Client::builder().http1_only()),
        ("HTTP/2", reqwest::Client::builder().http2_prior_knowledge()),
    ] {
        let client = builder
            .no_proxy()
            .danger_accept_invalid_certs(true)
            .resolve("example.test", address)
            .build()
            .unwrap();
        let response = client.get(&url).send().await.unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK, "{label}");
        assert_eq!(response.text().await.unwrap(), "mixed-case-site", "{label}");
    }
}
