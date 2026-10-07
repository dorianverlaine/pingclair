// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🃏 A wildcard site's manual certificate serves the names it covers.

use super::*;

/// 🔐 A `*.sandbox.test` site with `tls cert.pem key.pem` answers beneath it.
///
/// The manual table was read by exact spelling, so a handshake for
/// `other.sandbox.test` ended in `unrecognized_name` even though the
/// certificate's SAN was `*.sandbox.test` — while the same site written with
/// `tls internal` answered, because the internal authority already matched
/// wildcards (#285).
#[tokio::test]
async fn a_manual_wildcard_certificate_serves_the_names_it_covers() {
    let mut params = rcgen::CertificateParams::new(vec!["*.sandbox.test".to_string()])
        .expect("certificate parameters");
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "*.sandbox.test");
    let key = rcgen::KeyPair::generate().expect("key pair");
    let certificate = params.self_signed(&key).expect("self-signed wildcard");
    let directory = tempfile::tempdir().unwrap();
    let cert_path = directory.path().join("cert.pem");
    let key_path = directory.path().join("key.pem");
    std::fs::write(&cert_path, certificate.pem()).unwrap();
    std::fs::write(&key_path, key.serialize_pem()).unwrap();

    let mut server = TestServer::new_pingclairfile(&format!(
        r#"
        {{
            admin off
            http_port __PINGCLAIR_TEST_HTTP_PORT__
            https_port __PINGCLAIR_TEST_HTTPS_PORT__
        }}

        https://*.sandbox.test:__PINGCLAIR_TEST_HTTPS_PORT__ {{
            tls {cert} {key}

            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
            respond "wild"
        }}
        "#,
        cert = cert_path.display(),
        key = key_path.display()
    ));
    assert!(
        server.wait_until_tls_ready("other.sandbox.test").await,
        "the covered name never got a handshake"
    );

    let client = reqwest::Client::builder()
        .no_proxy()
        // 🔐 The client verifies the certificate, so a handshake that got past
        // the name check with the wrong pair would fail here.
        .add_root_certificate(reqwest::Certificate::from_pem(certificate.pem().as_bytes()).unwrap())
        .resolve("other.sandbox.test", server.address(0))
        .build()
        .unwrap();
    let response = client
        .get(server.tls_url(0, "other.sandbox.test", "/"))
        .send()
        .await
        .expect("a covered name must reach the site");
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "wild");

    // 🫥 The wildcard is one label deep: the apex is a different name, and the
    // client must be told so rather than served someone else's certificate.
    let apex = reqwest::Client::builder()
        .no_proxy()
        .danger_accept_invalid_certs(true)
        .resolve("sandbox.test", server.address(0))
        .build()
        .unwrap();
    assert!(
        apex.get(server.tls_url(0, "sandbox.test", "/"))
            .send()
            .await
            .is_err(),
        "the apex is not covered by *.sandbox.test"
    );
    server.stop();
}
