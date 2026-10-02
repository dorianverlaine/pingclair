// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🏠 A site with two addresses has a certificate for both (issue #202).
//!
//! A site written `a.test, b.test` keeps its first address as its name and
//! every address in its list of names. The certificate sources read the name
//! alone, so the second address had no internal leaf and no manual pair, and
//! its TLS handshake failed on every transport. HTTP/3 additionally seeded its
//! certificate table from the first name only, which is how the defect first
//! showed with public certificates; `scripts/test-h3-22-septembre-2026-local.sh`
//! covers that half, because this suite has no QUIC client.

use super::*;

/// 🔐 A client that trusts `root_pem` and resolves both names to the listener.
fn trusting_client(server: &TestServer, root_pem: &[u8]) -> reqwest::Client {
    let root = reqwest::Certificate::from_pem(root_pem).unwrap();
    reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(root)
        .resolve("first.test", server.address(0))
        .resolve("second.test", server.address(0))
        .http2_prior_knowledge()
        .build()
        .unwrap()
}

/// 🌐 Asks each name for `/`, recording the body or the error kind.
async fn answers(server: &TestServer, client: &reqwest::Client) -> Vec<(&'static str, String)> {
    let mut seen = Vec::new();
    for host in ["first.test", "second.test"] {
        let answer = match client.get(server.tls_url(0, host, "/")).send().await {
            Ok(response) => response.text().await.unwrap(),
            Err(error) => format!("handshake failed: {error}"),
        };
        seen.push((host, answer));
    }
    seen
}

/// 🏛️ `tls internal` issues a leaf for the second address as well.
#[tokio::test]
async fn test_internal_tls_covers_every_name_of_a_two_name_site() {
    let mut server = TestServer::new_pingclairfile(
        r#"
        {
            admin off
            http_port __PINGCLAIR_TEST_HTTP_PORT__
            https_port __PINGCLAIR_TEST_HTTPS_PORT__
        }

        https://first.test:__PINGCLAIR_TEST_HTTPS_PORT__, https://second.test:__PINGCLAIR_TEST_HTTPS_PORT__ {
            tls internal
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
            respond "served {host}"
        }
        "#,
    );
    assert!(
        server.wait_until_tls_ready("first.test").await,
        "the `tls internal` site did not start"
    );
    let root = std::fs::read(
        server
            ._temp_dir
            .path()
            .join("tls/pki/authorities/local/root.crt"),
    )
    .unwrap();

    assert_eq!(
        answers(&server, &trusting_client(&server, &root)).await,
        [
            ("first.test", "served first.test".to_owned()),
            ("second.test", "served second.test".to_owned()),
        ]
    );
}

/// 📜 One `tls <cert> <key>` pair answers for every address of its site.
#[tokio::test]
async fn test_manual_certificate_covers_every_name_of_a_two_name_site() {
    let mut params =
        rcgen::CertificateParams::new(vec!["first.test".to_string(), "second.test".to_string()])
            .expect("certificate parameters");
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "first.test");
    let key = rcgen::KeyPair::generate().expect("key pair");
    let certificate = params.self_signed(&key).expect("self-signed site");
    let files = tempfile::tempdir().expect("certificate dir");
    let cert_path = files.path().join("site.crt");
    let key_path = files.path().join("site.key");
    std::fs::write(&cert_path, certificate.pem()).unwrap();
    std::fs::write(&key_path, key.serialize_pem()).unwrap();

    let mut server = TestServer::new_pingclairfile(&format!(
        r#"
        {{
            admin off
            http_port __PINGCLAIR_TEST_HTTP_PORT__
            https_port __PINGCLAIR_TEST_HTTPS_PORT__
        }}

        https://first.test:__PINGCLAIR_TEST_HTTPS_PORT__, https://second.test:__PINGCLAIR_TEST_HTTPS_PORT__ {{
            tls {cert} {key}
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
            respond "served {{host}}"
        }}
        "#,
        cert = cert_path.display(),
        key = key_path.display(),
    ));
    assert!(
        server.wait_until_tls_ready("first.test").await,
        "the manual-certificate site did not start"
    );

    assert_eq!(
        answers(
            &server,
            &trusting_client(&server, certificate.pem().as_bytes())
        )
        .await,
        [
            ("first.test", "served first.test".to_owned()),
            ("second.test", "served second.test".to_owned()),
        ]
    );
}
