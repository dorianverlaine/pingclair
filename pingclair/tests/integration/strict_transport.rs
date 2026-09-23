// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔐 `Strict-Transport-Security` from a Pingclairfile.
//!
//! There is no dedicated HSTS directive, in Pingclair or in the format it
//! follows: an operator writes `header Strict-Transport-Security "max-age=…"`
//! like any other response header. These tests pin that spelling down, because
//! it is the only way a Pingclairfile can turn HSTS on.

use super::TestServer;

/// 🔐 The one fixture every test here uses: a `tls internal` site that sets
/// the header itself, reachable over TLS on `address(0)`.
const STS_SITE: &str = r#"
    {
        admin off
        http_port __PINGCLAIR_TEST_HTTP_PORT__
        https_port __PINGCLAIR_TEST_HTTPS_PORT__
    }

    https://hsts.test:__PINGCLAIR_TEST_HTTPS_PORT__ {
        tls internal
        header Strict-Transport-Security "max-age=60; includeSubDomains"

        @readiness path __PINGCLAIR_TEST_READINESS_PATH__
        respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
        respond "hsts-ok"
    }
"#;

/// 🔐 Builds a client that trusts the fixture's internal authority and
/// resolves `host` to `address`.
fn trusting_client(
    server: &TestServer,
    host: &str,
    address: std::net::SocketAddr,
) -> reqwest::Client {
    let root_path = server
        ._temp_dir
        .path()
        .join("tls/pki/authorities/local/root.crt");
    let root = reqwest::Certificate::from_pem(&std::fs::read(root_path).unwrap()).unwrap();
    reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(root)
        .resolve(host, address)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

/// 🔐 `header Strict-Transport-Security …` reaches a TLS response unchanged,
/// on a `tls internal` site that has no JSON security policy at all.
#[tokio::test]
async fn test_header_directive_sets_strict_transport_security_over_tls() {
    let mut server = TestServer::new_pingclairfile(STS_SITE);
    assert!(
        server.wait_until_tls_ready("hsts.test").await,
        "the `tls internal` site did not start"
    );
    let client = trusting_client(&server, "hsts.test", server.address(0));
    let response = client
        .get(server.tls_url(0, "hsts.test", "/"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let values: Vec<_> = response
        .headers()
        .get_all("strict-transport-security")
        .iter()
        .map(|value| value.to_str().unwrap().to_owned())
        .collect();
    assert_eq!(values, ["max-age=60; includeSubDomains"]);
}

/// 🚫 One site served over both plaintext and TLS sends the header only on
/// the TLS half (RFC 6797 §7.2).
///
/// 🤡 The site's `tls internal` block is cloned onto its `http://` half, and
/// the header decision used to ask "does this site have TLS?" rather than
/// "did this response travel over TLS?" — so the plaintext answer carried it
/// too.
#[tokio::test]
async fn test_plaintext_half_of_a_site_never_sends_strict_transport_security() {
    let config = r#"
        {
            admin off
            http_port __PINGCLAIR_TEST_HTTP_PORT__
            https_port __PINGCLAIR_TEST_HTTPS_PORT__
        }

        https://hsts.test:__PINGCLAIR_TEST_HTTPS_PORT__, http://hsts.test:__PINGCLAIR_TEST_HTTP_PORT__ {
            tls internal
            header Strict-Transport-Security "max-age=60"

            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
            respond "hsts-ok"
        }
    "#;
    let mut server = TestServer::new_pingclairfile(config);
    assert!(
        server.wait_until_tls_ready("hsts.test").await,
        "the mixed-scheme site did not start"
    );

    let tls = trusting_client(&server, "hsts.test", server.address(0))
        .get(server.tls_url(0, "hsts.test", "/"))
        .send()
        .await
        .unwrap();
    assert_eq!(tls.status(), reqwest::StatusCode::OK);
    assert_eq!(
        tls.headers().get("strict-transport-security").unwrap(),
        "max-age=60"
    );

    let plain_address = server.listener_address(0, 1);
    let plain = trusting_client(&server, "hsts.test", plain_address)
        .get(format!("http://hsts.test:{}/", plain_address.port()))
        .send()
        .await
        .unwrap();
    assert_eq!(plain.status(), reqwest::StatusCode::OK);
    assert_eq!(
        plain.headers().get("strict-transport-security"),
        None,
        "a plaintext response carried Strict-Transport-Security"
    );
    assert_eq!(plain.text().await.unwrap(), "hsts-ok");
}
