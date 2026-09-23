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
