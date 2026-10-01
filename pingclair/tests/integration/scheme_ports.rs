// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

use super::TestServer;

#[tokio::test]
async fn scheme_only_http_uses_global_port() {
    let mut server = TestServer::new_pingclairfile(
        r#"
        {
            admin off
            http_port __PINGCLAIR_TEST_PORT__
        }
        http://127.0.0.1 {
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
            respond "plain"
        }
    "#,
    );
    assert!(server.wait_until_ready().await);
    let response = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .get(server.url(0, "/"))
        .header("Host", "127.0.0.1")
        .send()
        .await
        .unwrap();
    assert_eq!(
        (response.status().as_u16(), response.text().await.unwrap()),
        (200, "plain".into())
    );
}

#[tokio::test]
async fn scheme_only_https_uses_global_port() {
    let mut server = TestServer::new_pingclairfile(
        r#"
        {
            admin off
            http_port __PINGCLAIR_TEST_HTTP_PORT__
            https_port __PINGCLAIR_TEST_HTTPS_PORT__
        }
        https://example.test {
            tls internal
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
            respond "secure"
        }
    "#,
    );
    assert!(server.wait_until_tls_ready("example.test").await);
    let response = reqwest::Client::builder()
        .no_proxy()
        .danger_accept_invalid_certs(true)
        .resolve("example.test", server.address(0))
        .build()
        .unwrap()
        .get(server.tls_url(0, "example.test", "/"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        (response.status().as_u16(), response.text().await.unwrap()),
        (200, "secure".into())
    );
}
