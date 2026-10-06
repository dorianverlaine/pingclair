// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🌐 A bracketed IPv6 site address without a port names a site.
//!
//! `http://[::1]` used to be split on its last colon, which sits inside the
//! brackets, so the address parsed to nothing and the block became the unnamed
//! catch-all: a site written for loopback answered every `Host` that reached
//! the port (pingclair#267).

use super::TestServer;

/// 🚫 A `Host` the configuration never mentions does not receive the `[::1]`
/// site, while `Host: [::1]` still does.
///
/// 📌 `http://named.test` puts a wildcard listener on the port, so every site
/// shares one socket and only the `Host` decides — which is the shape in which
/// a catch-all leaks. `http://127.0.0.1` carries the readiness route because
/// the harness probes with that `Host`.
#[tokio::test]
async fn test_bracketed_ipv6_site_is_not_a_catch_all() {
    let config = r#"
        {
            admin off
            http_port __PINGCLAIR_TEST_PORT__
        }

        http://[::1] {
            respond "LOOPBACK-ONLY"
        }

        http://named.test {
            respond "NAMED"
        }

        http://127.0.0.1 {
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
            respond "IPV4"
        }
        "#;
    let mut server = TestServer::new_pingclairfile(config);
    assert!(server.wait_until_ready().await, "server failed to start");

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let port = server.address(0).port();
    let mut bodies = Vec::new();
    for (url, host) in [
        (server.url(0, "/"), Some("unrelated.test")),
        (server.url(0, "/"), Some("named.test")),
        // 🌐 Over IPv6 loopback, with the `Host` a client derives from it.
        (format!("http://[::1]:{port}/"), None),
    ] {
        let mut request = client.get(&url);
        if let Some(host) = host {
            request = request.header("Host", host);
        }
        let body = request.send().await.unwrap().text().await.unwrap();
        bodies.push((host, body));
    }
    server.stop();

    assert_eq!(
        bodies,
        [
            (Some("unrelated.test"), String::new()),
            (Some("named.test"), "NAMED".to_string()),
            (None, "LOOPBACK-ONLY".to_string()),
        ]
    );
}
