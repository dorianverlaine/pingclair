// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔌 An IP-literal site and a hostname site on one port share one socket
//! (issue #246).
//!
//! The two used to become `127.0.0.1:P` and `[::]:P`, two sockets carrying
//! different sites. Linux lets only one of them bind, so which site answered
//! depended on which socket the kernel took first; macOS keeps both, and each
//! socket then answered only for its own site. These requests do not depend on
//! bind order: they ask each socket for the site it did not carry before.

use super::*;

/// 🌐 Fetches `path` from `address` with `host` as the `Host` header.
async fn body(address: SocketAddr, host: &str, path: &str) -> (u16, String) {
    let response = no_proxy_client()
        .get(format!("http://{address}{path}"))
        .header(reqwest::header::HOST, host)
        .send()
        .await
        .unwrap();
    (response.status().as_u16(), response.text().await.unwrap())
}

/// 🔌 Every site on the port answers on every address of that port.
#[tokio::test]
async fn test_literal_and_hostname_sites_share_one_listener() {
    let mut server = TestServer::new_pingclairfile(
        r#"
        {
            admin off
        }

        http://127.0.0.1:__PINGCLAIR_TEST_PORT__ {
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
            respond "loopback"
        }

        http://example.test:__PINGCLAIR_TEST_PORT__ {
            respond "named"
        }
        "#,
    );
    assert!(server.wait_until_ready().await, "server did not start");
    let address = server.address(0);
    let port = address.port();
    let literal_host = format!("127.0.0.1:{port}");
    let ipv6_loopback = SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port));

    let seen = vec![
        body(address, &literal_host, "/").await,
        body(address, "example.test", "/").await,
        // 🎯 The literal site through the wildcard socket: before the fold
        // the `[::]` socket did not carry it at all.
        body(ipv6_loopback, &literal_host, "/").await,
        body(ipv6_loopback, "example.test", "/").await,
    ];
    assert_eq!(
        seen,
        vec![
            (200, "loopback".to_string()),
            (200, "named".to_string()),
            (200, "loopback".to_string()),
            (200, "named".to_string()),
        ]
    );
}
