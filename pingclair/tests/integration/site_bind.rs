// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🛡️ `bind` restricts a site with an explicit address to its interface.
//!
//! `http://x.test:P { bind 127.0.0.1 }` used to listen on `[::]:P`, because
//! `bind` was only consulted for a site without an address of its own. The
//! site the operator restricted to loopback was then reachable on every
//! interface. The check below does not depend on bind order or on which
//! address the harness reserved: the IPv4 loopback must answer, and the IPv6
//! loopback, which only a wildcard socket would cover, must refuse.
//!
//! 📌 The site also names `127.0.0.1:P` only so the harness's readiness probe,
//! which sends that `Host`, reaches it.

use super::*;

/// 🛡️ Only the bound interface accepts connections.
#[tokio::test]
async fn test_bind_restricts_an_explicit_site_address_to_its_interface() {
    let mut server = TestServer::new_pingclairfile(
        r#"
        {
            admin off
        }

        http://x.test:__PINGCLAIR_TEST_PORT__, http://127.0.0.1:__PINGCLAIR_TEST_PORT__ {
            bind 127.0.0.1
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
            respond "bound"
        }
        "#,
    );
    assert!(server.wait_until_ready().await, "server did not start");
    let port = server.address(0).port();

    let bound = no_proxy_client()
        .get(format!("http://127.0.0.1:{port}/"))
        .header(reqwest::header::HOST, "x.test")
        .send()
        .await
        .unwrap();
    let bound = (bound.status().as_u16(), bound.text().await.unwrap());
    // 🎯 A raw connect, so "refused" cannot be confused with an HTTP answer.
    let elsewhere =
        tokio::net::TcpStream::connect(SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port)))
            .await
            .map(|_| ())
            .map_err(|error| error.kind());
    assert_eq!(
        (bound, elsewhere),
        (
            (200, "bound".to_string()),
            Err(std::io::ErrorKind::ConnectionRefused)
        )
    );
}
