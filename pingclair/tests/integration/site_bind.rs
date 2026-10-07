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

/// 🔁 The automatic HTTP→HTTPS redirect of a bound site listens on the bound
/// interface too.
///
/// The plaintext companion used to be hard-coded to `[::]:<http_port>`, so a
/// `bind 127.0.0.1` HTTPS site kept its redirect listener on every interface.
#[tokio::test]
async fn test_bind_restricts_the_automatic_http_redirect_to_its_interface() {
    let mut server = TestServer::new_pingclairfile(
        r#"
        {
            admin off
            http_port __PINGCLAIR_TEST_HTTP_PORT__
            https_port __PINGCLAIR_TEST_HTTPS_PORT__
        }

        example.test {
            bind 127.0.0.1
            tls internal
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
            respond "secure"
        }
        "#,
    );
    assert!(server.wait_until_tls_ready("example.test").await);
    let http = server.listener_address(0, 1);

    let redirect = raw_get_status_and_location(http, "example.test").await;
    let elsewhere = tokio::net::TcpStream::connect(SocketAddr::from((
        std::net::Ipv6Addr::LOCALHOST,
        http.port(),
    )))
    .await
    .map(|_| ())
    .map_err(|error| error.kind());
    assert_eq!(
        (redirect, elsewhere),
        (
            (
                "HTTP/1.1 308 Permanent Redirect".to_string(),
                Some("https://example.test/".to_string())
            ),
            Err(std::io::ErrorKind::ConnectionRefused)
        )
    );
}

/// 🧩 Two sites on one port, one per interface, are two sites.
///
/// The duplicate check compared `(name, listens)` alone, so both blocks below
/// were refused with `Duplicate server name: _` even though they sit on
/// different interfaces — the shape Caddy accepts since
/// caddyserver/caddy#4635, where `bind` is part of what makes a site distinct
/// (#279).
#[tokio::test]
async fn test_two_binds_on_one_port_serve_their_own_interface() {
    let mut server = TestServer::new_pingclairfile(
        r#"
        {
            admin off
        }

        http://:__PINGCLAIR_TEST_PORT__ {
            bind 127.0.0.1
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
            respond "v4"
        }

        http://:__PINGCLAIR_TEST_PORT__ {
            bind [::1]
            respond "v6"
        }
        "#,
    );
    assert!(server.wait_until_ready().await, "server did not start");
    let port = server.address(0).port();

    // 🎯 Each socket answers its own site, and the other interface's site is
    // not reachable through it even when the `Host` names it.
    let mut seen = Vec::new();
    for (url, host) in [
        (format!("http://127.0.0.1:{port}/"), None),
        (format!("http://[::1]:{port}/"), None),
        (format!("http://127.0.0.1:{port}/"), Some("[::1]")),
    ] {
        let mut request = no_proxy_client().get(url);
        if let Some(host) = host {
            request = request.header(reqwest::header::HOST, host);
        }
        let response = request.send().await.unwrap();
        seen.push((response.status().as_u16(), response.text().await.unwrap()));
    }

    assert_eq!(
        seen,
        vec![
            (200, "v4".to_string()),
            (200, "v6".to_string()),
            (200, "v4".to_string()),
        ]
    );
}
