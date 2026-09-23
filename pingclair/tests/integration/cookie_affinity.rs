// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🍪 `lb_policy cookie` must not depend on how the client ordered cookies.
//!
//! A browser holding two cookies with the same name (set for different
//! paths) sends both, in an order RFC 6265 §4.2.2 tells servers not to rely
//! on. Two origins that name themselves let the test see which one a request
//! was pinned to.

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::TestServer;

/// 🎛️ An origin that answers every request with its own name.
async fn spawn_named_origin(name: &'static str) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 16384];
                if stream.read(&mut buffer).await.is_err() {
                    return;
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{name}",
                    name.len()
                );
                stream.write_all(response.as_bytes()).await.ok();
            });
        }
    });
    address
}

/// 🧵 Sends a raw HTTP/1.1 request with the given `Cookie` lines and returns
/// the name of the origin that answered.
async fn backend_for(proxy: SocketAddr, cookie_lines: &[&str]) -> String {
    let mut request = String::from("GET /whoami HTTP/1.1\r\nHost: test\r\n");
    for line in cookie_lines {
        request.push_str("Cookie: ");
        request.push_str(line);
        request.push_str("\r\n");
    }
    request.push_str("Connection: close\r\n\r\n");
    let mut stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8_lossy(&response).into_owned();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    response
        .rsplit("\r\n\r\n")
        .next()
        .unwrap_or_default()
        .to_string()
}

/// 🎯 The same cookies in either order, on one line or two, reach the same
/// origin.
///
/// Before the fix the first `sid` in the first `Cookie` line won, so
/// swapping the order moved the session for roughly half of these pairs.
#[tokio::test]
async fn test_cookie_affinity_ignores_cookie_order_and_line_split() {
    let first = spawn_named_origin("first").await;
    let second = spawn_named_origin("second").await;
    let config = format!(
        r#"
        {{
            admin off
        }}

        :__PINGCLAIR_TEST_PORT__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            reverse_proxy {first} {second} {{
                lb_policy cookie sid
            }}
        }}
        "#
    );
    let mut server = TestServer::new_pingclairfile(&config);
    assert!(server.wait_until_ready().await, "server failed to start");
    let proxy = server.address(0);

    // 🎲 Several pairs, so a hash that happens to put both values on the same
    // origin cannot hide an order dependence.
    let pairs = [
        ("alpha", "beta"),
        ("one", "two"),
        ("red", "blue"),
        ("north", "south"),
        ("x1", "y2"),
        ("left", "right"),
        ("cat", "dog"),
        ("sun", "moon"),
    ];
    for (a, b) in pairs {
        let forward = format!("sid={a}; theme=dark; sid={b}");
        let reverse = format!("sid={b}; theme=dark; sid={a}");
        let one_line = backend_for(proxy, &[&forward]).await;
        assert_eq!(
            backend_for(proxy, &[&reverse]).await,
            one_line,
            "sid={a} and sid={b} reached different origins by order"
        );
        let a_line = format!("sid={a}");
        let b_line = format!("sid={b}");
        assert_eq!(
            backend_for(proxy, &[&a_line, &b_line]).await,
            one_line,
            "two Cookie lines must be read like one"
        );
        assert_eq!(
            backend_for(proxy, &[&b_line, &a_line]).await,
            one_line,
            "two Cookie lines in reverse order must be read like one"
        );
    }
}
