// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔀 Proxies in one `route` block each reach their own upstream.
//!
//! 🤡 A route kept one upstream pool, chosen from its first `reverse_proxy`, so
//! the second `handle` of a `route` block proxied to the first one's upstream.
//! pingclair.com's `/mcp` reached the installer bucket that way on 2026-10-12.

use super::{TestServer, no_proxy_client};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 🏷️ An origin that answers every request with its own tag.
async fn tagged_origin(tag: &'static str) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut head = [0u8; 4096];
                let _ = stream.read(&mut head).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{tag}",
                    tag.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    address
}

#[tokio::test]
async fn each_handle_in_a_route_block_reaches_its_own_upstream() {
    let first = tagged_origin("first").await;
    let second = tagged_origin("second").await;
    let config = format!(
        r#"
:__PINGCLAIR_TEST_PORT__ {{
    route {{
        handle __PINGCLAIR_TEST_READINESS_PATH__ {{
            respond "__PINGCLAIR_TEST_READINESS_TOKEN__"
        }}
        handle /first {{
            reverse_proxy {first}
        }}
        handle /second {{
            reverse_proxy {second}
        }}
    }}
}}
"#
    );
    let mut server = TestServer::new_pingclairfile(&config);
    assert!(server.wait_until_ready().await, "server failed to start");

    let client = no_proxy_client();
    let mut answers = Vec::new();
    for path in ["/first", "/second"] {
        let response = client.get(server.url(0, path)).send().await.unwrap();
        answers.push((path, response.text().await.unwrap()));
    }
    assert_eq!(
        answers,
        [
            ("/first", "first".to_string()),
            ("/second", "second".to_string())
        ]
    );
}

/// 🏷️ A shared `header` in the route reaches both proxy branches.
///
/// This is the shape the 0.2.3 split could not honour: the header belongs to
/// the route, while the upstream belongs to each `reverse_proxy`. Keying pools
/// by proxy lets both facts be true at once.
#[tokio::test]
async fn a_shared_header_reaches_both_route_block_proxies() {
    let first = tagged_origin("first").await;
    let second = tagged_origin("second").await;
    let config = format!(
        r#"
:__PINGCLAIR_TEST_PORT__ {{
    route {{
        header X-Shared yes
        handle __PINGCLAIR_TEST_READINESS_PATH__ {{
            respond "__PINGCLAIR_TEST_READINESS_TOKEN__"
        }}
        handle /first {{
            reverse_proxy {first}
        }}
        handle /second {{
            reverse_proxy {second}
        }}
    }}
}}
"#
    );
    let mut server = TestServer::new_pingclairfile(&config);
    assert!(server.wait_until_ready().await, "server failed to start");

    let client = no_proxy_client();
    for (path, expected) in [("/first", "first"), ("/second", "second")] {
        let response = client.get(server.url(0, path)).send().await.unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("x-shared")
                .and_then(|value| value.to_str().ok()),
            Some("yes"),
            "the shared route header must reach the client on {path}"
        );
        assert_eq!(response.text().await.unwrap(), expected);
    }
}
