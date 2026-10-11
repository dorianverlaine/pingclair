// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 📝 Native header text remains literal through the proxy exchange.

use super::{TestServer, no_proxy_client, read_until_marker};
use std::time::Duration;
use tokio::io::AsyncWriteExt;

#[tokio::test]
async fn header_literals_reach_both_sides_of_h1_and_h2_exchanges() {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let origin = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let head = read_until_marker(&mut stream, b"\r\n\r\n", Duration::from_secs(2)).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                head.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.write_all(&head).await.unwrap();
        }
    });
    let source = format!(
        r#"HTTPListener(on: "__PINGCLAIR_TEST_LISTEN__") {{
        Site(host: "*") {{
            Route(when: .path(exact: "__PINGCLAIR_TEST_READINESS_PATH__")) {{
                Respond(body: "__PINGCLAIR_TEST_READINESS_TOKEN__")
            }}
            Fallback {{
                RequestHeader(.set("X-Request", "{{host}}"), .append("X-Request", "{{path}}"))
                ResponseHeader(.set("X-Response", "{{host}}"), .append("X-Response", "{{path}}"),
                               .setIfAbsent("X-Default", "{{host}}"))
                Proxy(to: "{address}", headersUp: [.set("X-Up", "{{host}}"), .append("X-Up", "{{path}}")],
                      headersDown: [.append("X-Down", "{{path}}")])
            }}
        }}
    }}"#
    );
    let mut server = TestServer::new_native(&source);
    assert!(server.wait_until_ready().await, "server failed to start");
    let h2 = reqwest::Client::builder()
        .no_proxy()
        .http2_prior_knowledge()
        .build()
        .unwrap();
    for client in [no_proxy_client(), h2] {
        let response = client.get(server.url(0, "/literal")).send().await.unwrap();
        let values: Vec<_> = response
            .headers()
            .get_all("X-Response")
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect();
        assert_eq!(values, ["{host}", "{path}"]);
        assert_eq!(response.headers()["X-Default"], "{host}");
        assert_eq!(response.headers()["X-Down"], "{path}");
        let head = response.text().await.unwrap().to_ascii_lowercase();
        for field in [
            "x-request: {host}",
            "x-request: {path}",
            "x-up: {host}",
            "x-up: {path}",
        ] {
            assert!(head.contains(field), "missing literal {field}: {head}");
        }
    }
    tokio::time::timeout(Duration::from_secs(2), origin)
        .await
        .unwrap()
        .unwrap();
}
