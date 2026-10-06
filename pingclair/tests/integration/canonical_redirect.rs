// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔁 Static redirects preserve queries and cannot name another authority.

use super::{TestServer, read_http1_to_end};
use tokio::io::AsyncWriteExt;

#[tokio::test]
async fn test_canonical_redirect_query_and_origin() {
    let root = tempfile::tempdir().unwrap();
    for directory in ["sub", "sub dir", "\\evil.example"] {
        std::fs::create_dir(root.path().join(directory)).unwrap();
        std::fs::write(root.path().join(directory).join("index.html"), "index").unwrap();
    }
    std::fs::write(root.path().join("plain.txt"), "plain").unwrap();
    let config = format!(
        r#"
        {{
            admin off
        }}
        :__PINGCLAIR_TEST_PORT__ {{
            root * {root}
            try_files {{path}} {{path}}/ /plain.txt
            file_server
            @ready path __PINGCLAIR_TEST_READINESS_PATH__
            respond @ready "__PINGCLAIR_TEST_READINESS_TOKEN__"
        }}
    "#,
        root = root.path().display()
    );
    let mut server = TestServer::new_pingclairfile(&config);
    assert!(server.wait_until_ready().await, "server failed to start");
    for (method, target, expected) in [
        ("GET", "/sub?x=1&y=2", "/sub/?x=1&y=2"),
        (
            "GET",
            "//sub?next=//evil.example&x=%2F",
            "/sub/?next=//evil.example&x=%2F",
        ),
        ("GET", "///sub?", "/sub/?"),
        ("GET", "/other/%2e/../sub?x=1", "/sub/?x=1"),
        ("GET", "/other/child/.%2e/../sub?x=1", "/sub/?x=1"),
        ("GET", "/other/child/%2e%2E/../sub?x=1", "/sub/?x=1"),
        ("HEAD", "/./sub?x=1", "/sub/?x=1"),
        ("POST", "/sub?x=1", "/sub/?x=1"),
        ("GET", "//plain.txt/?x=1", "/plain.txt?x=1"),
        ("GET", "/sub%20dir?x=%252F", "/sub%20dir/?x=%252F"),
        ("GET", "/\\evil.example?x=1", "/%5Cevil.example/?x=1"),
    ] {
        let mut stream = tokio::net::TcpStream::connect(server.address(0))
            .await
            .unwrap();
        stream.write_all(format!("{method} {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: 0\r\n\r\n").as_bytes()).await.unwrap();
        let response = read_http1_to_end(&mut stream).await;
        let split = response
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
            .unwrap();
        let head = String::from_utf8_lossy(&response[..split]);
        assert!(
            head.starts_with("HTTP/1.1 308"),
            "{method} {target}: {head}"
        );
        let location = head.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("location").then(|| value.trim())
        });
        assert_eq!(location, Some(expected), "{target}");
        assert!(
            response[split + 4..].is_empty(),
            "redirect body must remain empty"
        );
    }
    // 🛰️ Raw HTTP/2 targets reach the same original-URI boundary.
    for (target, expected) in [
        (
            "//sub?next=//evil.example&x=%2F",
            "/sub/?next=//evil.example&x=%2F",
        ),
        ("/./sub?x=1", "/sub/?x=1"),
        ("/other/%2e/../sub?x=1", "/sub/?x=1"),
        ("/other/child/.%2e/../sub?x=1", "/sub/?x=1"),
        ("/other/child/%2e%2E/../sub?x=1", "/sub/?x=1"),
        ("//plain.txt/?x=1", "/plain.txt?x=1"),
    ] {
        let stream = tokio::net::TcpStream::connect(server.address(0))
            .await
            .unwrap();
        let (mut client, connection) = h2::client::handshake(stream).await.unwrap();
        let driver = tokio::spawn(connection);
        let request = http::Request::builder()
            .uri(format!("http://localhost{target}"))
            .body(())
            .unwrap();
        let (response, _) = client.send_request(request, true).unwrap();
        let response = response.await.unwrap();
        assert_eq!(
            (
                response.status().as_u16(),
                response
                    .headers()
                    .get("location")
                    .unwrap()
                    .to_str()
                    .unwrap()
            ),
            (308, expected),
            "{target}"
        );
        let mut body = response.into_body();
        while let Some(data) = body.data().await {
            assert!(data.unwrap().is_empty(), "redirect body must remain empty");
        }
        driver.abort();
    }
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    for (path, body) in [("/sub/?x=1", "index"), ("/missing?x=1", "plain")] {
        let response = client.get(server.url(0, path)).send().await.unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.text().await.unwrap(), body);
    }
}
