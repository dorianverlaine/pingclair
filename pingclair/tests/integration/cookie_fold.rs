// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🍪 Several `Cookie` field lines on HTTP/1.1.
//!
//! A client that sends two `Cookie` lines is unusual but real, and the proxy
//! passes them through as sent. Whatever reads them as one value must join
//! them with `"; "`, the only separator a cookie-string has.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{MockFastCgi, TestServer};

/// 🍪 A FastCGI script sees two cookie lines as one cookie-string.
///
/// Before the fix the CGI sink used the list separator, so the script read
/// `a=1, b=2`: one cookie `a` with the value `1, b=2`.
#[tokio::test]
async fn test_fastcgi_folds_http1_cookie_lines_with_semicolons() {
    let responder = MockFastCgi::start();
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("index.php"), "<?php").unwrap();
    let root = root.path().to_str().unwrap().replace('\\', "/");
    let config = format!(
        r#"
        {{
            admin off
        }}

        :__PINGCLAIR_TEST_PORT__ {{
            root * {root}

            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            php_fastcgi 127.0.0.1:{fcgi_port}
        }}
        "#,
        fcgi_port = responder.port
    );
    let mut server = TestServer::new_pingclairfile(&config);
    assert!(server.wait_until_ready().await, "server failed to start");

    let mut stream = tokio::net::TcpStream::connect(server.address(0))
        .await
        .unwrap();
    stream
        .write_all(
            b"GET /index.php HTTP/1.1\r\nHost: test\r\nCookie: a=1\r\nCookie: b=2\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&response)
    );

    let (env, _) = responder
        .requests
        .lock()
        .unwrap()
        .first()
        .cloned()
        .expect("the responder saw one request");
    assert_eq!(env.get("HTTP_COOKIE").map(String::as_str), Some("a=1; b=2"));
}
