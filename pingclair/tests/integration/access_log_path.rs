// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧾 The access log records the request target the client sent.
//!
//! A `rewrite` is an implementation detail: before this test, every missing
//! page on the documentation site appeared as a request for `/404.html`, and
//! the two public installer URLs both appeared as `/pingclair/install.sh`.
//! That made a scanner probe and a broken external link indistinguishable in
//! the only record an operator has after the fact.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{TestServer, no_proxy_client, wait_for_captured_line};

/// 🖥️ A one-request HTTP origin for the installer rewrite test.
async fn spawn_installer_origin() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind the installer origin");
    let address = listener.local_addr().expect("origin address");
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut request = [0u8; 4096];
                let _ =
                    tokio::time::timeout(Duration::from_secs(2), stream.read(&mut request)).await;
                let body = "installer";
                let _ = stream
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await;
            });
        }
    });
    (address, task)
}

/// 🚨 A missing page rendered through `handle_errors` keeps the client's path.
#[tokio::test]
async fn handle_errors_rewrite_keeps_the_requested_path_in_the_log() {
    let dir = tempfile::tempdir().expect("test directory");
    let root = tempfile::tempdir().expect("site root");
    std::fs::write(root.path().join("404.html"), "not found").unwrap();
    let log = dir.path().join("access.log");
    let config = format!(
        r#"
        {{
            admin off
        }}

        http://__PINGCLAIR_TEST_LISTEN__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            log {{
                output file {log}
                format json
            }}

            root * {root}
            handle_errors {{
                rewrite * /404.html
                file_server
            }}
            file_server
        }}
        "#,
        log = log.display(),
        root = root.path().display(),
    );
    let mut server = TestServer::new_pingclairfile(&config);
    assert!(server.wait_until_ready().await, "server failed to start");

    let response = no_proxy_client()
        .get(server.url(0, "/missing-page?from=test"))
        .send()
        .await
        .expect("the missing page must answer");
    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
    assert_eq!(response.text().await.unwrap(), "not found");

    let recorded = wait_for_captured_line(&log, "\"path\":", Duration::from_secs(10)).await;
    assert!(
        recorded.contains("\"path\":\"/missing-page?from=test\""),
        "the client's path must survive the error-page rewrite: {recorded}"
    );
    assert!(
        !recorded.contains("\"path\":\"/404.html\""),
        "the error page must not become the recorded request: {recorded}"
    );
}

/// 🏷️ A rewrite in front of `reverse_proxy` is not the client's path either.
#[tokio::test]
async fn proxy_rewrite_keeps_the_requested_path_in_the_log() {
    let (origin, origin_task) = spawn_installer_origin().await;
    let dir = tempfile::tempdir().expect("test directory");
    let log = dir.path().join("access.log");
    let config = format!(
        r#"
        {{
            admin off
        }}

        http://__PINGCLAIR_TEST_LISTEN__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            log {{
                output file {log}
                format json
            }}

            handle /install.sh {{
                rewrite * /pingclair/install.sh
                reverse_proxy http://{origin}
            }}
            respond "not found" 404
        }}
        "#,
        log = log.display(),
    );
    let mut server = TestServer::new_pingclairfile(&config);
    assert!(server.wait_until_ready().await, "server failed to start");

    let response = no_proxy_client()
        .get(server.url(0, "/install.sh"))
        .send()
        .await
        .expect("the installer route must answer");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.text().await.unwrap(), "installer");

    let recorded = wait_for_captured_line(&log, "\"path\":", Duration::from_secs(10)).await;
    assert!(
        recorded.contains("\"path\":\"/install.sh\""),
        "the client's installer URL must survive the upstream rewrite: {recorded}"
    );
    assert!(
        !recorded.contains("\"path\":\"/pingclair/install.sh\""),
        "the rewritten upstream path must not replace the request: {recorded}"
    );
    origin_task.abort();
}
