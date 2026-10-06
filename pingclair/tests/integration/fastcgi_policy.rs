// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🤐 FastCGI responses share the local HEAD and download-rate policy.

use super::*;

const BODY_SIZE: usize = 32 * 1024;

/// 🧾 Exercise streamed, buffered, replacement, and response-file bodies.
fn policy_site(responder: &MockFastCgi, root: &std::path::Path, mode: &str) -> String {
    let body = "x".repeat(BODY_SIZE);
    *responder.response.lock().unwrap() = format!(
        "Status: 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {BODY_SIZE}\r\n\r\n{body}"
    )
    .into_bytes();
    let policy = match mode {
        "streamed" => String::new(),
        "buffered" => "response_buffers 64KiB".to_string(),
        "replacement" => format!("handle_response {{\n respond \"{body}\"\n }}"),
        "file" => format!(
            "handle_response {{\n root * {}\n rewrite * /body.bin\n file_server\n }}",
            root.display()
        ),
        _ => unreachable!(),
    };
    format!(
        r#"
        {{
            admin off
        }}
        :__PINGCLAIR_TEST_PORT__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
            limits {{
                download_bytes_per_sec 32768
            }}
            reverse_proxy 127.0.0.1:{port} {{
                transport fastcgi
                {policy}
            }}
        }}
    "#,
        port = responder.port
    )
}

/// 🤐 A raw HTTP/2 client observes DATA that higher-level HEAD clients may hide.
#[tokio::test]
async fn test_fastcgi_policy_head_sends_no_h2_data() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("body.bin"), vec![b'x'; BODY_SIZE]).unwrap();
    for mode in ["streamed", "buffered", "replacement", "file"] {
        let responder = MockFastCgi::start();
        let mut server = TestServer::new_pingclairfile(&policy_site(&responder, root.path(), mode));
        assert!(server.wait_until_ready().await, "server failed to start");
        let stream = tokio::net::TcpStream::connect(server.address(0))
            .await
            .unwrap();
        let (mut client, connection) = h2::client::handshake(stream).await.unwrap();
        let connection_task = tokio::spawn(async move {
            let _ = connection.await;
        });
        let request = http::Request::builder()
            .method("HEAD")
            .uri(server.url(0, "/probe"))
            .body(())
            .unwrap();
        let (response, _) = client.send_request(request, true).unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), 200, "{mode}");
        assert_eq!(
            response.headers().get("content-length").unwrap(),
            "32768",
            "{mode}"
        );
        let mut body = response.into_body();
        let mut received = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.unwrap();
            received.extend_from_slice(&chunk);
            body.flow_control().release_capacity(chunk.len()).unwrap();
        }
        connection_task.abort();
        server.stop();
        assert!(
            received.is_empty(),
            "HEAD must send no DATA for {mode}, saw {} bytes",
            received.len()
        );
    }
}

/// 🚦 Each FastCGI body path spends the configured rate budget on H1 and H2.
#[tokio::test]
async fn test_fastcgi_policy_paces_downloads_on_h1_and_h2() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("body.bin"), vec![b'x'; BODY_SIZE]).unwrap();
    for mode in ["streamed", "buffered", "replacement", "file"] {
        let responder = MockFastCgi::start();
        let mut server = TestServer::new_pingclairfile(&policy_site(&responder, root.path(), mode));
        assert!(server.wait_until_ready().await, "server failed to start");
        for http2 in [false, true] {
            let builder = reqwest::Client::builder().no_proxy();
            let client = if http2 {
                builder.http2_prior_knowledge()
            } else {
                builder.http1_only()
            }
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
            let started = std::time::Instant::now();
            let response = client.get(server.url(0, "/probe")).send().await.unwrap();
            assert_eq!(response.status(), 200, "{mode}");
            assert_eq!(
                response.bytes().await.unwrap().as_ref(),
                vec![b'x'; BODY_SIZE]
            );
            assert!(
                started.elapsed() >= Duration::from_millis(900),
                "{mode} http2={http2} bypassed the one-second download budget: {:?}",
                started.elapsed()
            );
        }
    }
}
