// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🗜️ Compression regressions exercise the user's Pingclairfile and real binary.

use super::*;

#[tokio::test]
async fn encode_block_controls_static_responses() {
    let tree = compressible_tree();
    let root = tree.path().to_str().unwrap();
    let client = no_proxy_client();
    for (settings, accepted, expected) in [
        ("zstd", "zstd", Some("zstd")),
        ("gzip\nminimum_length 10000", "gzip", None),
        ("gzip\nmatch {\nstatus 4xx\n}", "gzip", None),
        (
            "gzip\nmatch {\nstatus 2xx\nheader Content-Type text/*\n}",
            "gzip",
            Some("gzip"),
        ),
    ] {
        let mut server = file_server_site(root, &format!("encode {{\n{settings}\n}}"));
        assert!(server.wait_until_ready().await, "{settings}");
        let response = client
            .get(server.url(0, "/big.txt"))
            .header("Accept-Encoding", accepted)
            .send()
            .await
            .unwrap();
        assert_eq!(
            response
                .headers()
                .get("content-encoding")
                .map(|value| value.to_str().unwrap()),
            expected,
            "{settings}"
        );
        server.stop();
    }
}

/// 🔌 A deterministic origin keeps compression assertions independent of routing.
async fn origin() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut request = [0; 8192];
                let size = stream.read(&mut request).await.unwrap();
                let request = String::from_utf8_lossy(&request[..size]);
                let (status, mime, etag) = if request.contains("/binary ") {
                    (200, "application/octet-stream", "\"origin\"")
                } else if request.contains("/missing ") {
                    (404, "text/plain", "\"origin\"")
                } else if request.contains("/weak ") {
                    (200, "text/plain", "W/\"origin\"")
                } else {
                    (200, "text/plain", "\"origin\"")
                };
                let body = "compressible text ".repeat(512);
                let header = format!(
                    "HTTP/1.1 {status} OK\r\nContent-Type: {mime}\r\nContent-Length: {}\r\nETag: {etag}\r\nVary: Origin\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream.write_all(header.as_bytes()).await.unwrap();
                stream.write_all(body.as_bytes()).await.unwrap();
            });
        }
    });
    (address, task)
}

fn proxy_site(address: SocketAddr, encode: &str) -> TestServer {
    TestServer::new_pingclairfile(&format!(
        r#"
{{
    admin off
}}
http://:__PINGCLAIR_TEST_PORT__ {{
    {encode}
    reverse_proxy {address}
    @readiness path __PINGCLAIR_TEST_READINESS_PATH__
    respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
}}
"#
    ))
}

#[tokio::test]
async fn encode_block_controls_proxy_responses() {
    let (address, task) = origin().await;
    let client = no_proxy_client();
    for (settings, path, expected) in [
        ("zstd", "/text", Some("zstd")),
        ("gzip\nminimum_length 10000", "/text", None),
        ("gzip\nmatch {\nstatus 2xx\n}", "/missing", None),
        ("gzip\nmatch {\nstatus 4xx\n}", "/missing", Some("gzip")),
    ] {
        let mut server = proxy_site(address, &format!("encode {{\n{settings}\n}}"));
        assert!(server.wait_until_ready().await, "{settings}");
        let response = client
            .get(server.url(0, path))
            .header("Accept-Encoding", "gzip, zstd")
            .send()
            .await
            .unwrap();
        assert_eq!(
            response
                .headers()
                .get("content-encoding")
                .map(|value| value.to_str().unwrap()),
            expected,
            "{settings}"
        );
        server.stop();
    }
    task.abort();
}
