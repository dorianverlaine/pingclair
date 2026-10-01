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

#[tokio::test]
async fn static_encode_offers_only_the_configured_codings() {
    let tree = compressible_tree();
    let client = no_proxy_client();
    for (encode, accepted, expected) in [
        ("encode gzip", "br", None),
        ("encode gzip", "zstd", None),
        ("encode gzip", "gzip", Some("gzip")),
        ("encode zstd gzip", "br", None),
        ("encode zstd gzip", "gzip, zstd", Some("zstd")),
        ("encode gzip zstd", "gzip, zstd", Some("gzip")),
        ("encode gzip", "*", None),
        ("encode zstd gzip", "*", None),
    ] {
        let mut server = file_server_site(tree.path().to_str().unwrap(), encode);
        assert!(server.wait_until_ready().await);
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
            "{encode}, {accepted}"
        );
        server.stop();
    }
}

#[tokio::test]
async fn static_identity_responses_always_vary_by_encoding() {
    let tree = compressible_tree();
    let mut server = file_server_site(tree.path().to_str().unwrap(), "");
    assert!(server.wait_until_ready().await);
    let response = no_proxy_client()
        .get(server.url(0, "/big.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.headers().get("vary").unwrap(), "Accept-Encoding");
    server.stop();
}

#[tokio::test]
async fn proxy_encode_varies_identity_and_encoded_responses() {
    let (address, task) = origin().await;
    let mut server = proxy_site(address, "encode gzip");
    assert!(server.wait_until_ready().await);
    let client = no_proxy_client();
    for (accepted, path, encoding) in [
        ("", "/text", None),
        ("gzip", "/text", Some("gzip")),
        ("gzip", "/binary", None),
    ] {
        let response = client
            .get(server.url(0, path))
            .header("Accept-Encoding", accepted)
            .send()
            .await
            .unwrap();
        let vary: Vec<_> = response
            .headers()
            .get_all("vary")
            .iter()
            .flat_map(|value| value.to_str().unwrap().split(','))
            .map(str::trim)
            .collect();
        assert_eq!(vary, ["Origin", "Accept-Encoding"]);
        assert_eq!(
            response
                .headers()
                .get("content-encoding")
                .map(|value| value.to_str().unwrap()),
            encoding
        );
    }
    server.stop();
    task.abort();
}

#[tokio::test]
async fn proxy_reencoding_weakens_only_strong_etags() {
    let (address, task) = origin().await;
    let mut server = proxy_site(address, "encode gzip");
    assert!(server.wait_until_ready().await);
    let client = no_proxy_client();
    for (accepted, path, expected) in [
        ("", "/text", "\"origin\""),
        ("gzip", "/text", "W/\"origin\""),
        ("gzip", "/weak", "W/\"origin\""),
        ("gzip", "/binary", "\"origin\""),
    ] {
        let response = client
            .get(server.url(0, path))
            .header("Accept-Encoding", accepted)
            .send()
            .await
            .unwrap();
        assert_eq!(response.headers().get("etag").unwrap(), expected);
    }
    server.stop();
    task.abort();
}

#[tokio::test]
async fn static_and_proxy_share_the_content_type_policy() {
    let tree = compressible_tree();
    std::fs::copy(tree.path().join("big.txt"), tree.path().join("data.bin")).unwrap();
    let (address, task) = origin().await;
    let client = no_proxy_client();
    for (types, text_encoding, binary_encoding) in [
        ("", Some("gzip"), None),
        ("gzip_types application/octet-stream", None, Some("gzip")),
    ] {
        let settings = format!("encode gzip\n{types}");
        let mut static_server = file_server_site(tree.path().to_str().unwrap(), &settings);
        let mut proxy_server = proxy_site(address, &settings);
        assert!(static_server.wait_until_ready().await);
        assert!(proxy_server.wait_until_ready().await);
        for (server, path, expected) in [
            (&static_server, "/big.txt", text_encoding),
            (&static_server, "/data.bin", binary_encoding),
            (&proxy_server, "/text", text_encoding),
            (&proxy_server, "/binary", binary_encoding),
        ] {
            let response = client
                .get(server.url(0, path))
                .header("Accept-Encoding", "gzip")
                .send()
                .await
                .unwrap();
            assert_eq!(
                response
                    .headers()
                    .get("content-encoding")
                    .map(|value| value.to_str().unwrap()),
                expected,
                "{types}, {path}"
            );
        }
        static_server.stop();
        proxy_server.stop();
    }
    task.abort();
}

#[tokio::test]
async fn gzip_levels_reach_both_wire_encoders() {
    let tree = compressible_tree();
    let (address, task) = origin().await;
    let client = no_proxy_client();
    for (encode, extra_flags) in [
        ("encode {\ngzip 1\n}", 4),
        ("encode {\ngzip 9\n}", 2),
        ("encode {\ngzip 5\n}", 0),
        ("encode gzip", 0),
    ] {
        let mut static_server = file_server_site(tree.path().to_str().unwrap(), encode);
        let mut proxy_server = proxy_site(address, encode);
        assert!(static_server.wait_until_ready().await);
        assert!(proxy_server.wait_until_ready().await);
        for (server, path) in [(&static_server, "/big.txt"), (&proxy_server, "/text")] {
            let response = client
                .get(server.url(0, path))
                .header("Accept-Encoding", "gzip")
                .send()
                .await
                .unwrap();
            assert_eq!(response.headers().get("content-encoding").unwrap(), "gzip");
            let wire = response.bytes().await.unwrap();
            assert_eq!(
                wire[8], extra_flags,
                "gzip XFL identifies fast/best/default quality: {encode}, {path}"
            );
            let mut decoded = String::new();
            flate2::read::GzDecoder::new(wire.as_ref())
                .read_to_string(&mut decoded)
                .unwrap();
            assert_eq!(decoded, "compressible text ".repeat(512));
        }
        static_server.stop();
        proxy_server.stop();
    }
    task.abort();
}

#[tokio::test]
async fn wildcard_acceptance_does_not_enable_a_coding() {
    let tree = compressible_tree();
    let (address, task) = origin().await;
    let client = no_proxy_client();
    let mut static_server = file_server_site(tree.path().to_str().unwrap(), "encode zstd gzip");
    let mut proxy_server = proxy_site(address, "encode zstd gzip");
    assert!(static_server.wait_until_ready().await);
    assert!(proxy_server.wait_until_ready().await);
    for (accepted, expected) in [
        ("*", None),
        ("*, gzip", Some("gzip")),
        ("gzip, *", Some("gzip")),
        ("*;q=0.5, gzip;q=0.5", Some("gzip")),
    ] {
        for (server, path) in [(&static_server, "/big.txt"), (&proxy_server, "/text")] {
            let response = client
                .get(server.url(0, path))
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
                "{accepted}, {path}"
            );
        }
    }
    static_server.stop();
    proxy_server.stop();
    task.abort();
}

/// 🛰️ The optional QUIC drill checks wire negotiation with an ngtcp2 curl.
#[tokio::test]
#[ignore = "requires an HTTP/3 curl; set PINGCLAIR_H3_CURL and run explicitly"]
async fn h3_encode_negotiation_matches_both_tcp_paths() {
    let tree = compressible_tree();
    let (address, task) = origin().await;
    let unavailable = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let unavailable_address = unavailable.local_addr().unwrap();
    drop(unavailable);
    let config = format!(
        r#"
{{
    admin off
    http_port __PINGCLAIR_TEST_HTTP_PORT__
    https_port __PINGCLAIR_TEST_HTTPS_PORT__
    servers {{
        protocols h1 h2 h3
    }}
}}
https://encode.test:__PINGCLAIR_TEST_HTTPS_PORT__ {{
    tls internal
    root * {root}
    header ETag "\"origin\""
    encode {{
        zstd
        gzip 9
    }}
    @unavailable path /unavailable
    reverse_proxy @unavailable {unavailable_address}
    @proxy path /proxy/*
    reverse_proxy @proxy {address}
    file_server
    @readiness path __PINGCLAIR_TEST_READINESS_PATH__
    respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
}}
"#,
        root = tree.path().display()
    );
    let mut server = TestServer::new_pingclairfile(&config);
    assert!(server.wait_until_tls_ready("encode.test").await);
    let curl = std::env::var("PINGCLAIR_H3_CURL")
        .expect("set PINGCLAIR_H3_CURL to an ngtcp2/nghttp3 curl");
    let artifacts = tempfile::tempdir().unwrap();
    for (accepted, expected) in [
        ("*", None),
        ("*, gzip", Some("gzip")),
        ("gzip, *", Some("gzip")),
        ("*;q=0.5, gzip;q=0.5", Some("gzip")),
    ] {
        for path in ["/big.txt", "/proxy/text", "/unavailable"] {
            let headers = artifacts.path().join("headers");
            let body = artifacts.path().join("body");
            let mut command = Command::new(&curl);
            command
                .args([
                    "--http3-only",
                    "--noproxy",
                    "*",
                    "--silent",
                    "--show-error",
                    "--max-time",
                    "15",
                ])
                .arg("--cacert")
                .arg(
                    server
                        ._temp_dir
                        .path()
                        .join("tls/pki/authorities/local/root.crt"),
                )
                .arg("--resolve")
                .arg(format!(
                    "encode.test:{}:127.0.0.1",
                    server.address(0).port()
                ))
                .arg("--header")
                .arg(format!("Accept-Encoding: {accepted}"))
                .arg("--dump-header")
                .arg(&headers)
                .arg("--output")
                .arg(&body)
                .arg(server.tls_url(0, "encode.test", path));
            let output = tokio::task::spawn_blocking(move || command.output().unwrap())
                .await
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let headers = std::fs::read_to_string(headers)
                .unwrap()
                .to_ascii_lowercase();
            let status = if path == "/unavailable" {
                "http/3 502"
            } else {
                "http/3 200"
            };
            assert!(headers.starts_with(status), "{headers}");
            assert!(headers.contains("vary: accept-encoding"), "{headers}");
            if path == "/unavailable" {
                continue;
            }
            let encoding = headers
                .lines()
                .find_map(|line| line.strip_prefix("content-encoding: "));
            assert_eq!(encoding, expected, "{accepted}, {path}");
            let wire = std::fs::read(body).unwrap();
            if expected == Some("gzip") {
                assert_eq!(wire[8], 2, "gzip 9 must reach the H3 wire");
                let mut decoded = String::new();
                flate2::read::GzDecoder::new(wire.as_slice())
                    .read_to_string(&mut decoded)
                    .unwrap();
                assert_eq!(decoded, "compressible text ".repeat(512));
                if path == "/proxy/text" {
                    assert!(headers.contains("etag: w/\"origin\""), "{headers}");
                }
            } else {
                assert_eq!(wire, "compressible text ".repeat(512).as_bytes());
            }
        }
    }
    server.stop();
    task.abort();
}
