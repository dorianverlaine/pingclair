// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧾 Re-encoded H3 messages must not retain integrity fields for identity bytes.

use super::*;

/// 🧾 A trailer task ends the body, so the encoder must be finalized there.
///
/// An HTTP/2 origin can end a response with trailing HEADERS, announced or
/// not. Pingora then writes the trailer task as the end of the message instead
/// of sending `Done`, which is the only task that used to finalize the coding —
/// so the client received compressed DATA with no gzip trailer and could not
/// decode a single byte of a perfectly good response. The body must decode;
/// trailer fields that cannot share the final body chunk are dropped rather
/// than left to break it (#225).
#[tokio::test]
async fn h2_origin_trailers_still_leave_a_decodable_gzip_body() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let text = "compressible text ".repeat(256);
    let origin_text = text.clone();
    let origin = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut connection = h2::server::handshake(socket).await.unwrap();
        while let Some(request) = connection.accept().await {
            let (_, mut respond) = request.unwrap();
            // 📏 No `Content-Length`: the origin streams and then ends the
            // message with trailer fields, which is exactly the shape an H2
            // origin uses for gRPC and for checksum trailers.
            let response = http::Response::builder()
                .status(200)
                .header("content-type", "text/plain")
                .body(())
                .unwrap();
            let mut body = respond.send_response(response, false).unwrap();
            body.send_data(bytes::Bytes::from(origin_text.clone()), false)
                .unwrap();
            let mut trailers = http::HeaderMap::new();
            trailers.insert(
                "x-origin-trailer",
                http::HeaderValue::from_static("after-the-body"),
            );
            body.send_trailers(trailers).unwrap();
        }
    });

    let mut server = TestServer::new_pingclairfile(&format!(
        r#"
{{
    admin off
}}

:__PINGCLAIR_TEST_PORT__ {{
    @readiness path __PINGCLAIR_TEST_READINESS_PATH__
    respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

    encode gzip
    reverse_proxy h2c://{address}
}}
"#
    ));
    assert!(server.wait_until_ready().await, "server failed to start");

    let client = reqwest::Client::builder()
        .no_proxy()
        .http2_prior_knowledge()
        .build()
        .unwrap();
    let response = client
        .get(server.url(0, "/text"))
        .header("accept-encoding", "gzip")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response
            .headers()
            .get("content-encoding")
            .and_then(|value| value.to_str().ok()),
        Some("gzip"),
        "the test needs a compressed response"
    );
    let wire = response.bytes().await.unwrap();
    server.stop();
    origin.abort();

    let mut decoded = Vec::new();
    flate2::read::GzDecoder::new(&wire[..])
        .read_to_end(&mut decoded)
        .expect("a compressed response that ends with trailers must stay decodable");
    assert_eq!(decoded, text.as_bytes());
}

#[tokio::test]
#[ignore = "requires an HTTP/3 curl; set PINGCLAIR_H3_CURL and run explicitly"]
async fn h3_encoding_removes_only_identity_integrity_trailers() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let origin = tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut connection = h2::server::handshake(socket).await.unwrap();
                while let Some(request) = connection.accept().await {
                    let (_, mut respond) = request.unwrap();
                    let text = "compressible text ".repeat(512);
                    let response = http::Response::builder()
                        .status(200)
                        .header("content-type", "text/plain")
                        .header("content-length", text.len())
                        .body(())
                        .unwrap();
                    let mut body = respond.send_response(response, false).unwrap();
                    body.send_data(bytes::Bytes::from(text), false).unwrap();
                    let mut trailers = http::HeaderMap::new();
                    for name in ["content-digest", "repr-digest", "digest", "content-md5"] {
                        trailers.insert(name, http::HeaderValue::from_static("identity-integrity"));
                    }
                    trailers.insert(
                        "x-origin-trailer",
                        http::HeaderValue::from_static("preserved"),
                    );
                    body.send_trailers(trailers).unwrap();
                }
            });
        }
    });
    let mut server = TestServer::new_pingclairfile(&format!(
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
    encode gzip
    reverse_proxy h2c://{address}
    @readiness path __PINGCLAIR_TEST_READINESS_PATH__
    respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
}}
"#
    ));
    assert!(server.wait_until_tls_ready("encode.test").await);
    let curl = std::env::var("PINGCLAIR_H3_CURL").unwrap();
    let artifacts = tempfile::tempdir().unwrap();
    for accepted in ["", "gzip"] {
        let header_path = artifacts.path().join("headers");
        let body_path = artifacts.path().join("body");
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
            .arg(&header_path)
            .arg("--output")
            .arg(&body_path)
            .arg(server.tls_url(0, "encode.test", "/text"));
        let output = tokio::task::spawn_blocking(move || command.output().unwrap())
            .await
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let headers = std::fs::read_to_string(header_path)
            .unwrap()
            .to_ascii_lowercase();
        assert!(headers.starts_with("http/3 200"), "{headers}");
        assert!(headers.contains("x-origin-trailer: preserved"), "{headers}");
        for name in ["content-digest", "repr-digest", "digest", "content-md5"] {
            assert_eq!(
                headers.contains(&format!("\n{name}: identity-integrity")),
                accepted.is_empty(),
                "{headers}"
            );
        }
        let wire = std::fs::read(body_path).unwrap();
        let decoded = if accepted == "gzip" {
            assert!(headers.contains("content-encoding: gzip"), "{headers}");
            let mut decoded = Vec::new();
            flate2::read::GzDecoder::new(wire.as_slice())
                .read_to_end(&mut decoded)
                .unwrap();
            decoded
        } else {
            wire
        };
        assert_eq!(decoded, "compressible text ".repeat(512).as_bytes());
    }
    server.stop();
    origin.abort();
}
