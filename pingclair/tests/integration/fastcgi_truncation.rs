// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔪 A failed FastCGI stream must not look like a complete HTTP response.

use super::*;

async fn check_truncation(http2: bool) {
    for buffered in [false, true] {
        for invalid_record in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let responder = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                loop {
                    let (kind, content) = read_fcgi_record(&mut stream).unwrap();
                    if kind == 5 && content.is_empty() {
                        break;
                    }
                }
                write_fcgi_record(
                    &mut stream,
                    6,
                    b"Status: 200 OK\r\nContent-Type: text/plain\r\n\r\npartial-document",
                )
                .unwrap();
                // 🔪 Headers and unbuffered bytes must leave before the failure.
                thread::sleep(Duration::from_millis(200));
                if invalid_record {
                    stream.write_all(&[2, 6, 0, 1, 0, 0, 0, 0]).unwrap();
                }
            });
            let buffering = if buffered {
                "response_buffers 64KiB"
            } else {
                ""
            };
            let config = format!(
                r#"
                {{
                    admin off
                }}
                :__PINGCLAIR_TEST_PORT__ {{
                    @readiness path __PINGCLAIR_TEST_READINESS_PATH__
                    respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
                    reverse_proxy 127.0.0.1:{port} {{
                        transport fastcgi
                        flush_interval -1
                        {buffering}
                    }}
                }}
            "#
            );
            let mut server = TestServer::new_pingclairfile(&config);
            assert!(server.wait_until_ready().await, "server failed to start");
            let builder = reqwest::Client::builder().no_proxy();
            let client = if http2 {
                builder.http2_prior_knowledge()
            } else {
                builder.http1_only()
            }
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
            let mut response = client.get(server.url(0, "/probe")).send().await.unwrap();
            assert_eq!(response.status(), 200);
            let mut received = Vec::new();
            let ending = loop {
                match response.chunk().await {
                    Ok(Some(chunk)) => received.extend_from_slice(&chunk),
                    Ok(None) => break "clean end".to_string(),
                    Err(error) => break format!("{error:?}"),
                }
            };
            responder.join().unwrap();
            server.stop();
            assert_ne!(
                ending, "clean end",
                "buffered={buffered}, invalid={invalid_record}"
            );
            assert!(
                !ending.contains("TimedOut"),
                "the response must abort promptly: {ending}"
            );
            if http2 {
                assert!(
                    ending.contains("INTERNAL_ERROR"),
                    "expected a stream reset: {ending}"
                );
            }
            assert_eq!(
                received,
                if buffered {
                    Vec::new()
                } else {
                    b"partial-document".to_vec()
                }
            );
        }
    }
}

/// 🔪 HTTP/1 closes without a final chunk after a FastCGI failure.
#[tokio::test]
async fn test_fastcgi_truncation_closes_h1_without_a_clean_end() {
    check_truncation(false).await;
}

/// 🔪 HTTP/2 resets with INTERNAL_ERROR after a FastCGI failure.
#[tokio::test]
async fn test_fastcgi_truncation_resets_h2_without_a_clean_end() {
    check_truncation(true).await;
}
