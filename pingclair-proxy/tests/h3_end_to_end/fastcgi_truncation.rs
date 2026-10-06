// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔪 A FastCGI body failure resets HTTP/3, including buffered responses.

use super::*;

/// 🔪 A disconnect or invalid record cannot turn a partial document into a whole one.
#[tokio::test]
async fn h3_fastcgi_truncation_resets_without_a_clean_end() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    for buffered in [false, true] {
        for invalid_record in [false, true] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let responder = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                loop {
                    let mut header = [0u8; 8];
                    stream.read_exact(&mut header).await.unwrap();
                    let length = u16::from_be_bytes([header[4], header[5]]) as usize;
                    let mut discard = vec![0; length + header[6] as usize];
                    stream.read_exact(&mut discard).await.unwrap();
                    if header[1] == 5 && length == 0 {
                        break;
                    }
                }
                write_fastcgi_record(
                    &mut stream,
                    6,
                    b"Status: 200 OK\r\nContent-Type: text/plain\r\n\r\npartial-document",
                )
                .await;
                // 🔪 Let the committed headers reach the client before failing.
                tokio::time::sleep(Duration::from_millis(200)).await;
                if invalid_record {
                    stream.write_all(&[2, 6, 0, 1, 0, 0, 0, 0]).await.unwrap();
                }
            });
            let buffering = if buffered {
                "response_buffers 64KiB"
            } else {
                ""
            };
            let server = spawn_h3_from_pingclairfile(&format!(
                r#"
                :443 {{
                    reverse_proxy {address} {{
                        transport fastcgi
                        {buffering}
                    }}
                }}
            "#
            ))
            .await;
            let outcome = h3_get(server, "/probe").await;
            responder.await.unwrap();
            assert_eq!(
                outcome.map(|r| (r.status, r.body)),
                Err("stream reset with code 258".to_string()),
                "buffered={buffered}, invalid={invalid_record}"
            );
        }
    }
}
