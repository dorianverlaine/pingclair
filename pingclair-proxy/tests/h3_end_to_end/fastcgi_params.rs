// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧾 HTTP/3 refuses an oversized FastCGI parameter before sending PARAMS.

use super::*;

/// 🛡️ The shared parameter refusal must become 431 on the QUIC path too.
#[tokio::test]
async fn h3_fastcgi_oversized_params_return_431() {
    use tokio::io::AsyncReadExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let responder = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut records = Vec::new();
        loop {
            let mut header = [0; 8];
            if stream.read_exact(&mut header).await.is_err() {
                break;
            }
            let length = u16::from_be_bytes([header[4], header[5]]) as usize;
            let mut discard = vec![0; length + header[6] as usize];
            stream.read_exact(&mut discard).await.unwrap();
            records.push(header[1]);
            // 🧾 The broken serializer would complete STDIN; answer so a
            // regression fails on status instead of waiting for a timeout.
            if header[1] == 5 && length == 0 {
                write_fastcgi_record(&mut stream, 6, b"Status: 200 OK\r\n\r\nwrong").await;
                write_fastcgi_record(&mut stream, 3, &[0; 8]).await;
                break;
            }
        }
        records
    });
    let value = "x".repeat(65_500);
    let source = format!(
        r#"
        :443 {{
            reverse_proxy {address} {{
                transport fastcgi {{
                    env BIG {value}
                }}
            }}
        }}
    "#
    );
    let site = pingclair_config::compile(&source).unwrap().servers[0].clone();
    let server = spawn_h3_server_with(|address| ServerConfig {
        listen: vec![address.to_string()],
        ..site
    })
    .await;
    // 🧾 A configured CGI value exercises the same refusal without requiring
    // the client's atomic HEADERS write to exceed its initial send window.
    let response = h3_get(server, "/probe").await.unwrap();
    assert_eq!(response.status, 431);
    assert_eq!(
        responder.await.unwrap(),
        vec![1],
        "no PARAMS may precede rejection"
    );
}
