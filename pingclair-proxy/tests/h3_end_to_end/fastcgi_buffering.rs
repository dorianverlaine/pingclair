//! 🧱 `request_buffers` and `response_buffers` on the HTTP/3 FastCGI path.
//!
//! The QUIC FastCGI exchange writes its own records, apart from both the
//! HTTP/3 reverse-proxy loop and the H1/H2 FastCGI exchange, so each of the
//! four body directions needs its own proof. The responder here records the
//! `STDIN` records it receives and answers in two halves with a pause.

use super::*;

/// 🧵 A FastCGI responder for `connections` requests. Each request's `STDIN`
/// record sizes are returned; each answer is `first`, a pause, then `second`.
async fn spawn_recording_responder(
    connections: usize,
) -> (SocketAddr, tokio::task::JoinHandle<Vec<Vec<usize>>>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut observed = Vec::new();
        for _ in 0..connections {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut records = Vec::new();
            loop {
                let mut header = [0u8; 8];
                stream.read_exact(&mut header).await.unwrap();
                let length = u16::from_be_bytes([header[4], header[5]]) as usize;
                let mut discard = vec![0u8; length + header[6] as usize];
                stream.read_exact(&mut discard).await.unwrap();
                if header[1] == 5 {
                    if length == 0 {
                        break;
                    }
                    records.push(length);
                }
            }
            observed.push(records);
            write_fastcgi_record(
                &mut stream,
                6,
                b"Status: 200 OK\r\nContent-Type: text/plain\r\n\r\nfirst",
            )
            .await;
            tokio::time::sleep(Duration::from_millis(600)).await;
            write_fastcgi_record(&mut stream, 6, b"second").await;
            write_fastcgi_record(&mut stream, 6, &[]).await;
            write_fastcgi_record(&mut stream, 3, &[0u8; 8]).await;
            stream.shutdown().await.unwrap();
        }
        observed
    });
    (address, task)
}

/// 🧾 One buffered FastCGI route and one streaming FastCGI route.
async fn spawn_site(responder: SocketAddr, directive: &str) -> SocketAddr {
    let source = format!(
        r#":443 {{
            handle /buffered/* {{
                reverse_proxy {responder} {{
                    transport fastcgi
                    {directive} unlimited
                }}
            }}

            reverse_proxy {responder} {{
                transport fastcgi
            }}
        }}"#
    );
    let site = pingclair_config::compile(&source).unwrap().servers[0].clone();
    spawn_h3_server_with(|address| ServerConfig {
        listen: vec![address.to_string()],
        ..site
    })
    .await
}

/// 🧱 A quarter-megabyte body crosses many QUIC frames. Buffered, it reaches
/// the responder cut only at the FastCGI record ceiling; streamed, it arrives
/// in the pieces the client's frames made.
#[tokio::test]
async fn h3_fastcgi_request_buffers_hold_the_body_until_the_client_finishes() {
    let (responder, observed) = spawn_recording_responder(2).await;
    let server = spawn_site(responder, "request_buffers").await;

    let body = vec![b'x'; 256 * 1024];
    for path in ["/buffered/upload", "/streamed/upload"] {
        let response = h3_attempt(
            H3Attempt {
                method: "POST",
                body: &body,
                extra_headers: &[("content-length", "262144")],
                ..H3Attempt::to(server, path)
            },
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            response.status, 200,
            "the FastCGI POST must succeed on {path}"
        );
    }

    let observed = observed.await.unwrap();
    assert_eq!(
        observed[0],
        vec![65_500, 65_500, 65_500, 65_500, 144],
        "`request_buffers` must send the whole body in full-size records"
    );
    assert!(
        observed[1].len() > observed[0].len(),
        "without buffering the responder must see the client's own pieces, saw {:?}",
        observed[1]
    );
    assert_eq!(observed[1].iter().sum::<usize>(), body.len());
}

/// 🧱 Buffered, the first body chunk the client sees already holds both
/// halves; streamed, it holds only the half written before the pause.
#[tokio::test]
async fn h3_fastcgi_response_buffers_hold_the_body_until_the_responder_finishes() {
    let (responder, observed) = spawn_recording_responder(2).await;
    let server = spawn_site(responder, "response_buffers").await;

    let first_chunk_of = |path: &'static str| async move {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let response = h3_get_observing_first_chunk(server, path, &[], Some(tx))
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"firstsecond", "the whole body must arrive");
        rx.await.expect("a body chunk must have been observed")
    };

    assert_eq!(first_chunk_of("/streamed/probe").await, b"first".to_vec());
    assert_eq!(
        first_chunk_of("/buffered/probe").await,
        b"firstsecond".to_vec(),
        "`response_buffers` must withhold the FastCGI body until the responder finishes"
    );
    observed.await.unwrap();
}
