// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧱 `request_buffers` and `response_buffers` on the FastCGI transport.
//!
//! FastCGI writes and reads its own records instead of going through the
//! HTTP proxy body filters, so both settings used to be accepted and then
//! ignored there, with a load-time warning saying so. These tests watch the
//! responder's side of the socket, because the client receives the same bytes
//! whether or not anything was buffered: what buffering changes is how the
//! body is cut into records and when the client sees the first of them.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use tokio::io::AsyncWriteExt;

use super::{TestServer, read_fcgi_record, read_until_marker, write_fcgi_record};

/// ⏸️ How long the responder waits between the two halves of its body.
const PAUSE: Duration = Duration::from_millis(600);

/// 🧾 Per request, in arrival order, the content of each `STDIN` record.
type ObservedStdin = Arc<Mutex<Vec<Vec<Vec<u8>>>>>;

/// 🧵 A FastCGI responder that records every `STDIN` record it receives, then
/// answers `first`, pauses, and answers `second`.
///
/// One thread per connection, so the pause of one request never delays the
/// next request's first byte and the timing assertions measure the proxy.
fn spawn_pausing_responder() -> (u16, ObservedStdin) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the FastCGI responder");
    let port = listener.local_addr().unwrap().port();
    let observed = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&observed);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let recorded = Arc::clone(&recorded);
            thread::spawn(move || {
                let _ = serve(stream, &recorded);
            });
        }
    });
    (port, observed)
}

/// 🧵 Serves one request on `stream` for [`spawn_pausing_responder`].
fn serve<S: Read + Write>(
    mut stream: S,
    recorded: &Mutex<Vec<Vec<Vec<u8>>>>,
) -> std::io::Result<()> {
    let mut records = Vec::new();
    loop {
        let (record_type, content) = read_fcgi_record(&mut stream)?;
        if record_type == 5 {
            if content.is_empty() {
                break;
            }
            records.push(content);
        }
    }
    recorded.lock().unwrap().push(records);
    write_fcgi_record(
        &mut stream,
        6,
        b"Status: 200 OK\r\nContent-Type: text/plain\r\n\r\nfirst",
    )?;
    stream.flush()?;
    thread::sleep(PAUSE);
    write_fcgi_record(&mut stream, 6, b"second")?;
    write_fcgi_record(&mut stream, 6, &[])?;
    write_fcgi_record(&mut stream, 3, &[0u8; 8])?;
    Ok(())
}

/// 🧾 A site with one buffered FastCGI route and one streaming FastCGI route.
fn config(port: u16, directive: &str) -> String {
    format!(
        r#"
        {{
            admin off
        }}

        http://__PINGCLAIR_TEST_LISTEN__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            handle /buffered/* {{
                reverse_proxy 127.0.0.1:{port} {{
                    transport fastcgi
                    {directive} unlimited
                }}
            }}

            reverse_proxy 127.0.0.1:{port} {{
                transport fastcgi
            }}
        }}
        "#
    )
}

/// 🧱 `request_buffers` hands the responder one `STDIN` record holding a body
/// the client trickled in two pieces; the streaming route hands it two.
#[tokio::test]
async fn test_fastcgi_request_buffers_hold_the_body_until_the_client_finishes() {
    let (port, observed) = spawn_pausing_responder();
    let mut server = TestServer::new_pingclairfile(&config(port, "request_buffers"));
    assert!(server.wait_until_ready().await, "server failed to start");

    for path in ["/buffered/upload", "/streamed/upload"] {
        let address = server.address(0);
        let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
        // 📏 A declared length, because the FastCGI transport refuses a body
        // without one: PHP-FPM needs `CONTENT_LENGTH` before any `STDIN`.
        client
            .write_all(
                format!(
                    "POST {path} HTTP/1.1\r\nHost: {address}\r\n\
                     Content-Length: 11\r\n\r\nfirst"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        client.write_all(b"second").await.unwrap();
        let response = read_until_marker(&mut client, b"second", Duration::from_secs(10)).await;
        assert!(
            String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200"),
            "the FastCGI request must succeed on {path}"
        );
    }

    let observed = observed.lock().unwrap().clone();
    assert_eq!(
        observed,
        vec![
            vec![b"firstsecond".to_vec()],
            vec![b"first".to_vec(), b"second".to_vec()],
        ],
        "only the buffered route may join the client's two pieces"
    );
}

/// 🧱 `response_buffers` withholds the responder's body until it finishes;
/// the streaming route shows the first half before the second exists.
#[tokio::test]
async fn test_fastcgi_response_buffers_hold_the_body_until_the_responder_finishes() {
    let (port, _observed) = spawn_pausing_responder();
    let mut server = TestServer::new_pingclairfile(&config(port, "response_buffers"));
    assert!(server.wait_until_ready().await, "server failed to start");

    // ⏱️ Measured on the raw socket, so "first byte" means the wire.
    let first_body_byte_at = |path: &'static str| {
        let address = server.address(0);
        async move {
            let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
            client
                .write_all(format!("GET {path} HTTP/1.1\r\nHost: {address}\r\n\r\n").as_bytes())
                .await
                .unwrap();
            let started = std::time::Instant::now();
            let _ = read_until_marker(&mut client, b"first", Duration::from_secs(10)).await;
            started.elapsed()
        }
    };

    let streamed = first_body_byte_at("/streamed/probe").await;
    let buffered = first_body_byte_at("/buffered/probe").await;
    assert!(
        streamed < PAUSE,
        "an unbuffered FastCGI response must start before the responder finishes, took {streamed:?}"
    );
    assert!(
        buffered >= PAUSE,
        "`response_buffers` must withhold the FastCGI body until the responder finishes, took {buffered:?}"
    );
}
