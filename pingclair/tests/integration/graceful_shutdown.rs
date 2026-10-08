// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🛑 SIGTERM lets running requests finish, within `grace_period`.
//!
//! The process used to exit about a quarter of a second after SIGTERM, whatever
//! `grace_period` said, so every request still running was cut: the client saw
//! a connection closed with no response at all.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::{TestServer, no_proxy_client};

/// 🐢 An origin that holds every response for `delay` before answering.
async fn spawn_slow_origin(delay: Duration) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut request = [0u8; 4096];
                let _ = stream.read(&mut request).await;
                tokio::time::sleep(delay).await;
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nslow-done")
                    .await;
            });
        }
    });
    address
}

/// 🐢 The same slow origin, with a body large enough that its response is
/// still crossing the transports when the process leaves.
///
/// 📌 The size is the point, not decoration: a nine-byte answer fits in the
/// HTTP/2 codec's and TLS layer's buffers in one go, and the shutdown race
/// that loses it only shows under load. Four megabytes are hundreds of frames
/// and several TLS records, so a process that exits before the connection
/// task flushes truncates the body every time.
async fn spawn_slow_big_origin(
    delay: Duration,
    bytes: usize,
) -> (SocketAddr, tokio::sync::mpsc::Receiver<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (arrived, requests) = tokio::sync::mpsc::channel(1);
    tokio::spawn(async move {
        let body = vec![b'x'; bytes];
        let head =
            format!("HTTP/1.1 200 OK\r\nContent-Length: {bytes}\r\nConnection: close\r\n\r\n");
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let body = body.clone();
            let head = head.clone();
            let arrived = arrived.clone();
            tokio::spawn(async move {
                let mut request = [0u8; 4096];
                if !matches!(stream.read(&mut request).await, Ok(1..)) {
                    return;
                }
                let _ = arrived.send(()).await;
                tokio::time::sleep(delay).await;
                let _ = stream.write_all(head.as_bytes()).await;
                let _ = stream.write_all(&body).await;
            });
        }
    });
    (address, requests)
}

fn sigterm(server: &TestServer) {
    // SAFETY: 🧯 `kill` is handed the pid of a child this test spawned, with a
    // signal constant from libc; a refusal is reported, never ignored.
    let sent = unsafe { libc::kill(server.process.id() as i32, libc::SIGTERM) };
    assert_eq!(sent, 0, "SIGTERM must reach the server");
}

/// ⏳ Waits for the server to exit, failing with its logs past `budget`.
async fn wait_for_exit(server: &mut TestServer, budget: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + budget;
    loop {
        if let Some(status) = server.exit_status() {
            return status;
        }
        if Instant::now() >= deadline {
            server.print_diagnostics();
            panic!("the server did not exit within {budget:?} of SIGTERM");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn config(origin: SocketAddr, grace: &str) -> String {
    format!(
        r#"
        {{
            admin off
            grace_period {grace}
        }}

        :__PINGCLAIR_TEST_PORT__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
            reverse_proxy {origin}
        }}
        "#
    )
}

/// 🚰 A request running at SIGTERM completes; a new connection is refused;
/// and the process leaves once the request is done rather than at the end of
/// the grace period.
#[cfg(unix)]
#[tokio::test]
async fn test_sigterm_lets_an_in_flight_request_finish_and_refuses_new_connections() {
    let origin = spawn_slow_origin(Duration::from_millis(1500)).await;
    let mut server = TestServer::new_pingclairfile(&config(origin, "30s"));
    assert!(server.wait_until_ready().await, "server failed to start");
    let address = server.address(0);

    let in_flight = tokio::spawn(no_proxy_client().get(server.url(0, "/slow")).send());
    // 🧭 The request must have reached the proxy before the signal; the
    // origin's delay leaves plenty of room either side of this pause.
    tokio::time::sleep(Duration::from_millis(400)).await;
    let signalled = Instant::now();
    sigterm(&server);

    // 🚫 Pingora closes its listeners on the shutdown broadcast; poll rather
    // than sleep so a slow runner only delays the answer, never flips it.
    let refused_by = Instant::now() + Duration::from_secs(1);
    let refused = loop {
        match tokio::net::TcpStream::connect(address).await {
            Err(_) => break true,
            Ok(_) if Instant::now() >= refused_by => break false,
            Ok(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    };

    let response = in_flight.await.unwrap();
    let status = wait_for_exit(&mut server, Duration::from_secs(20)).await;
    let response = match response {
        Ok(response) => response,
        Err(error) => {
            server.print_diagnostics();
            panic!("the in-flight request was cut by SIGTERM: {error}");
        }
    };
    assert_eq!(
        (response.status().as_u16(), response.text().await.unwrap()),
        (200, "slow-done".to_string()),
        "the in-flight request must complete after SIGTERM"
    );
    assert!(refused, "a new connection was accepted after SIGTERM");
    assert!(status.success(), "the server must leave cleanly: {status}");
    // 🎯 Exiting on the last request rather than the 30 s clock is the other
    // half of the behavior; 15 s leaves a slow runner ample room.
    assert!(
        signalled.elapsed() < Duration::from_secs(15),
        "the server waited out its grace period instead of leaving when idle"
    );
}

/// ⏱️ `grace_period` bounds the wait: a request that outlives it is cut and
/// the process still exits.
#[cfg(unix)]
#[tokio::test]
async fn test_sigterm_cuts_a_request_that_outlives_the_grace_period() {
    let origin = spawn_slow_origin(Duration::from_secs(60)).await;
    let mut server = TestServer::new_pingclairfile(&config(origin, "1s"));
    assert!(server.wait_until_ready().await, "server failed to start");

    let in_flight = tokio::spawn(no_proxy_client().get(server.url(0, "/slow")).send());
    tokio::time::sleep(Duration::from_millis(400)).await;
    sigterm(&server);

    let status = wait_for_exit(&mut server, Duration::from_secs(20)).await;
    assert!(status.success(), "the server must leave cleanly: {status}");
    assert!(
        in_flight.await.unwrap().is_err(),
        "a request longer than the grace period cannot have completed"
    );
}

/// 🔐 An HTTPS site with HTTP/2, and the ports the harness reserves for it.
fn tls_config(origin: SocketAddr, grace: &str) -> String {
    format!(
        r#"
        {{
            admin off
            grace_period {grace}
            http_port __PINGCLAIR_TEST_HTTP_PORT__
            https_port __PINGCLAIR_TEST_HTTPS_PORT__
            servers {{
                protocols h1 h2
            }}
        }}

        https://slow.test:__PINGCLAIR_TEST_HTTPS_PORT__ {{
            tls internal
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
            reverse_proxy {origin}
        }}
        "#
    )
}

/// 🚰 An HTTP/2 response in flight across SIGTERM still reaches the client.
///
/// The in-flight count reaches zero when the proxy has *handed* the response
/// to its transport, which is not the same as the bytes being on the wire:
/// HTTP/1 writes synchronously, while the HTTP/2 codec queues frames for its
/// connection task and the TLS layer buffers one more. The process used to
/// exit in between, so the connection closed with the response still in
/// userspace and the client lost a request the origin had already answered
/// (#313).
///
/// 📌 The loop is deliberate: measured before the fix, 5 of 7 runs lost the
/// response — one run would be a coin flip, five in a row are not.
#[cfg(unix)]
#[tokio::test]
async fn test_h2_response_in_flight_across_sigterm_reaches_the_client() {
    let (origin, mut requests) =
        spawn_slow_big_origin(Duration::from_millis(800), 4 * 1024 * 1024).await;
    for attempt in 1..=5 {
        let mut server = TestServer::new_pingclairfile(&tls_config(origin, "30s"));
        assert!(
            server.wait_until_tls_ready("slow.test").await,
            "attempt {attempt}: server failed to start"
        );

        // 🔌 curl, not a Rust client: the wire behaviour under test is the
        // one a real client sees, and curl is what the issue measured with.
        let curl = std::process::Command::new("curl")
            .args([
                "--http2",
                "-ksS",
                "--noproxy",
                "*",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code} %{size_download}",
                "--resolve",
                &format!("slow.test:{}:127.0.0.1", server.address(0).port()),
                &server.tls_url(0, "slow.test", "/slow"),
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("curl must start");
        // 🧭 Confirm admission before stopping: spawning curl does not prove
        // its TLS handshake finished, especially while other suites compile.
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(10), requests.recv()).await,
            Ok(Some(())),
            "attempt {attempt}: the origin never received the request"
        );
        sigterm(&server);

        let status = wait_for_exit(&mut server, Duration::from_secs(20)).await;
        let output = curl.wait_with_output().expect("curl must exit");
        let observed = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if observed != "200 4194304" {
            server.print_diagnostics();
            panic!(
                "attempt {attempt}: the HTTP/2 response was cut by SIGTERM \
                 (curl said {observed:?}, rc {:?}, {})",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        assert!(status.success(), "attempt {attempt}: {status}");
    }
}
