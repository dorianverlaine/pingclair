// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! ⏱️ A request header has one deadline, however slowly it is sent.
//!
//! The attack these guard against is slowloris: open a connection, send the
//! request header one byte at a time, and never finish it. Each byte used to
//! restart the read timer, so the connection stayed open for as long as the
//! client kept trickling — and with no `header_timeout` set there was no timer
//! at all. Both tests drive a raw TCP client that sends one header byte per
//! second and measure when the server hangs up.

use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::TestServer;

/// 🧾 A site that answers everything, with `limits` written by the caller.
fn site(limits: &str) -> String {
    format!(
        r#"
        {{
            admin off
        }}

        :__PINGCLAIR_TEST_PORT__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            {limits}

            respond "ok" 200
        }}
        "#
    )
}

/// 🐌 Sends a header that never ends, one byte a second, and returns how long
/// after connecting the server closed the connection — or `None` if it was
/// still open at `give_up`.
async fn seconds_until_dribbler_is_dropped(server: &TestServer, give_up: Duration) -> Option<f64> {
    let mut stream = tokio::net::TcpStream::connect(server.address(0))
        .await
        .unwrap();
    let started = Instant::now();
    let opening = b"GET / HTTP/1.1\r\nHost: test\r\nX-Slow: ";
    let mut sent = 0usize;
    let mut buffer = [0u8; 256];
    while started.elapsed() < give_up {
        let byte = opening.get(sent).copied().unwrap_or(b'a');
        if stream.write_all(&[byte]).await.is_err() {
            return Some(started.elapsed().as_secs_f64());
        }
        sent += 1;
        // 🔌 A read that ends — cleanly or with a reset — is the server
        // hanging up; one that times out means the connection is still held.
        match tokio::time::timeout(Duration::from_secs(1), stream.read(&mut buffer)).await {
            Ok(Ok(0) | Err(_)) => return Some(started.elapsed().as_secs_f64()),
            Ok(Ok(read)) => panic!(
                "an unfinished header must not be answered: {:?}",
                String::from_utf8_lossy(&buffer[..read])
            ),
            Err(_still_open) => {}
        }
    }
    None
}

/// ⏱️ A configured `header_timeout` bounds the whole header, not each read.
///
/// With two seconds configured and a byte arriving every second, no single
/// read ever waited two seconds, so the old per-read timer never fired.
#[tokio::test]
async fn test_configured_header_timeout_bounds_a_dribbled_header() {
    let mut server = TestServer::new_pingclairfile(&site("limits {\n header_timeout 2s\n }"));
    assert!(server.wait_until_ready().await, "server failed to start");

    let closed = seconds_until_dribbler_is_dropped(&server, Duration::from_secs(10)).await;
    assert!(
        closed.is_some_and(|seconds| (1.5..5.0).contains(&seconds)),
        "a header dribbled past a 2 s header_timeout must be dropped near 2 s, got {closed:?}"
    );
}

/// ⏱️ With no `header_timeout`, a header still has one minute.
///
/// This is the default the soak run was missing: ten clients like this one
/// were all still connected after 120 s. The test takes about a minute,
/// because the default is the thing under test.
#[tokio::test]
async fn test_default_header_timeout_bounds_a_dribbled_header() {
    let mut server = TestServer::new_pingclairfile(&site(""));
    assert!(server.wait_until_ready().await, "server failed to start");

    let closed = seconds_until_dribbler_is_dropped(&server, Duration::from_secs(90)).await;
    assert!(
        closed.is_some_and(|seconds| (55.0..70.0).contains(&seconds)),
        "a dribbled header must be dropped at the 60 s default, got {closed:?}"
    );
}
