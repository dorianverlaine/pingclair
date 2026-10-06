// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! ⌛ `lb_try_duration` bounds how long the proxy keeps *trying*, not how long
//! an answer may take.
//!
//! In Caddy the duration is consulted only when an attempt has failed and the
//! question is whether to start another one. An attempt already under way —
//! an origin thinking before its headers, or an event stream that runs for
//! minutes — is governed by the transport's own timeouts. These tests pin that
//! line with an origin that is slower than the budget and still succeeds: the
//! client must receive every byte of it.

use super::TestServer;
use super::no_proxy_client;
use super::read_until_marker;
use super::write_http_chunk;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

/// ⌛ The retry budget every test here runs with: shorter than the origin
/// takes, so anything that still treats it as a response deadline fails.
const TRY_DURATION: &str = "300ms";

/// 🧾 One site that proxies everything to `upstream` with a short
/// `lb_try_duration`.
fn retry_budget_site(upstream: SocketAddr) -> String {
    format!(
        r#"
        {{
            admin off
        }}

        :__PINGCLAIR_TEST_PORT__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            reverse_proxy {upstream} {{
                lb_try_duration {TRY_DURATION}
            }}
        }}
        "#
    )
}

/// 🐢 An origin that waits `header_delay` before answering, then streams
/// `events` chunked server-sent events `event_gap` apart.
async fn slow_event_origin(
    header_delay: Duration,
    events: usize,
    event_gap: Duration,
) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                read_until_marker(&mut stream, b"\r\n\r\n", Duration::from_secs(5)).await;
                tokio::time::sleep(header_delay).await;
                let (_read, mut write) = stream.into_split();
                if write
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\
                          Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                    )
                    .await
                    .is_err()
                {
                    return;
                }
                for index in 0..events {
                    if index > 0 {
                        tokio::time::sleep(event_gap).await;
                    }
                    let event = format!("data: {index}\n\n");
                    if write_http_chunk(&mut write, event.as_bytes())
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                let _ = write.write_all(b"0\r\n\r\n").await;
                let _ = write.shutdown().await;
            });
        }
    });
    address
}

/// 📜 The complete body `slow_event_origin` sends for `events` events.
fn expected_events(events: usize) -> String {
    (0..events)
        .map(|index| format!("data: {index}\n\n"))
        .collect()
}

/// 🐢 An origin that takes longer than the retry budget to send its headers
/// is still answered with its own response, not a 504.
#[tokio::test]
async fn test_slow_response_header_outlives_lb_try_duration() {
    let origin = slow_event_origin(Duration::from_millis(900), 1, Duration::ZERO).await;
    let mut server = TestServer::new_pingclairfile(&retry_budget_site(origin));
    assert!(server.wait_until_ready().await, "server failed to start");

    let reply = no_proxy_client()
        .get(server.url(0, "/"))
        .send()
        .await
        .unwrap();
    let status = reply.status().as_u16();
    let body = reply.text().await.unwrap_or_default();
    assert_eq!((status, body.as_str()), (200, expected_events(1).as_str()));
}

/// 🌊 An event stream that runs well past the retry budget reaches the client
/// whole instead of being cut when the budget runs out.
#[tokio::test]
async fn test_event_stream_outlives_lb_try_duration() {
    const EVENTS: usize = 4;
    // ⏸️ Each pause is longer than the whole budget, so a budget applied per
    // read cuts the stream just as surely as one applied to the total.
    let origin = slow_event_origin(Duration::ZERO, EVENTS, Duration::from_millis(450)).await;
    let mut server = TestServer::new_pingclairfile(&retry_budget_site(origin));
    assert!(server.wait_until_ready().await, "server failed to start");

    let reply = no_proxy_client()
        .get(server.url(0, "/"))
        .send()
        .await
        .unwrap();
    let status = reply.status().as_u16();
    let body = match reply.text().await {
        Ok(body) => body,
        Err(error) => format!("<body cut: {error}>"),
    };
    assert_eq!(
        (status, body.as_str()),
        (200, expected_events(EVENTS).as_str())
    );
}
