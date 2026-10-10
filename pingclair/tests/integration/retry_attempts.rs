// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔢 How many peers one request dials when connections are refused.
//!
//! The reference tries each peer at most once per request and has no count
//! cap; this build retries connect failures with the same per-request
//! exclusion and a cap (`max_attempts`, 1..=16, spellable as `maxAttempts:`
//! since 2026-10-10). This file measures the number that actually leaves the
//! process, because "bounded work" is a claim about dials, not about code.

use std::net::SocketAddr;

use super::{TestServer, no_proxy_client};

/// 🎛️ An address nothing listens on: a connect attempt is refused there.
///
/// Bind and drop, so the ephemeral port the kernel handed out is closed
/// again. The window between the two belongs to this process and every peer
/// below is used for its address, never for its service.
fn refused_address() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

/// 🌐 A site that proxies to `peers`, with the metrics endpoint on `/metrics`.
fn refusing_pool(peers: &[SocketAddr], retry: &str) -> String {
    let upstreams = peers
        .iter()
        .map(|peer| format!("http://{peer}"))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        r#"{{
    admin off
    metrics
}}

http://__PINGCLAIR_TEST_LISTEN__ {{
    metrics /metrics
    @readiness path __PINGCLAIR_TEST_READINESS_PATH__
    respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
    reverse_proxy {upstreams}{retry}
}}
"#
    )
}

/// 🧾 Upstream attempts beyond the first, summed over routes.
///
/// The counter is incremented where a peer was actually selected for a retry
/// (`server.rs`, inside the `Ok` arm), so this is the number of retried dials
/// — a failed selection that dials nothing is not counted.
async fn retried_dials(server: &TestServer) -> u64 {
    let scrape = no_proxy_client()
        .get(server.url(0, "/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    scrape
        .lines()
        .filter(|line| {
            line.starts_with("pingclair_upstream_retries_total{")
                && line.contains(r#"outcome="dispatched""#)
        })
        .map(|line| line.rsplit_once(' ').unwrap().1.parse::<u64>().unwrap())
        .sum()
}

/// 🔁 A pool where every peer refuses is dialled once per peer, then 502.
#[tokio::test]
async fn a_refused_pool_is_dialled_once_per_peer() {
    let peers: Vec<SocketAddr> = (0..5).map(|_| refused_address()).collect();
    let mut server = TestServer::new_pingclairfile(&refusing_pool(&peers, ""));
    assert!(server.wait_until_ready().await, "server failed to start");

    let response = no_proxy_client()
        .get(server.url(0, "/"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 502);
    assert_eq!(
        retried_dials(&server).await,
        4,
        "five peers, one dial each: four of them are retries"
    );
}

/// 🧱 `max_attempts` — the native `maxAttempts:` spelling of it — bounds the
/// dials: two attempts mean one retried dial, not five.
#[tokio::test]
async fn max_attempts_bounds_the_dials() {
    let peers: Vec<SocketAddr> = (0..5).map(|_| refused_address()).collect();
    let mut server = TestServer::new_pingclairfile(&refusing_pool(
        &peers,
        " {\n\tretry {\n\t\tmax_attempts 2\n\t}\n}",
    ));
    assert!(server.wait_until_ready().await, "server failed to start");

    let response = no_proxy_client()
        .get(server.url(0, "/"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 502);
    assert_eq!(
        retried_dials(&server).await,
        1,
        "a cap of two attempts leaves exactly one retry"
    );
}
