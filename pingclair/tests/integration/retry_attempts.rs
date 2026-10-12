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
/// 📌 The windows are fixed, and below both platforms' ephemeral floors — Linux
/// hands out 32768–60999, macOS 49152–65535 — so no `bind(:0)` on the machine,
/// this suite's or a shard-mate's, can ever be handed one of them. The previous
/// bind-and-drop left exactly that race: on a loaded shard the kernel handed a
/// freshly dropped port to another fixture, that fixture accepted the dial, and
/// the "refused" attempt became a non-retryable request-phase failure — which
/// is how this test came up one dial short on 2026-10-11 (postmerge x86_64
/// shard 4/4 counted three retried dials instead of four).
fn refused_address(index: usize) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 21_010 + index as u16))
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
    let peers: Vec<SocketAddr> = (0..5).map(refused_address).collect();
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
    let peers: Vec<SocketAddr> = (0..5).map(refused_address).collect();
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
