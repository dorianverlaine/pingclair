// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 📊 A Pingclairfile that never says `metrics` collects nothing.
//!
//! 📌 This matches Caddy, and it is what makes a benchmark configuration and an
//! operator's configuration the same program: before the default flipped, every
//! DSL-configured server paid for metrics it had not asked for, and there was no
//! way to write the shape the published numbers were measured on.

use super::TestServer;
use super::no_proxy_client;

/// 🚫 Without the global `metrics` option, requests are served but not counted.
///
/// The scrape route stays reachable so the test can look: an empty exposition
/// is the evidence that no request series were recorded, where a missing route
/// would only prove the route was missing.
#[tokio::test]
async fn test_metrics_are_not_collected_unless_the_option_is_set() {
    let config = r#"
        {
            admin off
        }

        http://__PINGCLAIR_TEST_LISTEN__ {
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            metrics /metrics
            respond /hello "hello" 200
        }
    "#;
    let mut server = TestServer::new_pingclairfile(config);
    assert!(server.wait_until_ready().await, "server failed to start");

    let client = no_proxy_client();
    let hello = client.get(server.url(0, "/hello")).send().await.unwrap();
    assert_eq!(hello.text().await.unwrap(), "hello");

    let scrape = client.get(server.url(0, "/metrics")).send().await.unwrap();
    assert_eq!(scrape.status(), 200);
    assert_eq!(
        scrape.text().await.unwrap(),
        "",
        "no `metrics` option means no series at all"
    );
}
