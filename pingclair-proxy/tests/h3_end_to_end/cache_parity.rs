// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧊 HTTP/3 does not use the response cache, which the docs state.

use super::*;

/// 🧊 An H3 request to a `cache` route always reaches the origin.
///
/// The response cache is driven by Pingora's HTTP/1.1 and HTTP/2 proxy
/// lifecycle; the QUIC path has its own upstream exchange and never consults
/// it. The `cache` page in the documentation says so, and this test is the
/// tripwire: wiring the cache into H3 has to flip it (#205).
#[tokio::test]
async fn h3_requests_always_reach_the_origin_while_the_cache_is_h1_h2_only() {
    let (origin, _heads, hits) = spawn_scripted_upstream(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\
          Cache-Control: public, max-age=60\r\nContent-Length: 2\r\n\r\nok",
    )
    .await;
    let source = format!(
        ":443 {{\n reverse_proxy http://{origin} {{\n  cache {{\n   ttl 60s\n  }}\n }}\n}}"
    );
    let config = pingclair_config::compile(&source).unwrap();
    // 🧊 The store the real binary configures at startup, so a wired-up H3
    // cache would be able to answer — otherwise this test would pass for the
    // wrong reason.
    pingclair_proxy::server::configure_response_cache(&config.servers);
    let server = spawn_h3_server(config.servers[0].routes[0].handler.clone()).await;

    for attempt in 0..2 {
        let response = h3_get(server, "/cached").await.unwrap();
        assert_eq!(response.status, 200, "attempt {attempt}");
        assert_eq!(response.body, b"ok", "attempt {attempt}");
    }
    assert_eq!(
        hits.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "HTTP/3 is documented as not using the response cache; wiring it in must flip this test"
    );
}
