// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🌊 Immediate-flush routes bypass storage before the upstream phase.

use super::cache::cache_pingclairfile;
use super::response_pipeline::spawn_scripted_origin;
use super::{TestServer, no_proxy_client, origin_hits_for_two_requests};

#[tokio::test]
async fn test_immediate_flush_and_sse_routes_are_never_cached() {
    for content_type in ["text/plain", "text/event-stream"] {
        let (origin, hits) = spawn_scripted_origin(format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nCache-Control: max-age=60\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"
        ).into_bytes()).await;
        let config =
            cache_pingclairfile(origin, "60s").replace("cache {", "flush_interval -1\n cache {");
        let mut server = TestServer::new_pingclairfile(&config);
        assert!(server.wait_until_ready().await);
        assert_eq!(
            origin_hits_for_two_requests(&server, &no_proxy_client(), &hits, "/stream").await,
            2,
            "{content_type} on an immediate-flush route was cached"
        );
    }
}
