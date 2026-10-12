// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🚪 `abort` closes the exchange without an HTTP response, on H1 and H2.

use super::{TestServer, no_proxy_client};
use std::time::Duration;

#[tokio::test]
async fn abort_closes_the_exchange_without_an_http_response() {
    let config = r#":__PINGCLAIR_TEST_PORT__ {
    handle __PINGCLAIR_TEST_READINESS_PATH__ {
        respond "__PINGCLAIR_TEST_READINESS_TOKEN__"
    }
    handle /abort {
        abort
    }
    handle {
        respond "healthy"
    }
}"#;
    let mut server = TestServer::new_pingclairfile(config);
    assert!(server.wait_until_ready().await, "server failed to start");
    let h2 = reqwest::Client::builder()
        .no_proxy()
        .http2_prior_knowledge()
        .build()
        .unwrap();
    for client in [no_proxy_client(), h2] {
        let response = client.get(server.url(0, "/healthy")).send().await.unwrap();
        assert_eq!(response.text().await.unwrap(), "healthy");
        let failure = client
            .get(server.url(0, "/abort"))
            .timeout(Duration::from_secs(2))
            .send()
            .await
            .expect_err("Abort must not send an HTTP status");
        assert!(
            !failure.is_timeout(),
            "Abort must close promptly: {failure}"
        );
    }
}
