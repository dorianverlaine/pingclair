// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🚨 A `respond` without a status keeps the error status inside `handle_errors`,
//! and an explicit status overrides it, as upstream's static response does.

use super::{TestServer, no_proxy_client};

#[tokio::test]
async fn respond_inherits_errors_and_honors_overrides_over_h1_and_h2() {
    let source = r#":__PINGCLAIR_TEST_PORT__ {
    handle_errors 503 504 {
        header X-Error-Route inherited
        respond "inherited"
    }
    handle_errors 404 {
        respond "overridden" 200
    }
    handle_errors 502 {
        respond "created" 201
    }
    handle __PINGCLAIR_TEST_READINESS_PATH__ {
        respond "__PINGCLAIR_TEST_READINESS_TOKEN__"
    }
    handle /503 {
        error 503
    }
    handle /504 {
        error 504
    }
    handle /404 {
        error 404
    }
    handle /502 {
        error 502
    }
    handle {
        respond "ordinary"
    }
}"#;
    let mut server = TestServer::new_pingclairfile(source);
    assert!(server.wait_until_ready().await, "server failed to start");
    let h2 = reqwest::Client::builder()
        .no_proxy()
        .http2_prior_knowledge()
        .build()
        .unwrap();
    for (client, expected_version) in [
        (no_proxy_client(), reqwest::Version::HTTP_11),
        (h2, reqwest::Version::HTTP_2),
    ] {
        let mut seen = Vec::new();
        for path in ["/503", "/504", "/404", "/502", "/ordinary"] {
            let response = client.get(server.url(0, path)).send().await.unwrap();
            let version = response.version();
            let status = response.status().as_u16();
            if matches!(path, "/503" | "/504") {
                assert_eq!(response.headers()["X-Error-Route"], "inherited");
            }
            seen.push((status, response.text().await.unwrap()));
            assert_eq!(version, expected_version);
        }
        assert_eq!(
            seen,
            vec![
                (503, "inherited".to_string()),
                (504, "inherited".to_string()),
                (200, "overridden".to_string()),
                (201, "created".to_string()),
                (200, "ordinary".to_string()),
            ]
        );
    }
}
