// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧾 Large FastCGI headers either arrive intact or receive 431.

use super::*;

/// 🛡️ Refuse oversized pairs on H1/H2 while forwarding a near-limit header intact.
#[tokio::test]
async fn test_fastcgi_oversized_params_return_431_on_h1_and_h2() {
    for http2 in [false, true] {
        let responder = MockFastCgi::start();
        let config = format!(
            r#"
            {{
                admin off
            }}
            :__PINGCLAIR_TEST_PORT__ {{
                @readiness path __PINGCLAIR_TEST_READINESS_PATH__
                respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
                limits {{
                    max_header_bytes 131072
                }}
                reverse_proxy 127.0.0.1:{port} {{
                    transport fastcgi
                }}
            }}
        "#,
            port = responder.port
        );
        let mut server = TestServer::new_pingclairfile(&config);
        assert!(server.wait_until_ready().await, "server failed to start");
        let builder = reqwest::Client::builder().no_proxy();
        let client = if http2 {
            builder.http2_prior_knowledge()
        } else {
            builder.http1_only()
        }
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
        let value = "x".repeat(65_400);
        let response = client
            .get(server.url(0, "/probe"))
            .header("X-Near-Limit", &value)
            .header("X-Z-After", "following-parameter")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        response.bytes().await.unwrap();
        let requests = responder.requests.lock().unwrap().clone();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].0.get("HTTP_X_NEAR_LIMIT"), Some(&value));
        assert_eq!(
            requests[0].0.get("HTTP_X_Z_AFTER"),
            Some(&"following-parameter".to_string())
        );
        let rejected = client
            .get(server.url(0, "/probe"))
            .header("X-Near-Limit", "y".repeat(65_500))
            .send()
            .await
            .unwrap();
        assert_eq!(rejected.status(), 431, "http2={http2}");
        rejected.bytes().await.unwrap();
        assert_eq!(
            responder.requests.lock().unwrap().len(),
            1,
            "an oversized environment must not reach the responder as a request"
        );
    }
}
