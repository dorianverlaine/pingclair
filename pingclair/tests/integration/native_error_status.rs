// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🚨 An omitted native response status preserves the active error.

use super::{TestServer, no_proxy_client};

#[tokio::test]
async fn native_respond_inherits_errors_and_honors_overrides_over_h1_and_h2() {
    let source = r#"HTTPListener(on: "__PINGCLAIR_TEST_LISTEN__") {
        Site(host: "*") {
            ErrorRoute(for: [.status(503), .status(504)]) {
                ResponseHeader(.set("X-Error-Route", "inherited"))
                Respond(body: "inherited")
            }
            ErrorRoute(for: [.status(404)]) { Respond(body: "overridden", status: 200) }
            ErrorRoute(for: [.status(502)]) { Respond(body: "created", status: 201) }
            Route(when: .path(exact: "__PINGCLAIR_TEST_READINESS_PATH__")) {
                Respond(body: "__PINGCLAIR_TEST_READINESS_TOKEN__")
            }
            Route(when: .path(exact: "/503")) { Fail(status: 503) }
            Route(when: .path(exact: "/504")) { Fail(status: 504) }
            Route(when: .path(exact: "/404")) { Fail(status: 404) }
            Route(when: .path(exact: "/502")) { Fail(status: 502) }
            Fallback { Respond(body: "ordinary") }
        }
    }"#;
    let mut server = TestServer::new_native(source);
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
