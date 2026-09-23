// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🚫 Locally raised error statuses carry a body that explains them.
//!
//! A status line alone tells a client that something went wrong, not what.
//! RFC 6585 asks the 429 and 431 representations to say more, and an
//! operator's `error_page` for those statuses must be reachable like any
//! other.

use super::{TestServer, no_proxy_client};

/// 🚦 A site that admits one request per minute per `X-Client` value.
fn rate_limited_site(extra: &str) -> String {
    format!(
        r#"
        {{
            admin off
        }}

        :__PINGCLAIR_TEST_PORT__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            {extra}
            rate_limit 1 60s {{
                key header X-Client
            }}
            respond "admitted"
        }}
        "#
    )
}

/// 🚦 A rate-limit rejection explains itself on HTTP/1.1 and HTTP/2.
///
/// Before the fix the 429 was a bare status with no `Content-Length`, so
/// HTTP/1.1 fell back to close-delimited framing and the client learned
/// nothing but the number.
#[tokio::test]
async fn test_rate_limit_rejection_carries_a_body_on_h1_and_h2() {
    let mut server = TestServer::new_pingclairfile(&rate_limited_site(""));
    assert!(server.wait_until_ready().await, "server failed to start");

    let h2 = reqwest::Client::builder()
        .no_proxy()
        .http2_prior_knowledge()
        .build()
        .unwrap();
    for (protocol, client) in [("h1", no_proxy_client()), ("h2", h2)] {
        let url = server.url(0, "/");
        let admitted = client
            .get(&url)
            .header("X-Client", protocol)
            .send()
            .await
            .unwrap();
        assert_eq!(admitted.status(), 200, "{protocol}: first request");

        let rejected = client
            .get(&url)
            .header("X-Client", protocol)
            .send()
            .await
            .unwrap();
        let headers = rejected.headers().clone();
        let fields = (
            rejected.status().as_u16(),
            headers.get("content-type").map(|v| v.to_str().unwrap()),
            headers.get("content-length").map(|v| v.to_str().unwrap()),
            headers.contains_key("retry-after"),
        );
        let body = rejected.text().await.unwrap();
        assert_eq!(
            (fields, body.as_str()),
            (
                (429, Some("text/plain"), Some("21"), true),
                "429 Too Many Requests"
            ),
            "{protocol}: the rejection must carry a body and keep Retry-After"
        );
    }
}

/// 🧯 An operator's `error_page 429` answers a rate-limit rejection.
#[tokio::test]
async fn test_rate_limit_rejection_uses_the_configured_error_page() {
    let pages = tempfile::tempdir().unwrap();
    let page = pages.path().join("slow-down.html");
    std::fs::write(&page, "<p>slow down</p>").unwrap();
    let config = rate_limited_site(&format!("error_page 429 {}", page.display()));
    let mut server = TestServer::new_pingclairfile(&config);
    assert!(server.wait_until_ready().await, "server failed to start");

    let client = no_proxy_client();
    let url = server.url(0, "/");
    let _ = client
        .get(&url)
        .header("X-Client", "a")
        .send()
        .await
        .unwrap();
    let rejected = client
        .get(&url)
        .header("X-Client", "a")
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), 429);
    assert_eq!(rejected.headers()["content-type"], "text/html");
    assert!(rejected.headers().contains_key("retry-after"));
    assert_eq!(rejected.text().await.unwrap(), "<p>slow down</p>");
}
