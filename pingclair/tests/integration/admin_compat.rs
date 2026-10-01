// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

use super::*;

#[tokio::test]
async fn missing_config_reads_return_null_and_support_creation() {
    let mut server = TestServer::new_pingclairfile(&admin_test_pingclairfile("/__null", "null"));
    assert!(server.wait_until_ready().await);
    let client = no_proxy_client();
    for path in [
        "/config/apps/",
        "/config/nope",
        "/config/servers/0/nope",
        "/config/servers/99",
        "/config/nope/deeper",
    ] {
        let response = client.get(server.admin_url(path)).send().await.unwrap();
        assert_eq!(response.status(), 200, "{path}");
        assert!(response.headers().contains_key("etag"));
        assert_eq!(
            response.json::<serde_json::Value>().await.unwrap(),
            serde_json::Value::Null
        );
    }
    let path = "/config/servers/0/extra";
    let absent = client.get(server.admin_url(path)).send().await.unwrap();
    let tag = absent.headers()["etag"].to_str().unwrap().to_owned();
    let created = client
        .put(server.admin_url(path))
        .header("If-Match", &tag)
        .json(&true)
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 200);
    let stale = client
        .patch(server.admin_url(path))
        .header("If-Match", &tag)
        .json(&false)
        .send()
        .await
        .unwrap();
    assert_eq!(stale.status(), 412);
    let missing = client
        .patch(server.admin_url("/config/servers/0/nope"))
        .json(&false)
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 404);
    let error = missing.json::<serde_json::Value>().await.unwrap()["error"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(error.contains("/config/servers/0"), "{error}");
    assert!(!error.contains("top level"), "{error}");
}

#[tokio::test]
async fn metrics_export_caddy_names_and_retain_extensions() {
    let config = admin_test_pingclairfile("/__metrics_names", "metrics").replace(
        "admin __PINGCLAIR_TEST_ADMIN_LISTEN__",
        "metrics\n            admin __PINGCLAIR_TEST_ADMIN_LISTEN__",
    );
    let mut server = TestServer::new_pingclairfile(&config);
    assert!(server.wait_until_ready().await);
    let client = no_proxy_client();
    let response = client
        .get(server.url(0, "/__metrics_names"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "metrics");
    let response = client
        .get(server.admin_url("/metrics"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let metrics = response.text().await.unwrap();
    for name in [
        "caddy_http_requests_total",
        "caddy_http_request_duration_seconds",
        "caddy_http_request_size_bytes",
        "caddy_http_response_size_bytes",
        "caddy_http_response_duration_seconds",
        "caddy_admin_http_requests_total",
    ] {
        assert!(
            metrics.contains(&format!("# TYPE {name} ")),
            "missing {name}: {metrics}"
        );
        assert!(
            metrics
                .lines()
                .any(|line| !line.starts_with('#') && line.starts_with(name)),
            "no samples for {name}"
        );
    }
    assert!(metrics.contains("# TYPE pingclair_access_log_dropped_total counter"));
    assert!(metrics.contains("# TYPE pingclair_config_version gauge"));
    assert!(!metrics.contains("# TYPE pingclair_requests_total "));
    assert!(!metrics.contains("# TYPE pingclair_admin_http_requests_total "));
}
