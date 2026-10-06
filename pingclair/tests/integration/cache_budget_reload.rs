// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧮 Configuration owns one cache ceiling before traffic and across reloads.

use super::response_pipeline::spawn_scripted_origin;
use super::{TestServer, no_proxy_client};

#[tokio::test]
async fn test_cache_budget_is_loaded_before_requests_and_resized_on_reload() {
    let body = "x".repeat(16 * 1024);
    let (origin, _) = spawn_scripted_origin(format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nCache-Control: max-age=60\r\nConnection: close\r\n\r\n{body}", body.len()
    ).into_bytes()).await;
    let mut server = TestServer::new_pingclairfile(&format!(
        r#"
        {{
            admin __PINGCLAIR_TEST_ADMIN_LISTEN__
        }}
        http://__PINGCLAIR_TEST_LISTEN__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
            reverse_proxy /large/* http://{origin} {{
                cache {{
                    ttl 60s
                    max_size 65536
                }}
            }}
            reverse_proxy /small/* http://{origin} {{
                cache {{
                    ttl 60s
                    max_size 65536
                }}
            }}
        }}
    "#
    ));
    assert!(server.wait_until_ready().await);
    let client = no_proxy_client();
    let status = client
        .get(server.admin_url("/cache"))
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();
    assert_eq!(
        (
            status["configured"].as_bool(),
            status["limit_bytes"].as_u64()
        ),
        (Some(true), Some(64 * 1024)),
        "the configured process ceiling must exist before the first cache request"
    );
    for path in ["/large/a", "/small/b"] {
        let response = client.get(server.url(0, path)).send().await.unwrap();
        let status = response.status();
        let received = response.text().await.unwrap();
        if status != 200 {
            server.print_diagnostics();
        }
        assert_eq!(status, 200, "{path}: {received}");
        assert_eq!(received, body, "{path}");
    }
    let status = client
        .get(server.admin_url("/cache"))
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();
    assert!(status["size_bytes"].as_u64().unwrap() <= 64 * 1024);
    assert!(
        status["size_bytes"].as_u64().unwrap() > 8 * 1024,
        "the shrink must act on a warm store"
    );
    // ♻️ Admin writes exercise the real configuration transaction and preserve listener topology.
    let mut document = client
        .get(server.admin_url("/config/"))
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();
    fn resize(value: &mut serde_json::Value, limit: usize) {
        match value {
            serde_json::Value::Object(fields) => {
                if let Some(size) = fields.get_mut("max_size_bytes") {
                    *size = serde_json::json!(limit);
                }
                for field in fields.values_mut() {
                    resize(field, limit);
                }
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    resize(value, limit);
                }
            }
            _ => {}
        }
    }
    for limit in [8 * 1024, 256 * 1024] {
        resize(&mut document, limit);
        assert_eq!(
            client
                .post(server.admin_url("/load"))
                .json(&document)
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
        let status = client
            .get(server.admin_url("/cache"))
            .send()
            .await
            .unwrap()
            .json::<serde_json::Value>()
            .await
            .unwrap();
        assert_eq!(status["limit_bytes"].as_u64(), Some(limit as u64));
        assert!(
            status["size_bytes"].as_u64().unwrap() <= limit as u64,
            "shrink must evict warm entries immediately"
        );
    }
}
