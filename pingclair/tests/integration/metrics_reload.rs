// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧹 What a configuration reload leaves on `/metrics`.
//!
//! The Prometheus client keeps every child series it has ever created, so a
//! series has to be removed explicitly when the configuration stops containing
//! what it names. Otherwise a dashboard reports a backend this process no
//! longer speaks to, at its last known value (#251).

use super::{TestServer, no_proxy_client};
use std::net::SocketAddr;

/// 🌱 A loopback origin that answers every request `200 ok` and closes.
async fn spawn_ok_origin() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                let _ = stream.read(&mut buffer).await;
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await;
            });
        }
    });
    (address, task)
}

/// 🧹 Reloading without the second upstream takes its health series away.
#[tokio::test]
async fn test_a_removed_upstream_leaves_the_health_metric() {
    let (first, first_task) = spawn_ok_origin().await;
    let (second, second_task) = spawn_ok_origin().await;

    // `least_conn` is the strategy that publishes the per-upstream health
    // gauge, so the fixture asks for it explicitly.
    let config = |upstreams: &str| {
        format!(
            r#"
        {{
            admin __PINGCLAIR_TEST_ADMIN_LISTEN__
            metrics
        }}

        http://__PINGCLAIR_TEST_LISTEN__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            metrics /metrics

            reverse_proxy {upstreams} {{
                lb_policy least_conn
            }}
        }}
        "#
        )
    };

    let mut server =
        TestServer::new_pingclairfile(&config(&format!("http://{first} http://{second}")));
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();

    // Warm the pool so the gauge is published for both addresses.
    for _ in 0..4 {
        let _ = client.get(server.url(0, "/warm")).send().await;
    }
    let scrape = client
        .get(server.url(0, "/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        health_series(&scrape).contains(
            &format!("caddy_reverse_proxy_upstreams_healthy{{upstream=\"{first}\"}} 1").as_str()
        ) && health_series(&scrape).contains(
            &format!("caddy_reverse_proxy_upstreams_healthy{{upstream=\"{second}\"}} 1").as_str()
        ),
        "both upstreams are published before the reload: {scrape}"
    );

    // A reload that keeps only the first upstream. The document comes from
    // `GET /config`, which carries the addresses the test placeholders were
    // substituted with, and loses the second upstream on the way back.
    let mut document = client
        .get(server.admin_url("/config"))
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();
    assert!(
        keep_first_upstream(&mut document),
        "the document really holds a proxy route: {document}"
    );
    assert!(
        !document.to_string().contains(&second.to_string()),
        "the trimmed document no longer names the second upstream: {document}"
    );
    let reload = client
        .post(server.admin_url("/load"))
        .json(&document)
        .send()
        .await
        .unwrap();
    let (status, body) = (reload.status(), reload.text().await.unwrap());
    assert_eq!(status, 200, "the reload applies: {body}");

    let running = client
        .get(server.admin_url("/config"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        !running.contains(&second.to_string()),
        "the running document dropped the second upstream: {running}"
    );

    // 🧹 Removal must not wait for the next request: the reload is what
    // retires the series.
    let after_reload_only = client
        .get(server.url(0, "/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        !health_series(&after_reload_only)
            .iter()
            .any(|line| line.contains(&second.to_string())),
        "the reload itself retires the series: {:?}",
        health_series(&after_reload_only)
    );

    // One request publishes the surviving upstream's health; the removed
    // upstream has no way to publish anything, and must not still be listed.
    let _ = client.get(server.url(0, "/after")).send().await;
    let scrape = client
        .get(server.url(0, "/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        health_series(&scrape)
            .iter()
            .any(|line| line.contains(&first.to_string())),
        "the surviving upstream is still published: {:?}",
        health_series(&scrape)
    );
    assert!(
        !health_series(&scrape)
            .iter()
            .any(|line| line.contains(&second.to_string())),
        "the removed upstream must leave /metrics: {:?}",
        health_series(&scrape)
    );

    server.stop();
    first_task.abort();
    second_task.abort();
}

/// 🩺 Only the health gauge's own samples, so the assertion cannot be satisfied
/// (or defeated) by a different metric that happens to carry the same label
/// name — `pingclair_upstream_duration_seconds` does.
fn health_series(scrape: &str) -> Vec<&str> {
    scrape
        .lines()
        .filter(|line| line.starts_with("caddy_reverse_proxy_upstreams_healthy"))
        .collect()
}

/// ✂️ Trims the first proxy route's upstream lists to one entry, wherever the
/// route is nested.
///
/// Both spellings have to move together: `upstream_options` carries the
/// per-upstream weight and backup role and takes precedence over `upstreams`
/// when it is not empty, so trimming only `upstreams` leaves the pool
/// unchanged.
fn keep_first_upstream(node: &mut serde_json::Value) -> bool {
    match node {
        serde_json::Value::Object(map) => {
            let mut found = false;
            for key in ["upstreams", "upstream_options"] {
                if let Some(serde_json::Value::Array(upstreams)) = map.get_mut(key) {
                    upstreams.truncate(1);
                    found = true;
                }
            }
            found || map.values_mut().any(keep_first_upstream)
        }
        serde_json::Value::Array(items) => items.iter_mut().any(keep_first_upstream),
        _ => false,
    }
}
