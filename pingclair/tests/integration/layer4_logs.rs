// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

use super::*;
use std::path::Path;

async fn record(path: &Path, port: u16) -> serde_json::Value {
    timeout(Duration::from_secs(5), async {
        loop {
            for line in std::fs::read_to_string(path).unwrap_or_default().lines() {
                if let Ok(record) = serde_json::from_str::<serde_json::Value>(line)
                    && record["remote_port"] == port
                {
                    return record;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap()
}

fn log(path: &Path) -> String {
    format!("log {{\n output file {}\n format json\n}}", path.display())
}

#[tokio::test]
async fn logs_account_for_preread_failures_and_refused_upstreams() {
    timeout(Duration::from_secs(30), async {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("sessions.jsonl");
        let reserved = AsyncListener::bind("127.0.0.1:0").await.unwrap();
        let address = reserved.local_addr().unwrap();
        drop(reserved);
        let routes = format!("@tls tls\nroute @tls {{\n proxy {address}\n}}");
        let config = fixture(
            &format!(
                "{}\npreread_timeout 100ms\npreread_buffer_size 16k",
                log(&path)
            ),
            &routes,
        )
        .replace("    auto_https off", "    metrics\n    auto_https off")
        .replace("    @ready path", "    metrics /metrics\n    @ready path");
        let mut server = TestServer::new_pingclairfile(&config);
        assert!(server.wait_until_ready().await);
        for (input, outcome, status) in [
            (vec![22], "preread_timeout", 200),
            (vec![22, 3, 3, 255, 255], "preread_overflow", 400),
            (b"plaintext".to_vec(), "no_route", 502),
            (vec![22, 3, 3, 0, 1, 0], "no_route", 502),
            (hello(), "connect_error", 502),
        ] {
            let mut stream = TcpStream::connect(server.listener_address(0, 1))
                .await
                .unwrap();
            let port = stream.local_addr().unwrap().port();
            stream.write_all(&input).await.unwrap();
            let _ = stream.read_to_end(&mut Vec::new()).await;
            let entry = record(&path, port).await;
            assert_eq!(
                (&entry["outcome"], &entry["status"]),
                (&serde_json::json!(outcome), &serde_json::json!(status))
            );
            assert_eq!(entry["bytes_sent"], 0);
            assert_eq!(entry["upstream_bytes_sent"], 0);
            assert!(entry.get("upstream_connect_time").is_none());
            assert!(entry.get("sni").is_none());
        }
        let metrics = super::metrics::scrape(&server).await;
        assert_eq!(
            super::metrics::value(
                &metrics,
                "l4_preread_failures_total",
                &["reason=\"declined_tls\""]
            ),
            1.0
        );
        assert_eq!(
            super::metrics::value(
                &metrics,
                "l4_upstream_connect_failures_total",
                &["reason=\"io_error\""]
            ),
            1.0
        );
        assert_eq!(
            super::metrics::value(
                &metrics,
                "l4_preread_failures_total",
                &["reason=\"timeout\""]
            ),
            1.0
        );
        assert_eq!(
            super::metrics::value(
                &metrics,
                "l4_preread_failures_total",
                &["reason=\"overflow\""]
            ),
            1.0
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn established_sessions_keep_their_logger_across_reload() {
    timeout(Duration::from_secs(30), async {
        let directory = tempfile::tempdir().unwrap();
        let first = directory.path().join("first.jsonl");
        let second = directory.path().join("second.jsonl");
        let origin = AsyncListener::bind("127.0.0.1:0").await.unwrap();
        let routes = format!(
            "@tls tls\nroute @tls {{\n proxy {}\n}}",
            origin.local_addr().unwrap()
        );
        let mut server = TestServer::new_pingclairfile(&fixture(&log(&first), &routes));
        assert!(server.wait_until_ready().await);
        let wire = hello();
        let mut old = TcpStream::connect(server.listener_address(0, 1))
            .await
            .unwrap();
        let old_port = old.local_addr().unwrap().port();
        old.write_all(&wire).await.unwrap();
        let (mut backend, _) = origin.accept().await.unwrap();
        backend.read_exact(&mut vec![0; wire.len()]).await.unwrap();
        let next = fixture(&log(&second), &routes)
            .replace("__PINGCLAIR_TEST_LISTEN__", &server.address(0).to_string())
            .replace(
                "__PINGCLAIR_TEST_HTTP_PORT__",
                &server.listener_address(0, 1).port().to_string(),
            )
            .replace(
                "__PINGCLAIR_TEST_ADMIN_LISTEN__",
                &server.admin_address.unwrap().to_string(),
            );
        let applied = no_proxy_client()
            .post(server.admin_url("/load"))
            .header("Content-Type", "text/caddyfile")
            .body(next)
            .send()
            .await
            .unwrap();
        assert_eq!(applied.status(), 200, "{}", applied.text().await.unwrap());
        old.shutdown().await.unwrap();
        assert_eq!(backend.read(&mut [0; 1]).await.unwrap(), 0);
        backend.write_all(b"after EOF").await.unwrap();
        backend.shutdown().await.unwrap();
        let mut reply = Vec::new();
        old.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, b"after EOF");
        let entry = record(&first, old_port).await;
        assert_eq!(entry["bytes_received"], wire.len());
        assert_eq!(entry["upstream_bytes_sent"], wire.len());
        assert_eq!(entry["bytes_sent"], 9);
        assert_eq!(entry["upstream_bytes_received"], 9);
        assert_eq!(entry["outcome"], "completed");
        assert!(entry["upstream_connect_time"].is_number());
        assert!(
            !std::fs::read_to_string(&first)
                .unwrap()
                .contains("example.test")
        );
        let mut new = TcpStream::connect(server.listener_address(0, 1))
            .await
            .unwrap();
        let new_port = new.local_addr().unwrap().port();
        new.write_all(b"plain").await.unwrap();
        let _ = new.read_to_end(&mut Vec::new()).await;
        assert_eq!(record(&second, new_port).await["outcome"], "no_route");
        assert!(
            !std::fs::read_to_string(&second)
                .unwrap()
                .contains(&format!("\"remote_port\":{old_port},"))
        );
    })
    .await
    .unwrap();
}
