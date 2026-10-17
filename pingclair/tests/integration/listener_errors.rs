// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔇 A client that walks away during the TLS handshake is a counter, not an
//! ERROR line on a healthy server.
//!
//! The listener cannot answer a request that never became HTTP. Keeping the
//! rate visible in `/metrics` is what separates a scan from an expired
//! certificate or a broken listener.

use std::time::Duration;

use tokio::io::AsyncWriteExt;

use super::{TestServer, no_proxy_client};

/// 🔢 The value of one unlabelled Prometheus counter.
fn counter_value(metrics: &str, name: &str) -> f64 {
    metrics
        .lines()
        .find(|line| !line.starts_with('#') && line.starts_with(name))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse().ok())
        .unwrap_or(0.0)
}

/// 🔐 A TLS listener whose handshake failure must not become an ERROR line.
#[tokio::test]
async fn a_client_that_closes_without_a_handshake_is_counted_not_logged_as_error() {
    let config = r#"
        {
            admin __PINGCLAIR_TEST_ADMIN_LISTEN__
            http_port __PINGCLAIR_TEST_HTTP_PORT__
            metrics
        }

        https://localhost:__PINGCLAIR_TEST_PORT__ {
            tls internal

            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
            respond "ok"
        }
    "#;
    let mut server = TestServer::new_pingclairfile(config);
    assert!(
        server.wait_until_tls_ready("localhost").await,
        "the TLS listener did not start"
    );

    // 🚪 Speak plaintext to the TLS port and leave without a handshake. This
    // is the shape scanners and impatient clients produce.
    let mut stream = tokio::net::TcpStream::connect(server.address(0))
        .await
        .expect("connect to the TLS listener");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("write the non-TLS bytes");
    drop(stream);

    let client = no_proxy_client();
    let mut metrics = String::new();
    let mut counted = 0.0;
    for _ in 0..50 {
        metrics = client
            .get(server.admin_url("/metrics"))
            .send()
            .await
            .expect("the admin metrics endpoint must answer")
            .text()
            .await
            .expect("metrics body");
        counted = counter_value(&metrics, "pingclair_downstream_handshake_failures_total");
        if counted > 0.0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        counted > 0.0,
        "the handshake failure must move its counter: {metrics}"
    );

    // 🧾 The bridge re-levels the record to DEBUG, and this harness sets
    // RUST_LOG=info, so the template's ERROR line must be gone.
    let stderr = std::fs::read_to_string(&server.stderr_path).unwrap_or_default();
    assert!(
        !stderr.contains("Downstream handshake error"),
        "a client-caused handshake failure reached the ERROR log: {stderr}"
    );
}
