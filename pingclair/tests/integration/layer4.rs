// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔌 Real-binary TCP routing, reload snapshots, and graceful connection drain.

use super::*;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener as AsyncListener, TcpStream};
use tokio::time::timeout;

fn fixture(options: &str, routes: &str) -> String {
    // 🔌 Reuse the harness's second reserved port; automatic HTTP is disabled here.
    format!(
        r#"
{{
    auto_https off
    admin __PINGCLAIR_TEST_ADMIN_LISTEN__
    grace_period 5s
    layer4 {{
        :__PINGCLAIR_TEST_HTTP_PORT__ {{
            proxy_half_close on
            {options}
            {routes}
        }}
    }}
}}
http://__PINGCLAIR_TEST_LISTEN__ {{
    @ready path __PINGCLAIR_TEST_READINESS_PATH__
    respond @ready "__PINGCLAIR_TEST_READINESS_TOKEN__"
}}
"#
    )
}

fn hello() -> Vec<u8> {
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(rustls::RootCertStore::empty())
    .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let mut client =
        rustls::ClientConnection::new(Arc::new(config), "example.test".try_into().unwrap())
            .unwrap();
    let mut wire = Vec::new();
    client.write_tls(&mut wire).unwrap();
    wire
}

#[tokio::test]
async fn tls_and_plaintext_reach_distinct_origins_without_losing_bytes() {
    timeout(Duration::from_secs(30), async {
        let tls = AsyncListener::bind("127.0.0.1:0").await.unwrap();
        let plain = AsyncListener::bind("127.0.0.1:0").await.unwrap();
        let routes = format!(
            "@secure {{\n tls {{\n sni EXAMPLE.test\n alpn h2\n }}\n remote_ip 127.0.0.0/8\n }}\n\
             route @secure {{\n proxy {}\n }}\n route {{\n proxy {}\n }}",
            tls.local_addr().unwrap(),
            plain.local_addr().unwrap()
        );
        let mut server = TestServer::new_pingclairfile(&fixture("proxy_buffer_size 1k", &routes));
        assert!(server.wait_until_ready().await);
        for (origin, mut payload) in [(tls, hello()), (plain, b"plain\0bytes".to_vec())] {
            payload.extend(std::iter::repeat_n(0x5a, 2 * 1024 * 1024));
            let expected = payload.clone();
            let backend = tokio::spawn(async move {
                let (mut stream, _) = origin.accept().await.unwrap();
                let mut received = Vec::new();
                stream.read_to_end(&mut received).await.unwrap();
                assert_eq!(received, expected);
                stream.write_all(b"after EOF").await.unwrap();
            });
            let mut stream = TcpStream::connect(server.listener_address(0, 1))
                .await
                .unwrap();
            stream.write_all(&payload).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut reply = Vec::new();
            stream.read_to_end(&mut reply).await.unwrap();
            assert_eq!(reply, b"after EOF");
            backend.await.unwrap();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn server_first_tunnels_retain_routes_across_reload_and_drain_on_stop() {
    timeout(Duration::from_secs(30), async {
        let first = AsyncListener::bind("127.0.0.1:0").await.unwrap();
        let second = AsyncListener::bind("127.0.0.1:0").await.unwrap();
        let routes = format!("route {{\n proxy {}\n }}", first.local_addr().unwrap());
        let mut server = TestServer::new_pingclairfile(&fixture("", &routes));
        assert!(server.wait_until_ready().await);
        // 🔌 The harness probes every reserved socket; a server-first route also dials for that probe.
        let (mut probe, _) = first.accept().await.unwrap();
        let mut empty = Vec::new();
        probe.read_to_end(&mut empty).await.unwrap();
        assert!(empty.is_empty());
        drop(probe);
        let address = server.listener_address(0, 1);
        let mut old = TcpStream::connect(address).await.unwrap();
        let (mut old_origin, _) = first.accept().await.unwrap();
        old_origin.write_all(b"first").await.unwrap();
        let mut greeting = [0; 5];
        old.read_exact(&mut greeting).await.unwrap();
        assert_eq!(&greeting, b"first");

        let client = no_proxy_client();
        let mut document = client
            .get(server.admin_url("/config/"))
            .send()
            .await
            .unwrap()
            .json::<serde_json::Value>()
            .await
            .unwrap();
        document["layer4"][0]["routes"][0]["upstream"] =
            serde_json::json!(second.local_addr().unwrap().to_string());
        let applied = client
            .post(server.admin_url("/load"))
            .json(&document)
            .send()
            .await
            .unwrap();
        assert_eq!(applied.status(), 200, "{}", applied.text().await.unwrap());
        let mut new = TcpStream::connect(address).await.unwrap();
        let (mut new_origin, _) = second.accept().await.unwrap();
        new_origin.write_all(b"second").await.unwrap();
        let mut greeting = [0; 6];
        new.read_exact(&mut greeting).await.unwrap();
        assert_eq!(&greeting, b"second");
        old_origin.write_all(b"still first").await.unwrap();
        let mut retained = [0; 11];
        old.read_exact(&mut retained).await.unwrap();
        assert_eq!(&retained, b"still first");

        let mut incompatible = document.clone();
        incompatible["layer4"][0]["proxy_buffer_size"] = serde_json::json!(512);
        let refused = client
            .post(server.admin_url("/load"))
            .json(&incompatible)
            .send()
            .await
            .unwrap();
        assert!(!refused.status().is_success());
        assert!(refused.text().await.unwrap().contains("restart_required"));
        let active = client
            .get(server.admin_url("/config/"))
            .send()
            .await
            .unwrap()
            .json::<serde_json::Value>()
            .await
            .unwrap();
        assert_eq!(active, document);

        // 🛑 The real process must stay alive while either accepted tunnel owes data.
        let stopped = client.post(server.admin_url("/stop")).send().await.unwrap();
        assert!(stopped.status().is_success());
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(server.exit_status().is_none());
        old_origin.write_all(b"drain").await.unwrap();
        let mut drained = [0; 5];
        old.read_exact(&mut drained).await.unwrap();
        assert_eq!(&drained, b"drain");
        drop((old, old_origin, new, new_origin));
        timeout(Duration::from_secs(8), async {
            while server.exit_status().is_none() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn incomplete_and_oversized_hellos_close_without_fallback() {
    timeout(Duration::from_secs(20), async {
        let origin = AsyncListener::bind("127.0.0.1:0").await.unwrap();
        let routes = format!(
            "@tls tls\n route @tls {{\n proxy {0}\n }}\n route {{\n proxy {0}\n }}",
            origin.local_addr().unwrap()
        );
        let mut server = TestServer::new_pingclairfile(&fixture(
            "preread_timeout 100ms\n preread_buffer_size 32",
            &routes,
        ));
        assert!(server.wait_until_ready().await);
        for input in [&[22][..], &[22, 3, 3, 255, 255][..]] {
            let mut stream = TcpStream::connect(server.listener_address(0, 1))
                .await
                .unwrap();
            stream.write_all(input).await.unwrap();
            let mut byte = [0];
            match stream.read(&mut byte).await {
                Ok(length) => assert_eq!(length, 0),
                Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset),
            }
        }
        assert!(
            timeout(Duration::from_millis(200), origin.accept())
                .await
                .is_err()
        );
    })
    .await
    .unwrap();
}

#[path = "layer4_metrics.rs"]
mod metrics;

#[path = "layer4_logs.rs"]
mod logs;
