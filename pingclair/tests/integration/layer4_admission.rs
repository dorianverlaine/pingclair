// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🚦 Real listener admission survives reload and releases capacity after disconnect.

use super::*;

#[tokio::test]
async fn quota_survives_reload_and_releases_after_disconnect() {
    timeout(Duration::from_secs(30), async {
        let origin = AsyncListener::bind("127.0.0.1:0").await.unwrap();
        let routes = format!("route {{\n proxy {}\n }}", origin.local_addr().unwrap());
        let mut server = TestServer::new_pingclairfile(&fixture("max_connections 1", &routes));
        assert!(server.wait_until_ready().await);
        // 🔌 Finish the harness probe before occupying the single session slot.
        let (mut probe, _) = origin.accept().await.unwrap();
        let mut empty = Vec::new();
        probe.read_to_end(&mut empty).await.unwrap();
        drop(probe);
        let address = server.listener_address(0, 1);
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let mut active = None;
        let mut backend = None;
        // ⏱️ Permit release can follow downstream EOF; wait for an acknowledged new session.
        while active.is_none() {
            let mut stream = TcpStream::connect(address).await.unwrap();
            let mut byte = [0];
            tokio::select! {
                pair = origin.accept() => {
                    backend = Some(pair.unwrap().0);
                    active = Some(stream);
                }
                result = stream.read(&mut byte) => {
                    assert!(matches!(result, Ok(0)) || result.is_err());
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
        for reload in [false, true] {
            if reload {
                let document = client
                    .get(server.admin_url("/config/"))
                    .send()
                    .await
                    .unwrap()
                    .json::<serde_json::Value>()
                    .await
                    .unwrap();
                assert!(
                    client
                        .post(server.admin_url("/load"))
                        .json(&document)
                        .send()
                        .await
                        .unwrap()
                        .status()
                        .is_success()
                );
            }
            let mut refused = TcpStream::connect(address).await.unwrap();
            let result = timeout(Duration::from_secs(2), refused.read(&mut [0]))
                .await
                .unwrap();
            assert!(matches!(result, Ok(0)) || result.is_err());
            assert!(
                timeout(Duration::from_millis(50), origin.accept())
                    .await
                    .is_err()
            );
            backend.as_mut().unwrap().write_all(b"alive").await.unwrap();
            let mut reply = [0; 5];
            active
                .as_mut()
                .unwrap()
                .read_exact(&mut reply)
                .await
                .unwrap();
            assert_eq!(&reply, b"alive");
        }
        drop((active, backend));
        // ♻️ A completed session restores capacity without a process restart.
        loop {
            let mut stream = TcpStream::connect(address).await.unwrap();
            let mut byte = [0];
            tokio::select! {
                pair = origin.accept() => {
                    let mut backend = pair.unwrap().0;
                    backend.write_all(b"new").await.unwrap();
                    let mut reply = [0; 3];
                    stream.read_exact(&mut reply).await.unwrap();
                    assert_eq!(&reply, b"new");
                    break;
                }
                _ = stream.read(&mut byte) => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn incomplete_client_hello_occupies_admission_until_timeout() {
    timeout(Duration::from_secs(20), async {
        let origin = AsyncListener::bind("127.0.0.1:0").await.unwrap();
        let routes = format!(
            "@tls tls\nroute @tls {{\n proxy {}\n}}",
            origin.local_addr().unwrap()
        );
        let config = fixture("max_connections 1\npreread_timeout 2s", &routes)
            .replace("    auto_https off", "    metrics\n    auto_https off")
            .replace("    @ready path", "    metrics /metrics\n    @ready path");
        let mut server = TestServer::new_pingclairfile(&config);
        assert!(server.wait_until_ready().await);
        while metrics::value(
            &metrics::scrape(&server).await,
            "l4_active_connections",
            &[],
        ) != 0.0
        {
            tokio::task::yield_now().await;
        }
        let mut slow = TcpStream::connect(server.listener_address(0, 1))
            .await
            .unwrap();
        slow.write_all(&[22]).await.unwrap();
        loop {
            if metrics::value(
                &metrics::scrape(&server).await,
                "l4_active_connections",
                &[],
            ) == 1.0
            {
                break;
            }
            tokio::task::yield_now().await;
        }
        let mut refused = TcpStream::connect(server.listener_address(0, 1))
            .await
            .unwrap();
        assert_eq!(refused.read(&mut [0]).await.unwrap(), 0);
        assert_eq!(
            metrics::value(
                &metrics::scrape(&server).await,
                "l4_admission_rejections_total",
                &[]
            ),
            1.0
        );
        assert_eq!(slow.read(&mut [0]).await.unwrap(), 0);
        let mut next = TcpStream::connect(server.listener_address(0, 1))
            .await
            .unwrap();
        next.write_all(&hello()).await.unwrap();
        let _accepted = origin.accept().await.unwrap();
    })
    .await
    .unwrap();
}
