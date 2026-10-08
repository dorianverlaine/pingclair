// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

use super::*;

pub(super) async fn scrape(server: &TestServer) -> String {
    no_proxy_client()
        .get(server.url(0, "/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap()
}

pub(super) fn value(scrape: &str, name: &str, labels: &[&str]) -> f64 {
    scrape
        .lines()
        .filter(|line| {
            line.starts_with(&format!("{name}{{"))
                && labels.iter().all(|label| line.contains(label))
        })
        .map(|line| line.rsplit_once(' ').unwrap().1.parse::<f64>().unwrap())
        .sum()
}

#[tokio::test]
async fn live_bytes_and_active_sessions_are_visible_before_eof() {
    timeout(Duration::from_secs(30), async {
        let origin = AsyncListener::bind("127.0.0.1:0").await.unwrap();
        let routes = format!(
            "@tls tls\nroute @tls {{\n proxy {}\n}}",
            origin.local_addr().unwrap()
        );
        let config = fixture("", &routes)
            .replace("    auto_https off", "    metrics\n    auto_https off")
            .replace("    @ready path", "    metrics /metrics\n    @ready path");
        let mut server = TestServer::new_pingclairfile(&config);
        assert!(server.wait_until_ready().await);
        let wire = hello();
        let expected = wire.clone();
        let backend = tokio::spawn(async move {
            let (mut socket, _) = origin.accept().await.unwrap();
            let mut got = vec![0; expected.len()];
            socket.read_exact(&mut got).await.unwrap();
            assert_eq!(got, expected);
            socket.write_all(b"reply").await.unwrap();
            assert_eq!(socket.read(&mut [0; 1]).await.unwrap(), 0);
        });
        let mut client = TcpStream::connect(server.listener_address(0, 1))
            .await
            .unwrap();
        client.write_all(&wire).await.unwrap();
        client.read_exact(&mut [0; 5]).await.unwrap();
        let live = scrape(&server).await;
        assert_eq!(value(&live, "l4_active_connections", &[]), 1.0);
        assert_eq!(
            value(
                &live,
                "l4_bytes_total",
                &["direction=\"client_to_upstream\""]
            ),
            wire.len() as f64
        );
        assert_eq!(
            value(
                &live,
                "l4_bytes_total",
                &["direction=\"upstream_to_client\""]
            ),
            5.0
        );
        assert_eq!(
            value(&live, "l4_connections_total", &["outcome=\"completed\""]),
            0.0
        );
        assert!(!live.contains("example.test"));
        client.shutdown().await.unwrap();
        client.read_to_end(&mut Vec::new()).await.unwrap();
        backend.await.unwrap();
        loop {
            let ended = scrape(&server).await;
            if value(
                &ended,
                "l4_connections_total",
                &["outcome=\"completed\"", "route=\"1\""],
            ) == 1.0
            {
                assert_eq!(value(&ended, "l4_active_connections", &[]), 0.0);
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}
