// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 📊 Real DNS transitions and physical dials use only configuration-bound labels.

use super::super::metrics::{scrape, value};
use super::*;

pub(super) fn observed(config: String) -> String {
    format!("Metrics(enabled: true)\n{config}").replace(
        "Site(host: \"*\") { Fallback",
        "Site(host: \"*\") { Route(when: .path(exact: \"/metrics\")) { ServeMetrics() } Fallback",
    )
}

pub(super) async fn wait_value(
    server: &TestServer,
    name: &str,
    labels: &[&str],
    expected: f64,
) -> String {
    timeout(Duration::from_secs(12), async {
        loop {
            let text = scrape(server).await;
            if value(&text, name, labels) == expected {
                return text;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{name} did not reach {expected}"))
}

#[tokio::test]
async fn pool_availability_expires_without_clients_and_refresh_reasons_are_bounded() {
    timeout(Duration::from_secs(30), async {
        let mode = Arc::new(AtomicU8::new(1));
        let dns = controlled(mode.clone()).await;
        let origin = AsyncListener::bind("127.0.0.1:0").await.unwrap();
        let address = origin.local_addr().unwrap();
        let _origin = Echo::new(origin, b'A');
        let mut server =
            TestServer::new_native(&observed(native(dns.address, address, address, 3)));
        assert!(server.wait_until_ready().await);
        let l4 = server.listener_address(0, 1);
        wait_value(&server, "l4_dns_pool_available", &[], 1.0).await;
        let mut old = wait_tag(l4, b'A').await;
        mode.store(0, Ordering::Release);
        wait_value(
            &server,
            "l4_dns_refreshes_total",
            &["reason=\"transient\""],
            1.0,
        )
        .await;
        assert_eq!(
            value(&scrape(&server).await, "l4_dns_pool_available", &[]),
            1.0
        );
        // ⏱️ No client traffic or successful refresh is needed to expire the availability gauge.
        let expired = wait_value(&server, "l4_dns_pool_available", &[], 0.0).await;
        let attempts = value(&expired, "l4_upstream_connect_attempts_total", &[]);
        for _ in 0..10 {
            assert!(tunnel(l4).await.is_err());
        }
        let text = scrape(&server).await;
        assert_eq!(
            value(&text, "l4_upstream_connect_attempts_total", &[]),
            attempts
        );
        retained(&mut old).await;
        for line in text.lines().filter(|line| line.starts_with("l4_dns_")) {
            let labels = line.split_once('{').unwrap().1.split_once('}').unwrap().0;
            assert!(labels.split(',').all(|label| {
                ["listener=", "route=", "reason="]
                    .iter()
                    .any(|key| label.starts_with(key))
            }));
            assert!(!line.contains("pool.test") && !line.contains("target.test"));
            assert!(!line.contains(&dns.address.to_string()));
            assert!(line.contains("route=\"2\""));
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn fallback_counts_each_tcp_attempt_and_round_robin_rotates_the_next_start() {
    timeout(Duration::from_secs(20), async {
        let dns = dns::Dns::new(|query| {
            let mut reply = dns::response(query);
            let name = query.queries[0].name().clone();
            let data = match query.queries[0].query_type() {
                RecordType::A => RData::A(A(Ipv4Addr::LOCALHOST)),
                RecordType::AAAA => RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)),
                other => panic!("unexpected query family {other}"),
            };
            reply.add_answer(Record::from_rdata(name, 30, data));
            reply
        })
        .await;
        let (refused, origin) = origins().await;
        let address = origin.local_addr().unwrap();
        drop(refused);
        let _origin = Echo::new(origin, b'B');
        let mut server =
            TestServer::new_native(&observed(native(dns.address, address, address, 3)));
        assert!(server.wait_until_ready().await);
        wait_value(&server, "l4_dns_pool_available", &[], 1.0).await;
        let l4 = server.listener_address(0, 1);
        let first = tunnel(l4).await.unwrap();
        assert_eq!(first.1, b'B');
        assert_eq!(
            value(
                &scrape(&server).await,
                "l4_upstream_connect_attempts_total",
                &[]
            ),
            2.0
        );
        let second = tunnel(l4).await.unwrap();
        assert_eq!(second.1, b'B');
        assert_eq!(
            value(
                &scrape(&server).await,
                "l4_upstream_connect_attempts_total",
                &[]
            ),
            3.0
        );
    })
    .await
    .unwrap();
}
