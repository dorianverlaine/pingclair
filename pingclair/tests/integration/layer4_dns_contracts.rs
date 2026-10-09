// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🌐 Real-binary boundaries for TTL zero, whole-answer rejection and DNS job cleanup.

use super::super::metrics::{scrape, value};
use super::metrics::{observed, wait_value};
use super::*;
use tokio::time::Instant;

async fn wait_reason(server: &TestServer, reason: &str, previous: f64) {
    timeout(Duration::from_secs(12), async {
        loop {
            if value(&scrape(server).await, "l4_dns_refreshes_total", &[reason]) > previous {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("DNS refresh reason was not observed");
}

#[tokio::test]
async fn zero_ttl_has_no_implicit_freshness_but_explicit_valid_can_override_it() {
    timeout(Duration::from_secs(25), async {
        let dns = dns::Dns::new(|query| {
            let mut reply = dns::response(query);
            reply.add_answer(Record::from_rdata(
                query.queries[0].name().clone(),
                0,
                RData::A(A(Ipv4Addr::LOCALHOST)),
            ));
            reply
        })
        .await;
        let origin = AsyncListener::bind("127.0.0.1:0").await.unwrap();
        let address = origin.local_addr().unwrap();
        let _origin = Echo::new(origin, b'A');
        let config = observed(native(dns.address, address, address, 0))
            .replace("versions: .ip,", "versions: .ipv4,")
            .replace(", valid: .seconds(1)", "");
        let mut server = TestServer::new_native(&config);
        assert!(server.wait_until_ready().await);
        let l4 = server.listener_address(0, 1);
        wait_reason(&server, "reason=\"available\"", 0.0).await;
        let started = Instant::now();
        for _ in 0..100 {
            assert!(tunnel(l4).await.is_err());
        }
        assert_eq!(
            value(&scrape(&server).await, "l4_dns_pool_available", &[]),
            0.0
        );
        assert!(dns.queries.lock().unwrap().len() <= started.elapsed().as_secs() as usize + 3);
        let resolved =
            std::fs::read_to_string(server._temp_dir.path().join("config.pingclair")).unwrap();
        let override_ttl =
            resolved.replace("versions: .ipv4,", "versions: .ipv4, valid: .seconds(2),");
        let applied = no_proxy_client()
            .post(server.admin_url("/load"))
            .header("Content-Type", "text/pingclair")
            .body(override_ttl)
            .send()
            .await
            .unwrap();
        assert!(
            applied.status().is_success(),
            "{}",
            applied.text().await.unwrap()
        );
        drop(wait_tag(l4, b'A').await);
        assert!(
            dns.queries
                .lock()
                .unwrap()
                .iter()
                .all(|(name, kind)| name.to_ascii() == "pool.test." && *kind == RecordType::A)
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn excessive_cnames_addresses_and_empty_answers_revoke_the_whole_live_pool() {
    timeout(Duration::from_secs(45), async {
        let mode = Arc::new(AtomicU8::new(0));
        let control = mode.clone();
        let dns = dns::Dns::new(move |query| {
            let mut reply = dns::response(query);
            let mut name = query.queries[0].name().clone();
            match control.load(Ordering::Acquire) {
                0 => {
                    reply.add_answer(Record::from_rdata(
                        name,
                        30,
                        RData::A(A(Ipv4Addr::LOCALHOST)),
                    ));
                }
                1 => {
                    for hop in 0..9 {
                        let target = Name::from_ascii(format!("c{hop}.test.")).unwrap();
                        reply.add_answer(Record::from_rdata(
                            name,
                            30,
                            RData::CNAME(CNAME(target.clone())),
                        ));
                        name = target;
                    }
                    reply.add_answer(Record::from_rdata(
                        name,
                        30,
                        RData::A(A(Ipv4Addr::LOCALHOST)),
                    ));
                }
                2 => {
                    for last in 1..=65 {
                        reply.add_answer(Record::from_rdata(
                            name.clone(),
                            30,
                            RData::A(A(Ipv4Addr::new(127, 0, 0, last))),
                        ));
                    }
                }
                3 => {}
                other => panic!("unexpected DNS mode {other}"),
            }
            reply
        })
        .await;
        let origin = AsyncListener::bind("127.0.0.1:0").await.unwrap();
        let address = origin.local_addr().unwrap();
        let _origin = Echo::new(origin, b'A');
        let config = observed(native(dns.address, address, address, 60))
            .replace("versions: .ip,", "versions: .ipv4,")
            .replace("\"127.0.0.1/32\", \"::1/128\"", "\"127.0.0.0/8\"");
        let mut server = TestServer::new_native(&config);
        assert!(server.wait_until_ready().await);
        let l4 = server.listener_address(0, 1);
        let mut old = wait_tag(l4, b'A').await;
        for (bad, reason) in [
            (1, "reason=\"invalid\""),
            (2, "reason=\"invalid\""),
            (3, "reason=\"empty\""),
        ] {
            let previous = value(&scrape(&server).await, "l4_dns_refreshes_total", &[reason]);
            mode.store(bad, Ordering::Release);
            wait_unavailable(l4).await;
            wait_reason(&server, reason, previous).await;
            retained(&mut old).await;
            mode.store(0, Ordering::Release);
            drop(wait_tag(l4, b'A').await);
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn dns_timeout_and_shutdown_release_tcp_workers_while_existing_tunnels_survive() {
    timeout(Duration::from_secs(40), async {
        let mode = Arc::new(AtomicU8::new(0));
        let control = mode.clone();
        let dns = dns::Dns::new(move |query| {
            let mut reply = dns::response(query);
            if control.load(Ordering::Acquire) == 1 {
                reply.metadata.truncation = true;
            } else {
                reply.add_answer(Record::from_rdata(
                    query.queries[0].name().clone(),
                    30,
                    RData::A(A(Ipv4Addr::LOCALHOST)),
                ));
            }
            reply
        })
        .await;
        let tcp = AsyncListener::bind(dns.address).await.unwrap();
        enum Event {
            Accepted(Instant),
            Closed(Instant),
        }
        let (sender, mut events) = tokio::sync::mpsc::channel(4);
        let peer = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut socket, _) = tcp.accept().await.unwrap();
                dns::tcp_query(&mut socket).await;
                sender.send(Event::Accepted(Instant::now())).await.unwrap();
                assert_eq!(
                    timeout(Duration::from_secs(8), socket.read(&mut [0]))
                        .await
                        .unwrap()
                        .unwrap(),
                    0
                );
                sender.send(Event::Closed(Instant::now())).await.unwrap();
            }
        });
        let origin = AsyncListener::bind("127.0.0.1:0").await.unwrap();
        let address = origin.local_addr().unwrap();
        let _origin = Echo::new(origin, b'A');
        let config = observed(native(dns.address, address, address, 1))
            .replace("versions: .ip,", "versions: .ipv4,");
        let mut server = TestServer::new_native(&config);
        assert!(server.wait_until_ready().await);
        let l4 = server.listener_address(0, 1);
        let mut old = wait_tag(l4, b'A').await;
        mode.store(1, Ordering::Release);
        let Some(Event::Accepted(started)) = timeout(Duration::from_secs(5), events.recv())
            .await
            .unwrap()
        else {
            panic!("expected a pending DNS TCP query")
        };
        wait_value(&server, "l4_dns_pool_available", &[], 0.0).await;
        assert!(tunnel(l4).await.is_err());
        retained(&mut old).await;
        let Some(Event::Closed(closed)) = timeout(Duration::from_secs(8), events.recv())
            .await
            .unwrap()
        else {
            panic!("DNS TCP worker did not close after timeout")
        };
        assert!(
            (Duration::from_secs(4)..=Duration::from_secs(7))
                .contains(&closed.duration_since(started))
        );
        wait_reason(&server, "reason=\"timeout\"", 0.0).await;
        mode.store(0, Ordering::Release);
        drop(wait_tag(l4, b'A').await);
        mode.store(1, Ordering::Release);
        assert!(matches!(
            timeout(Duration::from_secs(5), events.recv())
                .await
                .unwrap(),
            Some(Event::Accepted(_))
        ));
        assert!(
            no_proxy_client()
                .post(server.admin_url("/stop"))
                .send()
                .await
                .unwrap()
                .status()
                .is_success()
        );
        assert!(matches!(
            timeout(Duration::from_secs(3), events.recv())
                .await
                .unwrap(),
            Some(Event::Closed(_))
        ));
        retained(&mut old).await;
        drop(old);
        peer.await.unwrap();
    })
    .await
    .unwrap();
}
