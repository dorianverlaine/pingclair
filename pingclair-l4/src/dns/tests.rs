// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

use super::*;
use hickory_resolver::proto::op::ResponseCode;
use hickory_resolver::proto::rr::{
    Name, RData, Record, RecordType,
    rdata::{A, CNAME},
};
use pingclair_core::config::Layer4IpVersions;
use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;
use tokio::time::timeout;

#[path = "../../tests/support/dns.rs"]
mod fixture;
use fixture::{Dns, address, response, tcp_query, truncated_dns};

fn config(dns: SocketAddr) -> Layer4Dns {
    Layer4Dns {
        name: "pool.test".into(),
        port: 443,
        resolvers: Some(vec![dns.to_string()]),
        versions: Layer4IpVersions::Ipv4,
        valid_ms: None,
        stale_ms: 60_000,
        allow_ip: Some(vec!["203.0.113.0/24".into(), "::1/128".into()]),
    }
}

async fn lookup(resolver: &Resolver) -> Result<Answer, Failure> {
    let (_cancel, receiver) = watch::channel(false);
    resolver.lookup(receiver).await
}

fn source(config: &Layer4Dns) -> Source {
    DnsRuntime::default()
        .prepare(vec![])
        .source(config)
        .unwrap()
}

#[tokio::test]
async fn raw_queries_enforce_selected_families_fqdn_and_zero_ttl() {
    for (versions, families) in [
        (Layer4IpVersions::Ipv4, vec![RecordType::A]),
        (Layer4IpVersions::Ipv6, vec![RecordType::AAAA]),
        (Layer4IpVersions::Ip, vec![RecordType::A, RecordType::AAAA]),
    ] {
        let dns = Dns::new(|query| {
            let mut reply = response(query);
            address(
                &mut reply,
                query.queries[0].name().clone(),
                0,
                query.queries[0].query_type(),
            );
            reply
        })
        .await;
        let mut config = config(dns.address);
        config.versions = versions;
        let resolver = Resolver::prepare(&config).unwrap();
        for _ in 0..2 {
            let answer = lookup(&resolver).await.unwrap();
            assert!(answer.fresh <= Instant::now());
            assert_eq!(answer.addresses.len(), families.len());
        }
        assert_eq!(
            *dns.queries.lock().unwrap(),
            families
                .iter()
                .cycle()
                .take(2 * families.len())
                .map(|kind| (Name::from_ascii("pool.test.").unwrap(), *kind))
                .collect::<Vec<_>>()
        );
    }
}

#[tokio::test]
async fn cname_hops_are_bounded_for_inline_and_separate_answers_and_ttl_is_preserved() {
    for inline in [true, false] {
        for hops in [8, 9] {
            let dns = Dns::new(move |query| {
                let mut reply = response(query);
                let mut name = query.queries[0].name().clone();
                let mut index = name
                    .to_ascii()
                    .strip_prefix("hop-")
                    .and_then(|s| s.strip_suffix(".test."))
                    .and_then(|s| s.parse::<u8>().ok())
                    .unwrap_or(0);
                while index < hops {
                    let target = Name::from_ascii(format!("hop-{}.test.", index + 1)).unwrap();
                    reply.add_answer(Record::from_rdata(
                        name,
                        1,
                        RData::CNAME(CNAME(target.clone())),
                    ));
                    name = target;
                    index += 1;
                    if !inline {
                        break;
                    }
                }
                if index == hops && (inline || query.queries[0].name() == &name) {
                    address(&mut reply, name, 30, RecordType::A);
                }
                reply
            })
            .await;
            let resolver = Resolver::prepare(&config(dns.address)).unwrap();
            let start = Instant::now();
            let answer = lookup(&resolver).await;
            if hops == 8 {
                let answer = answer.unwrap();
                assert_eq!(answer.addresses.len(), 1);
                assert!(answer.fresh <= start + Duration::from_millis(1100));
            } else {
                assert_eq!(answer.err(), Some(Failure::Invalid));
            }
            assert!(dns.queries.lock().unwrap().len() <= 9);
        }
    }
}

#[tokio::test]
async fn cyclic_aliases_oversized_pools_and_negative_answers_have_distinct_results() {
    for (code, expected) in [
        (ResponseCode::NXDomain, Failure::NxDomain),
        (ResponseCode::NoError, Failure::Empty),
        (ResponseCode::ServFail, Failure::Transient),
    ] {
        let dns = Dns::new(move |query| {
            let mut reply = response(query);
            reply.metadata.response_code = code;
            reply
        })
        .await;
        assert_eq!(
            lookup(&Resolver::prepare(&config(dns.address)).unwrap())
                .await
                .err(),
            Some(expected)
        );
    }
    for cyclic in [true, false] {
        let dns = Dns::new(move |query| {
            let mut reply = response(query);
            let name = query.queries[0].name().clone();
            if cyclic {
                reply.add_answer(Record::from_rdata(
                    name.clone(),
                    30,
                    RData::CNAME(CNAME(name)),
                ));
            } else {
                for suffix in 1..=65 {
                    reply.add_answer(Record::from_rdata(
                        name.clone(),
                        30,
                        RData::A(A(Ipv4Addr::new(203, 0, 113, suffix))),
                    ));
                }
            }
            reply
        })
        .await;
        assert_eq!(
            lookup(&Resolver::prepare(&config(dns.address)).unwrap())
                .await
                .err(),
            Some(Failure::Invalid)
        );
    }
}

async fn raw_transport(cancel: bool) {
    timeout(Duration::from_secs(3), async {
        let (dns, tcp) = truncated_dns().await;
        let baseline = tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks();
        let resolver = Resolver::prepare(&config(dns.address)).unwrap();
        let (cancelled, receiver) = watch::channel(false);
        let query = tokio::spawn(async move { resolver.lookup(receiver).await });
        let (mut stream, _) = tcp.accept().await.unwrap();
        let request = tcp_query(&mut stream).await;
        if cancel {
            cancelled.send(true).unwrap();
        } else {
            let mut reply = response(&request);
            address(
                &mut reply,
                request.queries[0].name().clone(),
                30,
                RecordType::A,
            );
            let wire = reply.to_vec().unwrap();
            stream
                .write_u16(wire.len().try_into().unwrap())
                .await
                .unwrap();
            stream.write_all(&wire).await.unwrap();
        }
        let answer = query.await.unwrap();
        if cancel {
            assert_eq!(answer.err(), Some(Failure::Cancelled));
        } else {
            assert_eq!(answer.unwrap().addresses.len(), 1);
        }
        assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
        assert_eq!(
            tokio::runtime::Handle::current()
                .metrics()
                .num_alive_tasks(),
            baseline
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn raw_tcp_fallback_joins_every_transport_task() {
    raw_transport(false).await;
}

#[tokio::test]
async fn raw_cancellation_joins_every_transport_task() {
    raw_transport(true).await;
}

#[tokio::test]
async fn aborting_the_outer_query_still_closes_scoped_transport_work() {
    timeout(Duration::from_secs(3), async {
        let (dns, tcp) = truncated_dns().await;
        let baseline = tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks();
        let resolver = Resolver::prepare(&config(dns.address)).unwrap();
        let (_cancel, receiver) = watch::channel(false);
        let query = tokio::spawn(async move { resolver.lookup(receiver).await });
        let (mut stream, _) = tcp.accept().await.unwrap();
        tcp_query(&mut stream).await;
        query.abort();
        assert!(matches!(query.await, Err(error) if error.is_cancelled()));
        assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
        while tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks()
            > baseline
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

fn publish(source: &Source, ttl: Duration) {
    source
        .0
        .apply(Ok(Answer {
            addresses: vec!["203.0.113.10:443".parse().unwrap()],
            fresh: Instant::now() + ttl,
        }))
        .unwrap();
}

#[tokio::test(start_paused = true)]
async fn hard_deadlines_are_checked_at_dial_without_scheduler_help_or_failure_extension() {
    let mut config = config("127.0.0.1:53".parse().unwrap());
    config.stale_ms = 2000;
    let source = source(&config);
    publish(&source, Duration::ZERO);
    let hard = source.0.snapshot.load().as_ref().unwrap().hard;
    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(
        source.0.apply(Err(Failure::Transient)),
        Err(Failure::Transient)
    );
    assert_eq!(source.0.snapshot.load().as_ref().unwrap().hard, hard);
    source
        .connect_with(Duration::from_secs(5), |_| std::future::ready(Ok(())))
        .await
        .unwrap();
    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(
        source
            .connect_with(Duration::from_secs(5), |_| std::future::ready(Ok(())))
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::AddrNotAvailable
    );
    config.valid_ms = Some(1000);
    config.stale_ms = 0;
    let source = super::tests::source(&config);
    publish(&source, Duration::from_secs(50));
    let snapshot = source.0.snapshot.load_full().unwrap();
    assert_eq!(snapshot.hard - snapshot.success, Duration::from_secs(1));
}

#[tokio::test]
async fn forbidden_mixed_answers_and_authoritative_negatives_revoke_the_whole_pool() {
    let source = source(&config("127.0.0.1:53".parse().unwrap()));
    for failure in [Failure::Empty, Failure::NxDomain, Failure::Invalid] {
        publish(&source, Duration::from_secs(30));
        let epoch = source.0.epoch.load(Ordering::Acquire);
        assert_eq!(source.0.apply(Err(failure)), Err(failure));
        assert!(source.0.snapshot.load().is_none());
        assert_ne!(source.0.epoch.load(Ordering::Acquire), epoch);
    }
    publish(&source, Duration::from_secs(30));
    assert_eq!(
        source.0.apply(Ok(Answer {
            addresses: vec![
                "203.0.113.10:443".parse().unwrap(),
                "127.0.0.1:443".parse().unwrap()
            ],
            fresh: Instant::now() + Duration::from_secs(30)
        })),
        Err(Failure::Invalid)
    );
    assert!(source.0.snapshot.load().is_none());
}

#[tokio::test]
async fn retries_use_one_snapshot_but_recheck_revocation_before_every_attempt() {
    let source = source(&config("127.0.0.1:53".parse().unwrap()));
    source
        .0
        .apply(Ok(Answer {
            addresses: vec![
                "203.0.113.10:443".parse().unwrap(),
                "203.0.113.11:443".parse().unwrap(),
            ],
            fresh: Instant::now() + Duration::from_secs(30),
        }))
        .unwrap();
    let attempts = AtomicUsize::new(0);
    let error = source
        .connect_with(Duration::from_secs(5), |_| {
            attempts.fetch_add(1, Ordering::Relaxed);
            source.0.revoke();
            std::future::ready(Err::<(), _>(io::ErrorKind::ConnectionRefused.into()))
        })
        .await
        .unwrap_err();
    assert_eq!(
        (error.kind(), attempts.load(Ordering::Relaxed)),
        (io::ErrorKind::AddrNotAvailable, 1)
    );
}

#[tokio::test]
async fn preparing_a_reload_cannot_mutate_pools_and_only_full_policies_reuse_snapshots() {
    let runtime = DnsRuntime::default();
    let config = config("127.0.0.1:53".parse().unwrap());
    let mut draft = runtime.prepare(vec![]);
    let first = draft.source(&config).unwrap();
    assert!(Arc::ptr_eq(&first.0, &draft.source(&config).unwrap().0));
    publish(&first, Duration::from_secs(30));
    runtime.publish(draft);
    let mut failed_reload = runtime.prepare(vec![]);
    let same = failed_reload.source(&config).unwrap();
    assert!(Arc::ptr_eq(&first.0, &same.0));
    let mut changed = config.clone();
    changed.stale_ms = 0;
    let new = failed_reload.source(&changed).unwrap();
    assert!(!Arc::ptr_eq(&first.0, &new.0));
    assert!(new.0.snapshot.load().is_none());
    drop(failed_reload);
    assert!(first.0.snapshot.load().is_some());
    let mut changed_own = runtime.prepare(vec!["127.0.0.1:443".parse().unwrap()]);
    assert!(!Arc::ptr_eq(
        &first.0,
        &changed_own.source(&config).unwrap().0
    ));
    runtime.publish(runtime.prepare(vec![]));
    assert!(first.0.snapshot.load().is_none());
}

#[tokio::test]
async fn removed_pools_cancel_immediately_and_retired_transports_hold_the_global_budget() {
    timeout(Duration::from_secs(5), async {
        let (dns, tcp) = truncated_dns().await;
        let runtime = Arc::new(DnsRuntime::default());
        let mut draft = runtime.prepare(vec![]);
        let mut all = Vec::new();
        for index in 0..20 {
            let mut config = config(dns.address);
            config.name = format!("old-{index}.test");
            all.push(draft.source(&config).unwrap());
        }
        runtime.publish(draft);
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let running = runtime.clone();
        let coordinator = tokio::spawn(async move {
            running
                .run(async {
                    let _ = stopped.await;
                })
                .await
        });
        let mut peers = Vec::new();
        for _ in 0..8 {
            let (mut stream, _) = tcp.accept().await.unwrap();
            tcp_query(&mut stream).await;
            peers.push(stream);
        }
        assert_eq!(dns.queries.lock().unwrap().len(), 8);
        let mut draft = runtime.prepare(vec![]);
        let mut config = config(dns.address);
        config.name = "replacement.test".into();
        let replacement = draft.source(&config).unwrap();
        runtime.publish(draft);
        assert!(
            all.iter()
                .filter_map(|source| source.0.cancel.lock().unwrap().clone())
                .all(|cancel| *cancel.borrow())
        );
        all.push(replacement);
        loop {
            let live = all
                .iter()
                .filter(|source| source.0.cancel.lock().unwrap().is_some())
                .count();
            assert!(live <= 8, "{live} DNS jobs including retired workers");
            if live == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        for mut peer in peers {
            assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
        }
        let (mut replacement, _) = tcp.accept().await.unwrap();
        tcp_query(&mut replacement).await;
        stop.send(()).unwrap();
        coordinator.await.unwrap();
        assert_eq!(replacement.read(&mut [0]).await.unwrap(), 0);
        assert!(all.last().unwrap().0.snapshot.load().is_none());
        assert_eq!(dns.queries.lock().unwrap().len(), 9);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn established_relay_drops_the_route_generation_and_dynamic_pool() {
    use pingclair_core::config::{Layer4Dynamic, Layer4Route, Layer4Server};
    timeout(Duration::from_secs(3), async {
        let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = origin.local_addr().unwrap();
        let mut config = config("127.0.0.1:53".parse().unwrap());
        config.port = address.port();
        config.allow_ip = Some(vec!["127.0.0.1/32".into()]);
        let runtime = DnsRuntime::default();
        let mut draft = runtime.prepare(vec![]);
        let source = draft.source(&config).unwrap();
        source
            .0
            .apply(Ok(Answer {
                addresses: vec![address],
                fresh: Instant::now() + Duration::from_secs(30),
            }))
            .unwrap();
        let weak_pool = Arc::downgrade(&source.0);
        drop(source);
        let mut listener = Layer4Server::new("127.0.0.1:9443".into());
        listener.proxy_half_close = true;
        listener.routes.push(Layer4Route {
            matches: vec![],
            upstream: String::new(),
            dynamic: Some(Layer4Dynamic::A(config)),
        });
        let prepared = Arc::new(
            crate::PreparedListener::prepare_with_dns(&listener, &[], None, &mut draft).unwrap(),
        );
        let weak_listener = Arc::downgrade(&prepared);
        runtime.publish(draft);
        let (mut client, stream) = tokio::io::duplex(32);
        let session = tokio::spawn(prepared.serve(stream, "127.0.0.1:1234".parse().unwrap()));
        let (mut backend, _) = origin.accept().await.unwrap();
        backend.write_all(b"ready").await.unwrap();
        let mut bytes = [0; 5];
        client.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"ready");
        assert!(weak_listener.upgrade().is_none());
        runtime.publish(runtime.prepare(vec![]));
        assert!(weak_pool.upgrade().is_none());
        client.write_all(b"still connected").await.unwrap();
        client.shutdown().await.unwrap();
        let mut received = Vec::new();
        backend.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"still connected");
        backend.shutdown().await.unwrap();
        session.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}
