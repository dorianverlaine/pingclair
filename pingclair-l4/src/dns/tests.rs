// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

use super::resolver::{Answer, Failure, Resolver};
use hickory_resolver::proto::op::ResponseCode;
use hickory_resolver::proto::rr::{
    Name, RData, Record, RecordType,
    rdata::{A, CNAME},
};
use pingclair_core::config::{Layer4Dns, Layer4IpVersions};
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;
use tokio::time::{Instant, timeout};

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
