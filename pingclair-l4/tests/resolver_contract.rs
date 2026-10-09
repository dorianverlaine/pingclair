// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🌐 Controlled wire checks for the async resolver required by the L4 DNS design.
//! These verify the pinned dependency before dynamic configuration is exposed.

use hickory_resolver::TokioResolver;
use hickory_resolver::config::{
    ConnectionConfig, LookupIpStrategy, NameServerConfig, ProtocolConfig, ResolveHosts,
    ResolverConfig,
};
use hickory_resolver::proto::op::ResponseCode;
use hickory_resolver::proto::rr::{Name, RData, Record, RecordType, rdata::CNAME};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

#[tokio::test]
async fn cname_ttl_is_preserved_across_separate_queries() {
    timeout(Duration::from_secs(3), async {
        let dns = Dns::new(|query| {
            let mut reply = response(query);
            let name = query.queries[0].name().clone();
            if name == Name::from_ascii("alias.test.").unwrap() {
                reply.add_answer(Record::from_rdata(
                    name,
                    1,
                    RData::CNAME(CNAME(Name::from_ascii("target.test.").unwrap())),
                ));
            } else {
                address(&mut reply, name, 30, RecordType::A);
            }
            reply
        })
        .await;
        let resolver = dns.resolver(LookupIpStrategy::Ipv4Only);
        let started = Instant::now();
        let lookup = resolver.lookup("alias.test.", RecordType::A).await.unwrap();
        assert_eq!(
            lookup
                .answers()
                .iter()
                .filter(|record| record.record_type() == RecordType::CNAME)
                .count(),
            1
        );
        assert_eq!(
            lookup
                .answers()
                .iter()
                .filter(|record| record.record_type() == RecordType::A)
                .count(),
            1
        );
        assert!(lookup.valid_until() <= started + Duration::from_millis(1100));
        assert!(lookup.valid_until() > started);
        assert_eq!(dns.queries.lock().unwrap().len(), 2);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn zero_ttl_is_not_promoted_and_cache_is_disabled() {
    timeout(Duration::from_secs(3), async {
        let dns = Dns::new(|query| {
            let mut reply = response(query);
            address(
                &mut reply,
                query.queries[0].name().clone(),
                0,
                RecordType::A,
            );
            reply
        })
        .await;
        let resolver = dns.resolver(LookupIpStrategy::Ipv4Only);
        for _ in 0..2 {
            let lookup = resolver.lookup("zero.test.", RecordType::A).await.unwrap();
            assert!(lookup.valid_until() <= Instant::now());
        }
        assert_eq!(dns.queries.lock().unwrap().len(), 2);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn address_family_selection_does_not_issue_the_other_query() {
    timeout(Duration::from_secs(3), async {
        for (strategy, kind) in [
            (LookupIpStrategy::Ipv4Only, RecordType::A),
            (LookupIpStrategy::Ipv6Only, RecordType::AAAA),
        ] {
            let dns = Dns::new(|query| {
                let mut reply = response(query);
                address(
                    &mut reply,
                    query.queries[0].name().clone(),
                    30,
                    query.queries[0].query_type(),
                );
                reply
            })
            .await;
            let resolver = dns.resolver(strategy);
            let lookup = resolver.lookup_ip("family.test.").await.unwrap();
            assert_eq!(lookup.iter().count(), 1);
            assert_eq!(
                *dns.queries.lock().unwrap(),
                [(Name::from_ascii("family.test.").unwrap(), kind)]
            );
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn negative_answers_are_distinct_from_transient_failures() {
    timeout(Duration::from_secs(3), async {
        for code in [
            ResponseCode::NXDomain,
            ResponseCode::NoError,
            ResponseCode::ServFail,
        ] {
            let dns = Dns::new(move |query| {
                let mut reply = response(query);
                reply.metadata.response_code = code;
                reply
            })
            .await;
            let resolver = dns.resolver(LookupIpStrategy::Ipv4Only);
            let error = resolver
                .lookup("negative.test.", RecordType::A)
                .await
                .unwrap_err();
            assert_eq!(error.is_nx_domain(), code == ResponseCode::NXDomain);
            assert_eq!(error.is_no_records_found(), code != ResponseCode::ServFail);
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn truncated_udp_retries_over_tcp_on_the_same_explicit_port() {
    timeout(Duration::from_secs(3), async {
        let (dns, tcp) = truncated_dns().await;
        let server = tokio::spawn(async move {
            let (mut stream, _) = tcp.accept().await.unwrap();
            let query = tcp_query(&mut stream).await;
            let mut reply = response(&query);
            address(
                &mut reply,
                query.queries[0].name().clone(),
                30,
                RecordType::A,
            );
            let wire = reply.to_vec().unwrap();
            stream
                .write_u16(wire.len().try_into().unwrap())
                .await
                .unwrap();
            stream.write_all(&wire).await.unwrap();
        });
        let resolver = dns.resolver(LookupIpStrategy::Ipv4Only);
        assert_eq!(
            resolver
                .lookup("truncated.test.", RecordType::A)
                .await
                .unwrap()
                .answers()
                .len(),
            1
        );
        server.await.unwrap();
        assert_eq!(dns.queries.lock().unwrap().len(), 1);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn cancellation_drops_the_scoped_resolver_and_its_tcp_work() {
    timeout(Duration::from_secs(3), async {
        let (dns, tcp) = truncated_dns().await;
        let baseline = tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks();
        let resolver = dns.resolver(LookupIpStrategy::Ipv4Only);
        let lookup =
            tokio::spawn(async move { resolver.lookup("cancel.test.", RecordType::A).await });
        let (mut stream, _) = tcp.accept().await.unwrap();
        let _query = tcp_query(&mut stream).await;
        lookup.abort();
        assert!(lookup.await.unwrap_err().is_cancelled());
        assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
        while tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks()
            > baseline
        {
            tokio::task::yield_now().await;
        }
        assert_eq!(dns.queries.lock().unwrap().len(), 1);
    })
    .await
    .unwrap();
}

#[path = "support/dns.rs"]
mod fixture;
use fixture::*;

impl Dns {
    fn resolver(&self, strategy: LookupIpStrategy) -> TokioResolver {
        let mut udp = ConnectionConfig::new(ProtocolConfig::Udp);
        udp.port = self.address.port();
        let mut tcp = ConnectionConfig::new(ProtocolConfig::Tcp);
        tcp.port = self.address.port();
        let config = ResolverConfig::from_parts(
            None,
            Vec::new(),
            vec![NameServerConfig::new(
                self.address.ip(),
                true,
                vec![udp, tcp],
            )],
        );
        let mut builder = TokioResolver::builder_with_config(config, Default::default());
        let options = builder.options_mut();
        options.cache_size = 0;
        options.preserve_intermediates = true;
        options.use_hosts_file = ResolveHosts::Never;
        options.ip_strategy = strategy;
        options.attempts = 1;
        options.num_concurrent_reqs = 1;
        options.max_active_requests = 1;
        options.timeout = Duration::from_secs(5);
        builder.build().unwrap()
    }
}
