// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! ☁️ The Cloudflare DNS-01 provider, against a mock API.
//!
//! Never against the real one. A test that needs a live token and a real zone
//! is a test nobody runs, which would leave this provider exercised only in
//! production — the one place a wrong DELETE is expensive.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::{Arc, Mutex};

use pingclair_tls::acme::{ChallengeHandler, ChallengeResponse, ChallengeType};
use pingclair_tls::dns01::cloudflare::CloudflareProvider;
use pingclair_tls::dns01::{Dns01Handler, DnsProvider, PropagationPolicy};

/// 📨 One request the mock saw, reduced to what a test asserts on.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SeenRequest {
    method: String,
    target: String,
    authorization: String,
    body: String,
}

/// ☁️ A stand-in for the Cloudflare API, speaking just enough HTTP/1.1.
struct MockApi {
    address: SocketAddr,
    seen: Arc<Mutex<Vec<SeenRequest>>>,
}

impl MockApi {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the mock API");
        let address = listener.local_addr().expect("mock address");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&seen);

        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut reader = BufReader::new(stream.try_clone().expect("clone the stream"));

                let mut request_line = String::new();
                if reader.read_line(&mut request_line).is_err() || request_line.is_empty() {
                    continue;
                }
                let mut parts = request_line.split_whitespace();
                let method = parts.next().unwrap_or_default().to_string();
                let target = parts.next().unwrap_or_default().to_string();

                let mut authorization = String::new();
                let mut content_length = 0usize;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).is_err() || line.trim().is_empty() {
                        break;
                    }
                    let lower = line.to_ascii_lowercase();
                    if let Some(value) = lower.strip_prefix("authorization:") {
                        authorization = value.trim().to_string();
                    }
                    if let Some(value) = lower.strip_prefix("content-length:") {
                        content_length = value.trim().parse().unwrap_or(0);
                    }
                }

                let mut body = vec![0u8; content_length];
                if content_length > 0 && reader.read_exact(&mut body).is_err() {
                    continue;
                }
                let body = String::from_utf8_lossy(&body).into_owned();

                recorded.lock().unwrap().push(SeenRequest {
                    method: method.clone(),
                    target: target.clone(),
                    authorization,
                    body,
                });

                let payload = respond_to(&method, &target);
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    payload.len(),
                    payload
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });

        Self { address, seen }
    }

    fn base(&self) -> String {
        format!("http://{}/client/v4", self.address)
    }

    fn seen(&self) -> Vec<SeenRequest> {
        self.seen.lock().unwrap().clone()
    }
}

/// ☁️ The smallest answers that are still shaped like Cloudflare's.
fn respond_to(method: &str, target: &str) -> String {
    if target.starts_with("/client/v4/zones?name=") {
        // 🔎 Only the registrable domain is a zone. The sub-domain lookups the
        // provider tries first must come back empty, or the test would never
        // exercise the suffix walk that finding a zone actually needs.
        if target.contains("name=example.com") {
            return r#"{"success":true,"result":[{"id":"zone-1","name":"example.com"}]}"#.into();
        }
        return r#"{"success":true,"result":[]}"#.into();
    }
    if method == "GET" && target.contains("/dns_records?") {
        // 🧹 One stale challenge record, so the replace path is exercised.
        return r#"{"success":true,"result":[{"id":"stale-record"}]}"#.into();
    }
    if method == "POST" {
        return r#"{"success":true,"result":{"id":"new-record"}}"#.into();
    }
    r#"{"success":true,"result":null}"#.into()
}

/// ☁️ A published record is found in the right zone, replaces what was there,
/// and can be taken away again.
#[tokio::test]
async fn a_txt_record_is_published_into_the_zone_that_holds_it() {
    let api = MockApi::start();
    let provider = CloudflareProvider::with_api_base("cf-test-token".to_string(), api.base())
        .expect("provider");

    let handle = provider
        .upsert_txt("_acme-challenge.wild.example.com", "proof-value", 60)
        .await
        .expect("the record is published");

    provider
        .delete_txt(&handle)
        .await
        .expect("the record is removed");

    let seen = api.seen();
    let targets: Vec<&str> = seen.iter().map(|r| r.target.as_str()).collect();

    // 🔎 The suffix walk: the longest candidate first, stopping at the zone.
    assert!(
        targets.iter().any(|t| t.contains("name=wild.example.com")),
        "the provider never tried the sub-domain as a zone: {targets:?}"
    );
    assert!(
        targets.iter().any(|t| t.contains("name=example.com")),
        "the provider never found the real zone: {targets:?}"
    );

    // 🧹 The stale record is deleted before the new one is written, or the
    // name would carry two challenge values.
    let stale = seen
        .iter()
        .position(|r| r.method == "DELETE" && r.target.contains("stale-record"));
    let created = seen.iter().position(|r| r.method == "POST");
    assert!(
        stale.is_some(),
        "the existing record was left in place: {seen:#?}"
    );
    assert!(
        stale < created,
        "the new record was written before the stale one was removed: {seen:#?}"
    );

    // ✍️ The record itself.
    let post = seen.iter().find(|r| r.method == "POST").expect("a create");
    assert!(
        post.target.contains("/zones/zone-1/dns_records"),
        "{post:?}"
    );
    assert!(post.body.contains("\"type\":\"TXT\""), "{post:?}");
    assert!(post.body.contains("proof-value"), "{post:?}");
    assert!(post.body.contains("\"ttl\":60"), "{post:?}");

    // 🧹 Cleanup addresses the record it created, not the stale one again.
    assert!(
        seen.iter()
            .any(|r| r.method == "DELETE" && r.target.contains("new-record")),
        "the published record was never removed: {seen:#?}"
    );

    // 🔐 Every call carries the token as a bearer credential.
    assert!(
        seen.iter()
            .all(|r| r.authorization == "bearer cf-test-token"),
        "a request went out unauthenticated: {seen:#?}"
    );
}

/// 🔎 The zone lookup is cached, so a second record in the same zone does not
/// re-walk the suffixes. Issuance does this once per name in an order.
#[tokio::test]
async fn the_zone_lookup_happens_once_per_zone() {
    let api = MockApi::start();
    let provider = CloudflareProvider::with_api_base("cf-test-token".to_string(), api.base())
        .expect("provider");

    provider
        .upsert_txt("_acme-challenge.a.example.com", "one", 60)
        .await
        .expect("first record");
    provider
        .upsert_txt("_acme-challenge.b.example.com", "two", 60)
        .await
        .expect("second record");

    // 🧭 The second name still probes its own longer suffixes, but must not
    // ask about `example.com` again.
    let repeated = api
        .seen()
        .iter()
        .filter(|r| r.target.contains("name=example.com"))
        .count();
    assert_eq!(repeated, 1, "the zone was looked up more than once");
}

/// 📡 The handler end to end: deploy writes the record, cleanup removes it.
#[tokio::test]
async fn the_handler_publishes_and_then_removes_the_challenge() {
    let api = MockApi::start();
    let provider = Arc::new(
        CloudflareProvider::with_api_base("cf-test-token".to_string(), api.base())
            .expect("provider"),
    );
    // 🕰️ No resolvers and no delay: propagation is a separate concern with its
    // own test, and waiting here would only make this slow.
    let handler = Dns01Handler::new(provider, PropagationPolicy::default());

    let challenge = ChallengeResponse {
        domain: "*.example.com".to_string(),
        challenge_type: ChallengeType::Dns01,
        token: "token".to_string(),
        key_authorization: "digest-value".to_string(),
    };

    handler.deploy(&challenge).await.expect("deploy");
    handler.cleanup(&challenge).await.expect("cleanup");

    let seen = api.seen();
    let post = seen.iter().find(|r| r.method == "POST").expect("a create");
    // 🏷️ A wildcard proves control of its parent, so the record has no `*`.
    assert!(
        post.body.contains("_acme-challenge.example.com"),
        "the wildcard leaked into the record name: {post:?}"
    );
    assert!(post.body.contains("digest-value"), "{post:?}");
    assert!(
        seen.iter()
            .any(|r| r.method == "DELETE" && r.target.contains("new-record")),
        "the challenge record outlived the order: {seen:#?}"
    );
}

/// 🚫 A handler given the wrong kind of challenge must say so rather than
/// publish a record no CA will read.
#[tokio::test]
async fn a_non_dns_challenge_is_refused() {
    let api = MockApi::start();
    let provider = Arc::new(
        CloudflareProvider::with_api_base("cf-test-token".to_string(), api.base())
            .expect("provider"),
    );
    let handler = Dns01Handler::new(provider, PropagationPolicy::default());

    let result = handler
        .deploy(&ChallengeResponse {
            domain: "example.com".to_string(),
            challenge_type: ChallengeType::Http01,
            token: "token".to_string(),
            key_authorization: "value".to_string(),
        })
        .await;

    assert!(
        result.is_err(),
        "an HTTP-01 challenge was answered with DNS"
    );
    assert!(
        api.seen().is_empty(),
        "the provider was called for a challenge it cannot answer"
    );
}

/// 🚫 DNS-01 has no token to serve over HTTP. Answering one would mean the
/// `/.well-known/acme-challenge/` route could satisfy a DNS proof.
#[tokio::test]
async fn the_handler_serves_no_http_token() {
    let api = MockApi::start();
    let provider = Arc::new(
        CloudflareProvider::with_api_base("token".to_string(), api.base()).expect("provider"),
    );
    let handler = Dns01Handler::new(provider, PropagationPolicy::default());
    assert!(handler.get_token("anything").is_none());
}
