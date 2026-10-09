// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🌐 Controlled DNS drives real-binary native and Caddy TCP routes.

use super::*;
use hickory_resolver::proto::op::ResponseCode;
use hickory_resolver::proto::rr::{
    Name, RData, Record, RecordType,
    rdata::{A, AAAA, CNAME},
};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU8, Ordering};
use tokio::task::{JoinHandle, JoinSet};

#[path = "../../../pingclair-l4/tests/support/dns.rs"]
mod dns;

struct Echo(JoinHandle<()>);

impl Echo {
    fn new(listener: AsyncListener, tag: u8) -> Self {
        Self(tokio::spawn(async move {
            let mut sessions = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((mut stream, _)) = accepted else { break; };
                        sessions.spawn(async move {
                            if stream.read_exact(&mut [0]).await.is_err() { return; }
                            if stream.write_all(&[tag]).await.is_err() { return; }
                            let (mut read, mut write) = stream.split();
                            let _ = tokio::io::copy(&mut read, &mut write).await;
                        });
                    }
                    _ = sessions.join_next(), if !sessions.is_empty() => {}
                }
            }
        }))
    }
}

impl Drop for Echo {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn origins() -> (AsyncListener, AsyncListener) {
    for _ in 0..8 {
        let first = AsyncListener::bind("127.0.0.1:0").await.unwrap();
        if let Ok(second) =
            AsyncListener::bind((Ipv6Addr::LOCALHOST, first.local_addr().unwrap().port())).await
        {
            return (first, second);
        }
    }
    panic!("could not reserve dual-family origin port");
}

async fn controlled(mode: Arc<AtomicU8>) -> dns::Dns {
    dns::Dns::new(move |query| {
        let mut reply = dns::response(query);
        let mode = mode.load(Ordering::Acquire);
        if mode == 0 {
            reply.metadata.response_code = ResponseCode::ServFail;
            return reply;
        }
        if mode == 3 {
            reply.metadata.response_code = ResponseCode::NXDomain;
            return reply;
        }
        let name = query.queries[0].name().clone();
        let target = Name::from_ascii("target.test.").unwrap();
        if name != target {
            reply.add_answer(Record::from_rdata(name, 30, RData::CNAME(CNAME(target))));
            return reply;
        }
        match query.queries[0].query_type() {
            RecordType::A if mode == 1 || mode == 4 => {
                reply.add_answer(Record::from_rdata(
                    name.clone(),
                    30,
                    RData::A(A(Ipv4Addr::LOCALHOST)),
                ));
                if mode == 4 {
                    dns::address(&mut reply, name, 30, RecordType::A);
                }
            }
            RecordType::AAAA if mode == 2 => {
                reply.add_answer(Record::from_rdata(
                    name,
                    30,
                    RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)),
                ));
            }
            _ => {}
        }
        reply
    })
    .await
}

fn native(resolver: SocketAddr, origin: SocketAddr, local: SocketAddr, stale: u64) -> String {
    format!(
        r#"
Admin(listen: "__PINGCLAIR_TEST_ADMIN_LISTEN__")
Shutdown(grace: .seconds(5))
TCPListener(on: ":__PINGCLAIR_TEST_HTTP_PORT__") {{
    Route(when: .tls(sni: ["example.test"])) {{ Proxy(to: "{local}") }}
    Fallback {{ Proxy(dynamic: .a("pool.test", port: {}, resolvers: ["{resolver}"], versions: .ip, valid: .seconds(1), stale: .seconds({stale}), allowIP: ["127.0.0.1/32", "::1/128"])) }}
}}
.timeouts(preread: .seconds(1), connect: .seconds(1), idle: .seconds(30))
.halfClose(enabled: true)
HTTPListener(on: "__PINGCLAIR_TEST_LISTEN__") {{
    Site(host: "*") {{ Fallback {{ Respond(body: "__PINGCLAIR_TEST_READINESS_TOKEN__") }} }}
}}
"#,
        origin.port()
    )
}

async fn tunnel(address: SocketAddr) -> io::Result<(TcpStream, u8)> {
    let mut stream = TcpStream::connect(address).await?;
    stream.write_all(b"p").await?;
    let mut tag = [0];
    stream.read_exact(&mut tag).await?;
    Ok((stream, tag[0]))
}

async fn wait_tag(address: SocketAddr, expected: u8) -> TcpStream {
    timeout(Duration::from_secs(15), async {
        loop {
            if let Ok((stream, tag)) = tunnel(address).await
                && tag == expected
            {
                return stream;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("DNS pool did not recover to the expected origin")
}

async fn wait_unavailable(address: SocketAddr) {
    timeout(Duration::from_secs(5), async {
        loop {
            if tunnel(address).await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("DNS pool continued admitting new connections")
}

async fn retained(stream: &mut TcpStream) {
    stream.write_all(b"z").await.unwrap();
    let mut byte = [0];
    stream.read_exact(&mut byte).await.unwrap();
    assert_eq!(byte, [b'z']);
}

#[tokio::test]
async fn native_dns_updates_reload_and_failures_preserve_existing_streams() {
    timeout(Duration::from_secs(60), async {
        let mode = Arc::new(AtomicU8::new(0));
        let dns = controlled(mode.clone()).await;
        let (first, second) = origins().await;
        let origin = first.local_addr().unwrap();
        let local = AsyncListener::bind("127.0.0.1:0").await.unwrap();
        let config = native(dns.address, origin, local.local_addr().unwrap(), 60);
        let (_first, _second, _local) = (
            Echo::new(first, b'A'),
            Echo::new(second, b'B'),
            Echo::new(local, b'L'),
        );
        let mut server = TestServer::new_native(&config);
        assert!(server.wait_until_ready().await);
        let address = server.listener_address(0, 1);
        let mut secure = TcpStream::connect(address).await.unwrap();
        secure.write_all(&hello()).await.unwrap();
        let mut local = [0];
        secure.read_exact(&mut local).await.unwrap();
        assert_eq!(local, [b'L']);
        drop(secure);
        let started = std::time::Instant::now();
        let queries = dns.queries.lock().unwrap().len();
        for _ in 0..100 {
            assert!(
                timeout(Duration::from_secs(1), tunnel(address))
                    .await
                    .unwrap()
                    .is_err()
            );
        }
        assert!(
            dns.queries.lock().unwrap().len() - queries
                <= 4 * (started.elapsed().as_secs() as usize + 2)
        );
        mode.store(1, Ordering::Release);
        let mut old = wait_tag(address, b'A').await;
        mode.store(2, Ordering::Release);
        let mut second = wait_tag(address, b'B').await;
        retained(&mut old).await;

        let client = no_proxy_client();
        let mut document = client
            .get(server.admin_url("/config/"))
            .send()
            .await
            .unwrap()
            .json::<serde_json::Value>()
            .await
            .unwrap();
        let mut invalid = document.clone();
        invalid["layer4"][0]["routes"][1]["dynamic"]["allow_ip"] = serde_json::json!(["0.0.0.0/0"]);
        assert!(
            !client
                .post(server.admin_url("/load"))
                .json(&invalid)
                .send()
                .await
                .unwrap()
                .status()
                .is_success()
        );
        assert_eq!(tunnel(address).await.unwrap().1, b'B');
        mode.store(0, Ordering::Release);
        document["layer4"][0]["routes"][1]["dynamic"]["versions"] = "ipv4".into();
        let applied = client
            .post(server.admin_url("/load"))
            .json(&document)
            .send()
            .await
            .unwrap();
        assert!(
            applied.status().is_success(),
            "{}",
            applied.text().await.unwrap()
        );
        assert!(
            tunnel(address).await.is_err(),
            "changed policy reused the IPv6 snapshot"
        );
        retained(&mut second).await;
        mode.store(1, Ordering::Release);
        let mut recovered = wait_tag(address, b'A').await;
        mode.store(3, Ordering::Release);
        wait_unavailable(address).await;
        retained(&mut recovered).await;
        drop(recovered);
        mode.store(1, Ordering::Release);
        let mut recovered = wait_tag(address, b'A').await;
        mode.store(4, Ordering::Release);
        wait_unavailable(address).await;
        retained(&mut recovered).await;
        assert!(dns.queries.lock().unwrap().iter().all(|(name, _)| {
            ["pool.test.", "target.test."]
                .iter()
                .any(|fixed| name.to_ascii() == *fixed)
        }));
        drop((old, second, recovered));
        assert!(
            client
                .post(server.admin_url("/stop"))
                .send()
                .await
                .unwrap()
                .status()
                .is_success()
        );
        let status = timeout(Duration::from_secs(10), async {
            loop {
                if let Some(status) = server.exit_status() {
                    break status;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(status.code(), Some(0));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn native_dns_transient_failures_cannot_extend_the_stale_deadline() {
    timeout(Duration::from_secs(30), async {
        let mode = Arc::new(AtomicU8::new(1));
        let dns = controlled(mode.clone()).await;
        let first = AsyncListener::bind("127.0.0.1:0").await.unwrap();
        let origin = first.local_addr().unwrap();
        let _origin = Echo::new(first, b'A');
        let mut server = TestServer::new_native(&native(dns.address, origin, origin, 1));
        assert!(server.wait_until_ready().await);
        let address = server.listener_address(0, 1);
        let mut old = wait_tag(address, b'A').await;
        mode.store(0, Ordering::Release);
        assert_eq!(tunnel(address).await.unwrap().1, b'A');
        wait_unavailable(address).await;
        retained(&mut old).await;
        mode.store(1, Ordering::Release);
        drop(wait_tag(address, b'A').await);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn caddy_dns_truncation_uses_tcp_and_closes_its_scoped_socket() {
    timeout(Duration::from_secs(15), async {
        let (dns, tcp) = dns::truncated_dns().await;
        let origin = AsyncListener::bind("127.0.0.1:0").await.unwrap();
        let address = origin.local_addr().unwrap();
        let _origin = Echo::new(origin, b'A');
        let dns_peer = tokio::spawn(async move {
            let (mut stream, _) = tcp.accept().await.unwrap();
            let query = dns::tcp_query(&mut stream).await;
            let mut reply = dns::response(&query);
            reply.add_answer(Record::from_rdata(query.queries[0].name().clone(), 30, RData::A(A(Ipv4Addr::LOCALHOST))));
            let wire = reply.to_vec().unwrap();
            stream.write_u16(wire.len().try_into().unwrap()).await.unwrap();
            stream.write_all(&wire).await.unwrap();
            assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
        });
        let routes = format!("route {{\n proxy {{\n dynamic a {{\n name pool.test\n port {}\n resolvers {}\n versions ipv4\n allow_ip 127.0.0.1/32\n }}\n }}\n }}", address.port(), dns.address);
        let mut server = TestServer::new_pingclairfile(&fixture("", &routes));
        assert!(server.wait_until_ready().await);
        drop(wait_tag(server.listener_address(0, 1), b'A').await);
        dns_peer.await.unwrap();
        assert_eq!(dns.queries.lock().unwrap().len(), 1);
    }).await.unwrap();
}
