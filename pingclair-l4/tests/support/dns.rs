// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧪 A controlled DNS peer shared by dependency and runtime contract tests.

use hickory_resolver::proto::op::{Message, OpCode};
use hickory_resolver::proto::rr::{
    Name, RData, Record, RecordType,
    rdata::{A, AAAA},
};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;

pub struct Dns {
    pub address: SocketAddr,
    pub queries: Arc<Mutex<Vec<(Name, RecordType)>>>,
    task: JoinHandle<()>,
}

impl Dns {
    pub async fn new(reply: impl Fn(&Message) -> Message + Send + 'static) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let queries = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&queries);
        let task = tokio::spawn(async move {
            let mut wire = [0; 65535];
            loop {
                let (length, peer) = socket.recv_from(&mut wire).await.unwrap();
                let query = Message::from_vec(&wire[..length]).unwrap();
                seen.lock().unwrap().push((
                    query.queries[0].name().clone(),
                    query.queries[0].query_type(),
                ));
                socket
                    .send_to(&reply(&query).to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });
        Self {
            address,
            queries,
            task,
        }
    }
}

impl Drop for Dns {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub fn response(query: &Message) -> Message {
    let mut reply = Message::response(query.id, OpCode::Query);
    reply.metadata.recursion_desired = query.recursion_desired;
    reply.metadata.recursion_available = true;
    reply.add_queries(query.queries.clone());
    reply
}

pub fn address(reply: &mut Message, name: Name, ttl: u32, kind: RecordType) {
    let data = match kind {
        RecordType::A => RData::A(A(Ipv4Addr::new(203, 0, 113, 10))),
        RecordType::AAAA => RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)),
        _ => panic!("unexpected address family"),
    };
    reply.add_answer(Record::from_rdata(name, ttl, data));
}

pub async fn tcp_query(stream: &mut TcpStream) -> Message {
    let length = stream.read_u16().await.unwrap();
    let mut wire = vec![0; usize::from(length)];
    stream.read_exact(&mut wire).await.unwrap();
    Message::from_vec(&wire).unwrap()
}

/// 🧷 A fixture that answers over UDP **and** holds the TCP side of the same
/// address, which is what the truncated-answer path needs.
///
/// 📌 The port is whatever the UDP socket's ephemeral assignment returned, and
/// the TCP bind can lose it to another process in between: `EADDRINUSE` on a
/// loaded CI runner, observed on 2026-10-10 in the aarch64 shard. Retrying the
/// pair is the fix — the collision is per attempt, the property under test (one
/// address, both transports) is unchanged, and five attempts make the race
/// negligible. A failure that is not a lost port still panics at once, so a
/// real defect is not hidden behind the retry.
pub async fn truncated_dns() -> (Dns, TcpListener) {
    for _ in 0..5 {
        let dns = Dns::new(|query| {
            let mut reply = response(query);
            reply.metadata.truncation = true;
            reply
        })
        .await;
        match TcpListener::bind(dns.address).await {
            Ok(tcp) => return (dns, tcp),
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => continue,
            Err(error) => panic!("TCP side of the DNS fixture: {error}"),
        }
    }
    panic!("the UDP-assigned port stayed taken across five attempts");
}
