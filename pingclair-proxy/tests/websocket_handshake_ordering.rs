// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔌 Pin the dependency's upgrade race through its public proxy interface.
//! A native configuration cannot delay the original empty-body task, so this
//! fixture supplies the scheduler hook directly, as upstream PR #947 does.

use async_trait::async_trait;
use bytes::Bytes;
use pingora_core::{apps::ServerApp, server::configuration::ServerConf, upstreams::peer::HttpPeer};
use pingora_proxy::{HttpProxy, ProxyHttp, Session};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

struct DelayedBodyProxy(SocketAddr);

#[async_trait]
impl ProxyHttp for DelayedBodyProxy {
    type CTX = bool;

    fn new_ctx(&self) -> Self::CTX {
        false
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> pingora_core::Result<Box<HttpPeer>> {
        Ok(Box::new(HttpPeer::new(self.0, false, String::new())))
    }

    async fn request_body_filter(
        &self,
        _session: &mut Session,
        _body: &mut Option<Bytes>,
        end_of_stream: bool,
        delayed: &mut Self::CTX,
    ) -> pingora_core::Result<()> {
        if end_of_stream && !*delayed {
            *delayed = true;
            // 🕰️ Let the upstream's immediate 101 overtake the empty-body task.
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        Ok(())
    }
}

async fn read_head(stream: &mut (impl AsyncRead + Unpin)) -> Vec<u8> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        assert!(head.len() < 8192, "header exceeds the fixture's bound");
        head.push(
            stream
                .read_u8()
                .await
                .expect("connection closed during header"),
        );
    }
    head
}

#[tokio::test]
async fn upgrade_survives_the_original_body_end_after_101() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let origin = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let _ = read_head(&mut socket).await;
            socket.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n").await.unwrap();
            let mut payload = [0; 5];
            socket.read_exact(&mut payload).await.unwrap();
            socket.write_all(&payload).await.unwrap();
        });

        let proxy = Arc::new(HttpProxy::new(DelayedBodyProxy(address), Arc::new(ServerConf::default())));
        let (mut client, downstream) = tokio::io::duplex(8192);
        let (_shutdown_tx, shutdown) = tokio::sync::watch::channel(false);
        let exchange = tokio::spawn(async move {
            proxy.process_new(Box::new(downstream), &shutdown).await;
        });
        client.write_all(b"GET /socket HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n").await.unwrap();
        let head = read_head(&mut client).await;
        assert!(head.starts_with(b"HTTP/1.1 101 "));
        client.write_all(b"hello").await.unwrap();
        let mut echoed = [0; 5];
        client.read_exact(&mut echoed).await.expect("tunnel closed instead of echoing the payload");
        assert_eq!(&echoed, b"hello");
        drop(client);
        origin.await.unwrap();
        exchange.await.unwrap();
    }).await.expect("upgrade exchange must complete within its bound");
}
