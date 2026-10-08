// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🚦 Independent listeners share the process quota before upstream dialing.

use super::*;
use pingclair_core::config::{Layer4Route, Layer4Server};
use pingclair_l4::PreparedListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener as AsyncListener, TcpStream};
use tokio::time::timeout;

#[tokio::test]
async fn process_quota_is_shared_and_released_across_listeners() {
    timeout(Duration::from_secs(10), async {
        let runtime = Arc::new(Runtime(
            arc_swap::ArcSwap::default(),
            Arc::new(Semaphore::new(1)),
        ));
        let origin = AsyncListener::bind("127.0.0.1:0").await.unwrap();
        let (stop, watch) = tokio::sync::watch::channel(false);
        let mut generation = super::super::Generation::new();
        let mut addresses = Vec::new();
        let mut tasks = Vec::new();
        for _ in 0..2 {
            let socket = TcpListener::bind("127.0.0.1:0").unwrap();
            socket.set_nonblocking(true).unwrap();
            let address = socket.local_addr().unwrap().to_string();
            let mut config = Layer4Server::new(address.clone());
            config.routes.push(Layer4Route {
                matches: vec![],
                upstream: origin.local_addr().unwrap().to_string(),
            });
            generation.insert(
                address.clone(),
                Arc::new(PreparedListener::prepare(&config, &[]).unwrap()),
            );
            addresses.push(address.clone());
            let mut listener = Listener {
                name: address.clone(),
                address,
                runtime: runtime.clone(),
                quota: Arc::new(Semaphore::new(2)),
                socket: Some(socket),
            };
            let watch = watch.clone();
            tasks.push(tokio::spawn(async move {
                listener.start_service(None, watch, 1).await;
            }));
        }
        runtime.publish(generation);
        let mut first = TcpStream::connect(&addresses[0]).await.unwrap();
        let (mut backend, _) = origin.accept().await.unwrap();
        backend.write_all(b"a").await.unwrap();
        first.read_exact(&mut [0]).await.unwrap();
        let mut rejected = TcpStream::connect(&addresses[1]).await.unwrap();
        assert_eq!(rejected.read(&mut [0]).await.unwrap(), 0);
        drop((first, backend));
        loop {
            let mut next = TcpStream::connect(&addresses[1]).await.unwrap();
            let mut byte = [0];
            tokio::select! {
                accepted = origin.accept() => {
                    let (mut backend, _) = accepted.unwrap();
                    backend.write_all(b"b").await.unwrap();
                    next.read_exact(&mut byte).await.unwrap();
                    assert_eq!(byte, [b'b']);
                    break;
                }
                _ = next.read(&mut byte) => tokio::task::yield_now().await,
            }
        }
        stop.send(true).unwrap();
        for task in tasks {
            task.await.unwrap();
        }
    })
    .await
    .unwrap();
}
