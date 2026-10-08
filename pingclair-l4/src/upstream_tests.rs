// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧪 Real sockets and deterministic clocks exercise the dial boundary.

use super::*;
use std::sync::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn addresses(count: u16) -> Vec<SocketAddr> {
    (1..=count)
        .map(|port| SocketAddr::from(([127, 0, 0, 1], port)))
        .collect()
}

#[tokio::test]
async fn concurrent_connections_distribute_initial_attempts() {
    let pool = std::sync::Arc::new(Upstream::from_addresses(addresses(3)).unwrap());
    let mut tasks = Vec::new();
    for _ in 0..30 {
        let pool = pool.clone();
        tasks.push(tokio::spawn(async move {
            pool.connect_with(Duration::from_secs(5), |address| async move { Ok(address) })
                .await
                .unwrap()
        }));
    }
    let mut counts = [0; 3];
    for task in tasks {
        counts[usize::from(task.await.unwrap().port()) - 1] += 1;
    }
    assert_eq!(counts, [10, 10, 10]);
}

#[tokio::test(start_paused = true)]
async fn a_blackhole_yields_to_the_next_address_without_resetting_the_total_deadline() {
    let pool = Upstream::from_addresses(addresses(3)).unwrap();
    let start = Instant::now();
    let selected = pool
        .connect_with(Duration::from_secs(3), |address| async move {
            if address.port() == 1 {
                std::future::pending::<()>().await;
            }
            Ok(address)
        })
        .await
        .unwrap();
    assert_eq!(
        (selected.port(), start.elapsed()),
        (2, Duration::from_secs(2))
    );
    let start = Instant::now();
    let result = pool
        .connect_with(Duration::from_secs(3), |_| {
            std::future::pending::<io::Result<()>>()
        })
        .await;
    assert_eq!(
        (result.unwrap_err().kind(), start.elapsed()),
        (io::ErrorKind::TimedOut, Duration::from_secs(3))
    );
}

#[tokio::test]
async fn refused_addresses_are_tried_once_with_a_four_attempt_ceiling() {
    let pool = Upstream::from_addresses(addresses(6)).unwrap();
    let attempts = Mutex::new(Vec::new());
    let error = pool
        .connect_with(Duration::from_secs(5), |address| {
            attempts.lock().unwrap().push(address.port());
            std::future::ready(Err::<(), _>(io::ErrorKind::ConnectionRefused.into()))
        })
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
    assert_eq!(*attempts.lock().unwrap(), vec![1, 2, 3, 4]);
    for kind in [
        io::ErrorKind::PermissionDenied,
        io::ErrorKind::OutOfMemory,
        io::ErrorKind::AddrNotAvailable,
        io::ErrorKind::Other,
    ] {
        attempts.lock().unwrap().clear();
        let error = pool
            .connect_with(Duration::from_secs(5), |address| {
                attempts.lock().unwrap().push(address.port());
                std::future::ready(Err::<(), _>(kind.into()))
            })
            .await
            .unwrap_err();
        assert_eq!(error.kind(), kind);
        assert_eq!(attempts.lock().unwrap().len(), 1);
    }
}

#[tokio::test(start_paused = true)]
async fn a_single_address_keeps_the_configured_deadline() {
    let pool = Upstream::from_addresses(addresses(1)).unwrap();
    let start = Instant::now();
    let error = pool
        .connect_with(Duration::from_secs(5), |_| {
            std::future::pending::<io::Result<()>>()
        })
        .await
        .unwrap_err();
    assert_eq!(
        (error.kind(), start.elapsed()),
        (io::ErrorKind::TimedOut, Duration::from_secs(5))
    );
}

#[tokio::test]
async fn real_tcp_connections_rotate_and_return_the_selected_stream() {
    let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let second = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pool =
        Upstream::from_addresses([first.local_addr().unwrap(), second.local_addr().unwrap()])
            .unwrap();
    let peers = [first, second];
    let mut selected = Vec::new();
    for _ in 0..2 {
        let mut client = pool.connect(Duration::from_secs(2)).await.unwrap();
        let address = client.peer_addr().unwrap();
        selected.push(address);
        let peer = peers
            .iter()
            .find(|peer| peer.local_addr().unwrap() == address)
            .unwrap();
        let (mut server, _) = peer.accept().await.unwrap();
        server.write_all(b"server first").await.unwrap();
        let mut reply = [0; 12];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"server first");
    }
    assert_ne!(selected[0], selected[1]);
}

#[test]
fn address_limits_apply_after_deduplication() {
    assert!(Upstream::from_addresses(addresses(65)).is_err());
    assert!(Upstream::from_addresses([]).is_err());
    let pool = Upstream::from_addresses(std::iter::repeat_n(addresses(1)[0], 100)).unwrap();
    assert_eq!(pool.addresses.as_ref(), addresses(1));
}

#[tokio::test]
async fn unavailable_socket_falls_back_to_a_live_origin() {
    let reserved = tokio::net::TcpSocket::new_v4().unwrap();
    reserved.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let refused = reserved.local_addr().unwrap();
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ready = origin.local_addr().unwrap();
    let pool = Upstream::from_addresses([refused, ready]).unwrap();
    pool.cursor.store(
        pool.addresses
            .iter()
            .position(|address| *address == refused)
            .unwrap(),
        Ordering::Relaxed,
    );
    // 🧪 A bound socket without listen can time out instead of refusing on macOS.
    let client = pool.connect(Duration::from_secs(5)).await.unwrap();
    assert_eq!(client.peer_addr().unwrap(), ready);
    let _accepted = origin.accept().await.unwrap();
}
