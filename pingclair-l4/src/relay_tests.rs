// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

fn options(half_close: bool) -> RelayOptions {
    RelayOptions {
        buffer_size: 31,
        idle_timeout: Duration::from_secs(2),
        half_close,
    }
}

#[tokio::test]
async fn prefix_and_large_body_arrive_once_before_a_half_close_response() {
    let (mut client, mut downstream) = duplex(43);
    let (mut upstream, mut origin) = duplex(47);
    let task = tokio::spawn(async move {
        relay(
            &mut downstream,
            &mut upstream,
            b"prefix:".to_vec(),
            options(true),
        )
        .await
    });
    let body: Vec<_> = (0..2_000_000).map(|i| (i % 251) as u8).collect();
    let expected = body.clone();
    let server = tokio::spawn(async move {
        let mut got = Vec::new();
        origin.read_to_end(&mut got).await.unwrap();
        assert_eq!(&got[..7], b"prefix:");
        assert_eq!(got[7..], expected);
        origin.write_all(b"response after EOF").await.unwrap();
        origin.shutdown().await.unwrap();
    });
    client.write_all(&body).await.unwrap();
    client.shutdown().await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, b"response after EOF");
    server.await.unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn default_eof_finishes_without_waiting_for_the_other_eof() {
    let (mut client, mut downstream) = duplex(64);
    let (mut upstream, mut origin) = duplex(64);
    let task = tokio::spawn(async move {
        relay(
            &mut downstream,
            &mut upstream,
            b"hello".to_vec(),
            options(false),
        )
        .await
    });
    client.shutdown().await.unwrap();
    let mut request = Vec::new();
    origin.read_to_end(&mut request).await.unwrap();
    assert_eq!(request, b"hello");
    task.await.unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn traffic_in_either_direction_refreshes_the_shared_idle_clock() {
    let (mut client, mut downstream) = duplex(64);
    let (mut upstream, mut origin) = duplex(64);
    let task = tokio::spawn(async move {
        relay(&mut downstream, &mut upstream, Vec::new(), options(true)).await
    });
    for _ in 0..5 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        origin.write_all(b"x").await.unwrap();
        assert_eq!(client.read_u8().await.unwrap(), b'x');
        assert!(!task.is_finished());
    }
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(
        task.await.unwrap().unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
}

#[tokio::test(start_paused = true)]
async fn a_stalled_reader_is_bounded_and_times_out() {
    let (client, mut downstream) = duplex(8);
    let (mut upstream, _origin) = duplex(8);
    let task = tokio::spawn(async move {
        relay(&mut downstream, &mut upstream, vec![3; 1024], options(true)).await
    });
    assert_eq!(
        task.await.unwrap().unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    drop(client);
}
