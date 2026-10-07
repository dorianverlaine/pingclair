// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

use super::*;
use pingclair_core::config::{Layer4Matcher, Layer4Route, Layer4TlsMatcher};
use std::sync::Arc;
use tokio::io::{AsyncWriteExt, duplex};
use tokio::net::TcpListener;

fn hello() -> Vec<u8> {
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(rustls::RootCertStore::empty())
    .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let mut client =
        rustls::ClientConnection::new(Arc::new(config), "example.test".try_into().unwrap())
            .unwrap();
    let mut bytes = Vec::new();
    client.write_tls(&mut bytes).unwrap();
    bytes
}

fn config(address: SocketAddr) -> Layer4Server {
    let mut config = Layer4Server::new("127.0.0.1:9443".into());
    config.proxy_half_close = true;
    config.routes.push(Layer4Route {
        matches: vec![Layer4Matcher {
            tls: Some(Layer4TlsMatcher {
                sni: vec!["EXAMPLE.test".into()],
                alpn: vec!["h2".into()],
            }),
            remote_ip: vec!["127.0.0.0/8".into()],
        }],
        upstream: address.to_string(),
    });
    config
}

#[tokio::test]
async fn a_real_rustls_hello_reaches_the_selected_origin_unchanged() {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let prepared = PreparedListener::prepare(&config(origin.local_addr().unwrap()), &[]).unwrap();
    let (mut client, stream) = duplex(17);
    let wire = hello();
    let expected = wire.clone();
    let backend = tokio::spawn(async move {
        let (mut socket, _) = origin.accept().await.unwrap();
        let mut got = Vec::new();
        socket.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, expected);
        socket.write_all(b"origin").await.unwrap();
    });
    let session = tokio::spawn(async move {
        prepared
            .serve(stream, "::ffff:127.0.0.1".parse().unwrap())
            .await
    });
    client.write_all(&wire).await.unwrap();
    client.shutdown().await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, b"origin");
    backend.await.unwrap();
    session.await.unwrap().unwrap();
}

#[tokio::test]
async fn plain_input_reaches_only_the_fallback_route() {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut cfg = config("127.0.0.1:1".parse().unwrap());
    cfg.routes.push(Layer4Route {
        matches: vec![],
        upstream: origin.local_addr().unwrap().to_string(),
    });
    let prepared = PreparedListener::prepare(&cfg, &[]).unwrap();
    let (mut client, stream) = duplex(32);
    let session =
        tokio::spawn(async move { prepared.serve(stream, "127.0.0.1".parse().unwrap()).await });
    client.write_all(b"plain bytes").await.unwrap();
    client.shutdown().await.unwrap();
    let (mut backend, _) = origin.accept().await.unwrap();
    let mut got = Vec::new();
    backend.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"plain bytes");
    backend.shutdown().await.unwrap();
    session.await.unwrap().unwrap();
}

#[tokio::test]
async fn timeout_and_overflow_do_not_dial_the_fallback() {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    for overflow in [false, true] {
        let mut cfg = config(origin.local_addr().unwrap());
        cfg.preread_timeout_ms = 20;
        cfg.preread_buffer_size = 32;
        cfg.routes.push(Layer4Route {
            matches: vec![],
            upstream: origin.local_addr().unwrap().to_string(),
        });
        let prepared = PreparedListener::prepare(&cfg, &[]).unwrap();
        let (mut client, stream) = duplex(32);
        client
            .write_all(if overflow {
                &[22, 3, 3, 255, 255]
            } else {
                &[22]
            })
            .await
            .unwrap();
        let error = prepared
            .serve(stream, "127.0.0.1".parse().unwrap())
            .await
            .unwrap_err();
        assert_eq!(
            error.kind(),
            if overflow {
                io::ErrorKind::InvalidData
            } else {
                io::ErrorKind::TimedOut
            }
        );
        assert!(
            timeout(Duration::from_millis(20), origin.accept())
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn blocked_peers_are_refused_before_any_preread_or_dial() {
    let prepared = PreparedListener::prepare(
        &config("127.0.0.1:1".parse().unwrap()),
        &["127.0.0.0/8".into()],
    )
    .unwrap();
    for peer in ["127.0.0.1", "::ffff:127.0.0.1"] {
        let (_client, stream) = duplex(8);
        assert_eq!(
            prepared
                .serve(stream, peer.parse().unwrap())
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }
}
