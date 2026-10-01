//! ⏱️ A request stream that never finishes its HEADERS frame is reset at the
//! header deadline, the HTTP/3 counterpart of a slowloris client.
//!
//! QUIC's idle timer starts again with every packet, so a client that sends a
//! request's header block one byte at a time kept its stream, and the
//! connection under it, for as long as it cared to keep trickling. Up to a
//! hundred such streams fit on one connection.

use super::*;

/// 🧾 A site with a two-second header deadline, written as a Pingclairfile so
/// the DSL spelling of the limit is what reaches the listener.
const SHORT_HEADER_DEADLINE: &str = r#"
:443 {
    limits {
        header_timeout 2s
    }
    respond "ok"
}
"#;

/// H3_REQUEST_INCOMPLETE, from the error codes in RFC 9114 §8.1.
const H3_REQUEST_INCOMPLETE: u64 = 0x010d;

/// ⏱️ What happened to the dribbled stream, as one value so a failure shows
/// every part of it.
#[derive(Debug, PartialEq)]
struct Outcome {
    /// The code the server reset the stream with, if it did.
    reset_code: Option<u64>,
    /// Whether the reset arrived inside the window around the deadline.
    near_deadline: bool,
    /// Whether the connection itself was still open afterwards: the deadline
    /// is the stream's, and other requests may share the connection.
    connection_open: bool,
}

/// 🐌 Opens stream 0 with a HEADERS frame that announces 100 bytes, sends one
/// of them every half second, and reports how the server ended the stream.
async fn dribble_headers(server: SocketAddr, give_up: Duration) -> Outcome {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    config.verify_peer(false);
    config.set_application_protos(&[ALPN]).unwrap();
    config.set_max_idle_timeout(30_000);
    config.set_max_recv_udp_payload_size(1350);
    config.set_max_send_udp_payload_size(1350);
    config.set_initial_max_data(1_000_000);
    config.set_initial_max_stream_data_bidi_local(100_000);
    config.set_initial_max_stream_data_bidi_remote(100_000);
    config.set_initial_max_stream_data_uni(100_000);
    config.set_initial_max_streams_bidi(10);
    config.set_initial_max_streams_uni(10);

    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let local = socket.local_addr().unwrap();
    let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
    boring::rand::rand_bytes(&mut scid).unwrap();
    let scid = quiche::ConnectionId::from_ref(&scid);
    let mut conn =
        quiche::connect(Some("h3.pingclair.test"), &scid, local, server, &mut config).unwrap();

    let mut out = [0u8; 1350];
    let mut buf = [0u8; 65535];
    let mut started: Option<tokio::time::Instant> = None;
    let mut next_byte = tokio::time::Instant::now();
    let give_up_at = tokio::time::Instant::now() + give_up;
    let mut reset: Option<(u64, Duration)> = None;

    while let Ok((write, info)) = conn.send(&mut out) {
        socket.send_to(&out[..write], info.to).await.unwrap();
    }

    while reset.is_none() && !conn.is_closed() {
        let timeout = conn
            .timeout()
            .unwrap_or(Duration::from_millis(50))
            .min(Duration::from_millis(50));
        tokio::select! {
            _ = tokio::time::sleep_until(give_up_at) => break,
            received = socket.recv_from(&mut buf) => {
                let (len, from) = received.unwrap();
                let _ = conn.recv(&mut buf[..len], quiche::RecvInfo { from, to: local });
            }
            _ = tokio::time::sleep(timeout) => conn.on_timeout(),
        }

        if conn.is_established() {
            let now = tokio::time::Instant::now();
            match started {
                None => {
                    // 🧵 Frame type 0x01 (HEADERS) with a two-byte varint
                    // length of 100, so the server waits for a block that
                    // never comes.
                    conn.stream_send(0, &[0x01, 0x40, 0x64], false).unwrap();
                    started = Some(now);
                    next_byte = now + Duration::from_millis(500);
                }
                Some(began) => {
                    if now >= next_byte {
                        // 🐌 Keeps the stream and the connection busy, which
                        // is what used to keep both alive indefinitely.
                        match conn.stream_send(0, &[0x00], false) {
                            Err(quiche::Error::StreamStopped(code)) => {
                                reset = Some((code, began.elapsed()));
                            }
                            _ => next_byte = now + Duration::from_millis(500),
                        }
                    }
                    let mut sink = [0u8; 64];
                    if let Err(quiche::Error::StreamReset(code)) = conn.stream_recv(0, &mut sink) {
                        reset = Some((code, began.elapsed()));
                    }
                }
            }
        }

        while let Ok((write, info)) = conn.send(&mut out) {
            socket.send_to(&out[..write], info.to).await.unwrap();
        }
    }

    Outcome {
        reset_code: reset.map(|(code, _)| code),
        near_deadline: reset.is_some_and(|(_, after)| (1.5..5.0).contains(&after.as_secs_f64())),
        connection_open: !conn.is_closed(),
    }
}

/// ⏱️ `limits { header_timeout 2s }` resets a stream whose header is still
/// arriving after two seconds, and leaves its connection alone.
#[tokio::test]
async fn h3_resets_a_stream_whose_header_never_finishes() {
    let mut servers = pingclair_config::compile(SHORT_HEADER_DEADLINE)
        .unwrap()
        .servers;
    let server = spawn_h3_listener(
        move |address| {
            servers[0].listen = vec![address.to_string()];
            servers
        },
        &["h3.pingclair.test"],
        None,
    )
    .await;

    let outcome = dribble_headers(server, Duration::from_secs(10)).await;

    assert_eq!(
        outcome,
        Outcome {
            reset_code: Some(H3_REQUEST_INCOMPLETE),
            near_deadline: true,
            connection_open: true,
        }
    );
}
