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

/// 🧵 Frame type 0x01 (HEADERS) with a two-byte varint length of 100, so the
/// server waits for a header block that never comes.
const UNFINISHED_HEADERS: [u8; 3] = [0x01, 0x40, 0x64];

/// ⏱️ How the server ended one dribbled stream, as one value so a failure
/// shows every part of it.
#[derive(Debug, PartialEq)]
struct Outcome {
    /// The code the server reset the stream with, if it did.
    reset_code: Option<u64>,
    /// Whether the reset came inside the window the test expects, measured
    /// from the stream's first byte.
    in_window: bool,
    /// Whether the connection itself was still open afterwards: the deadline
    /// is the stream's, and other requests may share the connection.
    connection_open: bool,
}

/// 🐌 One dribbled stream: when it started and how the server ended it.
struct Dribble {
    stream_id: u64,
    started: Option<tokio::time::Instant>,
    next_byte: tokio::time::Instant,
    reset: Option<(u64, Duration)>,
}

impl Dribble {
    fn on(stream_id: u64) -> Self {
        Self {
            stream_id,
            started: None,
            next_byte: tokio::time::Instant::now(),
            reset: None,
        }
    }

    /// 🐌 Starts the stream, or sends its next byte every half second, and
    /// notices the server ending it from either direction.
    fn step(&mut self, conn: &mut quiche::Connection) {
        let now = tokio::time::Instant::now();
        let Some(began) = self.started else {
            conn.stream_send(self.stream_id, &UNFINISHED_HEADERS, false)
                .unwrap();
            self.started = Some(now);
            self.next_byte = now + Duration::from_millis(500);
            return;
        };
        if now >= self.next_byte {
            // 🐌 Keeps the stream and the connection busy, which is what used
            // to keep both alive indefinitely.
            match conn.stream_send(self.stream_id, &[0x00], false) {
                Err(quiche::Error::StreamStopped(code)) => {
                    self.reset = Some((code, began.elapsed()));
                }
                _ => self.next_byte = now + Duration::from_millis(500),
            }
        }
        let mut sink = [0u8; 64];
        if let Err(quiche::Error::StreamReset(code)) = conn.stream_recv(self.stream_id, &mut sink) {
            self.reset = Some((code, began.elapsed()));
        }
    }
}

/// 🐌 Dribbles an unfinished HEADERS frame on stream 0 and reports how the
/// server ended it, expecting the reset `window` seconds after stream 0's
/// first byte.
///
/// With `decoy`, stream 8 is dribbled first and stream 0 only once 8 has been
/// reset. Opening 8 opens 0 and 4 implicitly (RFC 9000 §3.2), so their
/// deadlines run out alongside 8's while quiche has not instantiated them;
/// stream 0 then arrives long after its deadline and has to be refused at
/// once rather than given forever.
async fn dribble_headers(server: SocketAddr, decoy: bool, window: std::ops::Range<f64>) -> Outcome {
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
    let give_up_at = tokio::time::Instant::now() + Duration::from_secs(if decoy { 14 } else { 10 });
    let mut decoy = decoy.then(|| Dribble::on(8));
    let mut target = Dribble::on(0);

    while let Ok((write, info)) = conn.send(&mut out) {
        socket.send_to(&out[..write], info.to).await.unwrap();
    }

    while target.reset.is_none() && !conn.is_closed() {
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
            match decoy.as_mut() {
                Some(first) if first.reset.is_none() => first.step(&mut conn),
                _ => target.step(&mut conn),
            }
        }

        while let Ok((write, info)) = conn.send(&mut out) {
            socket.send_to(&out[..write], info.to).await.unwrap();
        }
    }

    Outcome {
        reset_code: target.reset.map(|(code, _)| code),
        in_window: target
            .reset
            .is_some_and(|(_, after)| window.contains(&after.as_secs_f64())),
        connection_open: !conn.is_closed(),
    }
}

/// 🧾 Starts an H3 listener for [`SHORT_HEADER_DEADLINE`].
async fn spawn_short_deadline_site() -> SocketAddr {
    let mut servers = pingclair_config::compile(SHORT_HEADER_DEADLINE)
        .unwrap()
        .servers;
    spawn_h3_listener(
        move |address| {
            servers[0].listen = vec![address.to_string()];
            servers
        },
        &["h3.pingclair.test"],
        None,
    )
    .await
}

/// 🎯 What every test here expects: a stream reset, not a closed connection.
const RESET_IN_WINDOW: Outcome = Outcome {
    reset_code: Some(H3_REQUEST_INCOMPLETE),
    in_window: true,
    connection_open: true,
};

/// ⏱️ `limits { header_timeout 2s }` resets a stream whose header is still
/// arriving after two seconds, and leaves its connection alone.
#[tokio::test]
async fn h3_resets_a_stream_whose_header_never_finishes() {
    let server = spawn_short_deadline_site().await;
    let outcome = dribble_headers(server, false, 1.5..5.0).await;
    assert_eq!(outcome, RESET_IN_WINDOW);
}

/// ⏱️ A stream opened implicitly, by a higher one, keeps the deadline it got
/// then: when it finally sends something after that deadline, it is refused
/// at once instead of being timed from scratch or not at all.
#[tokio::test]
async fn h3_refuses_an_implicit_stream_that_arrives_after_its_deadline() {
    let server = spawn_short_deadline_site().await;
    let outcome = dribble_headers(server, true, 0.0..1.0).await;
    assert_eq!(outcome, RESET_IN_WINDOW);
}
