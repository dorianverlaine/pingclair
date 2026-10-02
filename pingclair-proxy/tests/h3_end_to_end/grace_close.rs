//! 🔌 A stream that outlives the grace period ends with the connection closed,
//! not with a client left waiting for an idle timeout (#211).
//!
//! In the 2026-09-25 soak an HTTP/3 server-sent-events stream was running when
//! `systemctl restart` stopped the process. The drain waited out the grace
//! period and the process exited, but nothing ever told the QUIC client, so
//! curl sat on a silent connection for about seventy seconds. TCP clients saw
//! the close at once because the kernel sends it; QUIC needs the process to.

use super::*;

/// 🌊 An origin that streams one event every 100 ms until the reader goes away.
async fn spawn_endless_origin() -> SocketAddr {
    use tokio::io::AsyncWriteExt as _;

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let _ = read_http_head(&mut stream).await;
        let head = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\
                     Transfer-Encoding: chunked\r\n\r\n";
        if stream.write_all(head).await.is_err() {
            return;
        }
        loop {
            if stream.write_all(b"c\r\ndata: tick\n\n\r\n").await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });
    address
}

/// 🔌 What the client saw of its connection once the grace period ran out.
#[derive(Debug, PartialEq)]
struct Observed {
    /// The id carried by the server's `GOAWAY`, if one arrived.
    goaway: Option<u64>,
    /// Whether the response stream ended with a FIN, which a cut one must not.
    finished: bool,
    /// Whether the server closed with H3_NO_ERROR as an application close.
    closed_cleanly: bool,
    /// Whether the close arrived soon after the grace period, rather than
    /// the client giving up on its own.
    closed_promptly: bool,
}

/// 🔌 The grace period runs out with an event stream still open: the server
/// sends `GOAWAY`, then closes the connection with H3_NO_ERROR right after
/// the deadline, and the drain reports the stream as cut and no connection
/// left unclosed.
#[tokio::test]
async fn h3_stream_outliving_the_grace_period_ends_with_a_prompt_close() {
    const GRACE: Duration = Duration::from_millis(600);

    let origin = spawn_endless_origin().await;
    let server = spawn_h3_from_pingclairfile(&format!(
        ":443 {{\n reverse_proxy http://{origin} {{\n  flush_interval -1\n }}\n}}"
    ))
    .await;

    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    config.verify_peer(false);
    config.set_application_protos(&[ALPN]).unwrap();
    // 🕰️ Far longer than the test may run, so a server that never closes
    // shows up as this test's deadline, not as the client giving up.
    config.set_max_idle_timeout(60_000);
    config.set_initial_max_data(1_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);

    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let local = socket.local_addr().unwrap();
    let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
    boring::rand::rand_bytes(&mut scid).unwrap();
    let scid = quiche::ConnectionId::from_ref(&scid);
    let mut conn =
        quiche::connect(Some("h3.pingclair.test"), &scid, local, server, &mut config).unwrap();

    let mut out = [0u8; 1350];
    let mut buf = [0u8; 65535];
    let mut h3: Option<quiche::h3::Connection> = None;
    let mut requested = false;
    let mut received = 0usize;
    let mut stop: Option<(tokio::time::Instant, tokio::task::JoinHandle<_>)> = None;
    let mut observed = Observed {
        goaway: None,
        finished: false,
        closed_cleanly: false,
        closed_promptly: false,
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);

    while !conn.is_closed() {
        while let Ok((write, info)) = conn.send(&mut out) {
            socket.send_to(&out[..write], info.to).await.unwrap();
        }
        let timeout = conn
            .timeout()
            .unwrap_or(Duration::from_millis(20))
            .min(Duration::from_millis(50));
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => panic!(
                "the connection was never closed: {observed:?}, {received} body bytes"
            ),
            got = socket.recv_from(&mut buf) => {
                let (len, from) = got.unwrap();
                let _ = conn.recv(&mut buf[..len], quiche::RecvInfo { from, to: local });
            }
            _ = tokio::time::sleep(timeout) => conn.on_timeout(),
        }

        if conn.is_established() && h3.is_none() {
            h3 = Some(
                quiche::h3::Connection::with_transport(
                    &mut conn,
                    &quiche::h3::Config::new().unwrap(),
                )
                .unwrap(),
            );
        }
        let Some(h3) = h3.as_mut() else { continue };

        if !requested {
            let request = [
                quiche::h3::Header::new(b":method", b"GET"),
                quiche::h3::Header::new(b":scheme", b"https"),
                quiche::h3::Header::new(b":authority", b"h3.pingclair.test"),
                quiche::h3::Header::new(b":path", b"/events"),
            ];
            requested = h3.send_request(&mut conn, &request, true).is_ok();
        }

        loop {
            match h3.poll(&mut conn) {
                Ok((stream_id, quiche::h3::Event::Data)) => {
                    let mut chunk = [0u8; 4096];
                    while let Ok(read) = h3.recv_body(&mut conn, stream_id, &mut chunk) {
                        received += read;
                    }
                }
                Ok((_, quiche::h3::Event::Finished)) => observed.finished = true,
                Ok((id, quiche::h3::Event::GoAway)) => observed.goaway = Some(id),
                Ok(_) => {}
                Err(_) => break,
            }
        }

        // 🛑 Begin the stop once events are flowing, so the stream is
        // provably running when the grace period starts.
        if stop.is_none() && received > 0 {
            stop = Some((
                tokio::time::Instant::now(),
                tokio::spawn(pingclair_proxy::drain::stop(GRACE)),
            ));
        }
    }

    let (stop_began, stop_task) = stop.expect("the stream never delivered an event");
    observed.closed_cleanly = conn.peer_error().is_some_and(|error| {
        error.is_app && error.error_code == quiche::h3::WireErrorCode::NoError as u64
    });
    observed.closed_promptly = stop_began.elapsed() < GRACE + Duration::from_secs(2);
    assert_eq!(
        observed,
        Observed {
            goaway: Some(4),
            finished: false,
            closed_cleanly: true,
            closed_promptly: true,
        }
    );
    assert_eq!(
        stop_task.await.unwrap(),
        pingclair_proxy::drain::Stopped {
            cut: 1,
            unclosed: 0
        },
        "the stream counts as cut, and the close left before the exit would have"
    );
}
