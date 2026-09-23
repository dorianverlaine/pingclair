//! 🛑 A graceful stop over HTTP/3: `GOAWAY`, the running request finishes,
//! then the connection closes cleanly (RFC 9114 §5.2).
//!
//! Before this, HTTP/3 never sent `GOAWAY` at all, so a client with a request
//! running during a restart could not tell whether it had been executed.

use super::*;

/// 🐢 An origin that holds its one response for `delay`.
async fn spawn_slow_origin(delay: Duration) -> SocketAddr {
    use tokio::io::AsyncWriteExt as _;

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let _ = read_http_head(&mut stream).await;
        tokio::time::sleep(delay).await;
        let _ = stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nslow")
            .await;
    });
    address
}

/// 🛑 What the client saw of one connection during a graceful stop.
#[derive(Debug, PartialEq)]
struct Observed {
    /// The id carried by the server's `GOAWAY`, if one arrived.
    goaway: Option<u64>,
    /// The request's status and body.
    response: Option<(u16, Vec<u8>)>,
    /// Whether the server closed with H3_NO_ERROR as an application close.
    closed_cleanly: bool,
}

/// 🛑 A request running when the stop begins completes, the client is told
/// with `GOAWAY(4)` that nothing after stream 0 will be served, and the
/// connection then closes with H3_NO_ERROR.
#[tokio::test]
async fn h3_graceful_stop_sends_goaway_and_finishes_the_running_request() {
    let origin = spawn_slow_origin(Duration::from_millis(800)).await;
    let server =
        spawn_h3_from_pingclairfile(&format!(":443 {{\n reverse_proxy http://{origin}\n}}")).await;

    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    config.verify_peer(false);
    config.set_application_protos(&[ALPN]).unwrap();
    config.set_max_idle_timeout(5_000);
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
    let mut sent_at: Option<tokio::time::Instant> = None;
    let mut stop_begun = false;
    let mut observed = Observed {
        goaway: None,
        response: None,
        closed_cleanly: false,
    };
    let mut status = 0u16;
    let mut body = Vec::new();
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
            _ = tokio::time::sleep_until(deadline) => panic!("timed out: {observed:?}"),
            received = socket.recv_from(&mut buf) => {
                let (len, from) = received.unwrap();
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

        if sent_at.is_none() {
            let request = [
                quiche::h3::Header::new(b":method", b"GET"),
                quiche::h3::Header::new(b":scheme", b"https"),
                quiche::h3::Header::new(b":authority", b"h3.pingclair.test"),
                quiche::h3::Header::new(b":path", b"/slow"),
            ];
            if h3.send_request(&mut conn, &request, true).is_ok() {
                sent_at = Some(tokio::time::Instant::now());
            }
        }
        // 🛑 Begin the stop while the origin is still holding the response,
        // long enough after sending that the server has the request.
        if !stop_begun && sent_at.is_some_and(|at| at.elapsed() >= Duration::from_millis(300)) {
            pingclair_proxy::drain::begin_stopping();
            stop_begun = true;
        }

        loop {
            match h3.poll(&mut conn) {
                Ok((_, quiche::h3::Event::Headers { list, .. })) => {
                    for header in &list {
                        if header.name() == b":status" {
                            status = String::from_utf8_lossy(header.value()).parse().unwrap();
                        }
                    }
                }
                Ok((stream_id, quiche::h3::Event::Data)) => {
                    let mut chunk = [0u8; 4096];
                    while let Ok(read) = h3.recv_body(&mut conn, stream_id, &mut chunk) {
                        body.extend_from_slice(&chunk[..read]);
                    }
                }
                Ok((_, quiche::h3::Event::Finished)) => {
                    observed.response = Some((status, std::mem::take(&mut body)));
                }
                Ok((id, quiche::h3::Event::GoAway)) => observed.goaway = Some(id),
                Ok(_) => {}
                Err(_) => break,
            }
        }
    }

    observed.closed_cleanly = conn.peer_error().is_some_and(|error| {
        error.is_app && error.error_code == quiche::h3::WireErrorCode::NoError as u64
    });
    assert_eq!(
        observed,
        Observed {
            goaway: Some(4),
            response: Some((200, b"slow".to_vec())),
            closed_cleanly: true,
        }
    );
    assert_eq!(
        pingclair_proxy::drain::in_flight(),
        0,
        "the finished stream must release its hold on the stop"
    );
}
