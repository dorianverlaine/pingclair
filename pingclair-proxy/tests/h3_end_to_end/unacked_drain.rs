//! 🌊 A response finished before the stop began, but not yet acknowledged,
//! still holds the drain open until it is delivered.
//!
//! A stream's in-flight token used to linger until acknowledgement only if
//! the stream finished *after* the stop began. One that finished just before
//! had already dropped its token, so the drain counted zero requests and
//! ended at once, and the unacknowledged tail of that response — including
//! any packet that needed retransmitting — was thrown away although the
//! grace period had time to spare.

use super::*;

/// 🌊 What the client saw of a response whose packets it lost around a stop.
#[derive(Debug, PartialEq)]
struct Delivered {
    /// The response's status and body, if it ever arrived whole.
    response: Option<(u16, Vec<u8>)>,
    /// What the drain reported once it was done.
    stopped: Option<pingclair_proxy::drain::Stopped>,
}

/// 🌊 The client loses every packet for a moment after sending its request,
/// so the server writes its whole response — the stream is done on the
/// server's side — while none of it is acknowledged. The stop begins inside
/// that window. The drain must keep the connection until loss recovery has
/// delivered the response, rather than count zero requests and close it.
#[tokio::test]
async fn h3_response_unacknowledged_when_the_stop_begins_is_still_delivered() {
    const BLACKOUT: Duration = Duration::from_millis(500);

    let server = spawn_h3_from_pingclairfile(":443 {\n respond \"delivered\"\n}").await;

    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    config.verify_peer(false);
    config.set_application_protos(&[ALPN]).unwrap();
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
    let mut blackout_until: Option<tokio::time::Instant> = None;
    let mut stop: Option<tokio::task::JoinHandle<pingclair_proxy::drain::Stopped>> = None;
    let mut status = 0u16;
    let mut body = Vec::new();
    let mut delivered = Delivered {
        response: None,
        stopped: None,
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);

    while !conn.is_closed() && delivered.response.is_none() {
        let dark = blackout_until.is_some_and(|until| tokio::time::Instant::now() < until);
        if !dark {
            while let Ok((write, info)) = conn.send(&mut out) {
                socket.send_to(&out[..write], info.to).await.unwrap();
            }
        }
        let timeout = conn
            .timeout()
            .unwrap_or(Duration::from_millis(20))
            .min(Duration::from_millis(20));
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => panic!("timed out: {delivered:?}"),
            got = socket.recv_from(&mut buf) => {
                let (len, from) = got.unwrap();
                // 🕳️ Lost on the way: nothing is read, so nothing is acked.
                if !dark {
                    let _ = conn.recv(&mut buf[..len], quiche::RecvInfo { from, to: local });
                }
            }
            _ = tokio::time::sleep(timeout) => {
                if !dark {
                    conn.on_timeout();
                }
            }
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

        if blackout_until.is_none() {
            let request = [
                quiche::h3::Header::new(b":method", b"GET"),
                quiche::h3::Header::new(b":scheme", b"https"),
                quiche::h3::Header::new(b":authority", b"h3.pingclair.test"),
                quiche::h3::Header::new(b":path", b"/"),
            ];
            if h3.send_request(&mut conn, &request, true).is_ok() {
                // 📤 The request goes out now; everything after it is lost
                // until the blackout ends.
                while let Ok((write, info)) = conn.send(&mut out) {
                    socket.send_to(&out[..write], info.to).await.unwrap();
                }
                blackout_until = Some(tokio::time::Instant::now() + BLACKOUT);
            }
        }
        // 🛑 Halfway through the blackout the server has long since written
        // the response, and none of it has been acknowledged.
        if stop.is_none()
            && blackout_until
                .is_some_and(|until| tokio::time::Instant::now() + BLACKOUT / 2 >= until)
        {
            stop = Some(tokio::spawn(pingclair_proxy::drain::stop(
                Duration::from_secs(5),
            )));
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
                    delivered.response = Some((status, std::mem::take(&mut body)));
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    }

    // 📤 Keep acknowledging until the drain is over, so the server can see
    // the response arrived and let the stop finish.
    let stop = stop.expect("the stop never began");
    while !stop.is_finished() && !conn.is_closed() {
        while let Ok((write, info)) = conn.send(&mut out) {
            socket.send_to(&out[..write], info.to).await.unwrap();
        }
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => panic!("the drain never ended: {delivered:?}"),
            got = socket.recv_from(&mut buf) => {
                let (len, from) = got.unwrap();
                let _ = conn.recv(&mut buf[..len], quiche::RecvInfo { from, to: local });
            }
            _ = tokio::time::sleep(Duration::from_millis(20)) => conn.on_timeout(),
        }
    }
    delivered.stopped = Some(stop.await.unwrap());
    assert_eq!(
        delivered,
        Delivered {
            response: Some((200, b"delivered".to_vec())),
            stopped: Some(pingclair_proxy::drain::Stopped {
                cut: 0,
                unclosed: 0
            }),
        }
    );
}
