//! End-to-end HTTP/3 against a real [`QuicServer`], with a real QUIC client.
//!
//! Before the tokio-quiche migration nothing started `QuicServer` in a test at
//! all — the whole H3 path was reachable only by running the binary. These
//! tests exist so the event loop is covered by something other than inspection:
//! a genuine handshake, a genuine request, and the response read back off the
//! wire.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use pingclair_core::config::{HandlerConfig, RouteConfig, ServerConfig};
use pingclair_proxy::quic::{CertTable, QuicServer};
use pingclair_proxy::server::PingclairProxy;
use quiche::h3::NameValue;

const ALPN: &[u8] = b"h3";

fn self_signed_pem(names: &[&str]) -> (String, String) {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(names.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .unwrap();
    (cert.pem(), signing_key.serialize_pem())
}

/// Start an H3 server on an ephemeral port serving `handler` at `/*`.
async fn spawn_h3_server(handler: HandlerConfig) -> SocketAddr {
    let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();

    // 🔌 Bind first so the test knows the port; `QuicServer` rebinds the same
    // address once this probe socket is dropped.
    let probe = std::net::UdpSocket::bind(listen).unwrap();
    let address = probe.local_addr().unwrap();
    drop(probe);

    let proxy = PingclairProxy::new();
    proxy.update_config(vec![ServerConfig {
        listen: vec![address.to_string()],
        routes: vec![RouteConfig {
            path: "/*".to_string(),
            handler,
            methods: None,
            matcher: None,
        }],
        ..Default::default()
    }]);

    let certs = Arc::new(CertTable::new());
    let (cert, key) = self_signed_pem(&["h3.pingclair.test"]);
    certs.upsert_pem("h3.pingclair.test", &cert, &key).unwrap();

    let server = QuicServer::new(address, Arc::new(proxy), certs, 8, Vec::new());
    tokio::spawn(async move {
        if let Err(e) = server.run().await {
            eprintln!("H3 server stopped: {e}");
        }
    });

    // 🕰️ The listener binds inside `run()`; give it a moment before probing.
    tokio::time::sleep(Duration::from_millis(200)).await;
    address
}

struct H3Response {
    status: u16,
    body: Vec<u8>,
}

/// Perform one HTTP/3 request and read the complete response.
///
/// A hand-driven client rather than a library one: this has to exercise the
/// server's own event loop, so the test must not depend on tokio-quiche's
/// client path being correct.
async fn h3_get(server: SocketAddr, path: &str) -> Result<H3Response, String> {
    let mut config = quiche::Config::with_boring_ssl_ctx_builder(
        quiche::PROTOCOL_VERSION,
        boring::ssl::SslContextBuilder::new(boring::ssl::SslMethod::tls()).unwrap(),
    )
    .unwrap();
    config.verify_peer(false);
    config.set_application_protos(&[ALPN]).unwrap();
    config.set_max_idle_timeout(5_000);
    config.set_max_recv_udp_payload_size(1350);
    config.set_max_send_udp_payload_size(1350);
    config.set_initial_max_data(10_000_000);
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

    let mut conn = quiche::connect(Some("h3.pingclair.test"), &scid, local, server, &mut config)
        .map_err(|e| format!("connect: {e}"))?;

    let mut out = [0u8; 1350];
    let mut buf = [0u8; 65535];
    let mut h3: Option<quiche::h3::Connection> = None;
    let mut sent = false;
    let mut status = None;
    let mut body = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);

    macro_rules! flush {
        () => {
            while let Ok((write, info)) = conn.send(&mut out) {
                socket.send_to(&out[..write], info.to).await.unwrap();
            }
        };
    }

    flush!();

    loop {
        if conn.is_closed() {
            return Err(format!("connection closed: {:?}", conn.peer_error()));
        }

        let timeout = conn
            .timeout()
            .unwrap_or(Duration::from_millis(20))
            .min(Duration::from_millis(100));

        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => {
                return Err(format!("timed out (status={status:?}, {} body bytes)", body.len()));
            }
            received = socket.recv_from(&mut buf) => {
                let (len, from) = received.unwrap();
                let info = quiche::RecvInfo { from, to: local };
                if let Err(e) = conn.recv(&mut buf[..len], info) {
                    return Err(format!("recv: {e}"));
                }
            }
            _ = tokio::time::sleep(timeout) => conn.on_timeout(),
        }

        if conn.is_established() && h3.is_none() {
            h3 = Some(
                quiche::h3::Connection::with_transport(
                    &mut conn,
                    &quiche::h3::Config::new().unwrap(),
                )
                .map_err(|e| format!("h3 setup: {e}"))?,
            );
        }

        if let Some(h3) = h3.as_mut() {
            if !sent {
                let request = [
                    quiche::h3::Header::new(b":method", b"GET"),
                    quiche::h3::Header::new(b":scheme", b"https"),
                    quiche::h3::Header::new(b":authority", b"h3.pingclair.test"),
                    quiche::h3::Header::new(b":path", path.as_bytes()),
                ];
                match h3.send_request(&mut conn, &request, true) {
                    Ok(_) => sent = true,
                    Err(quiche::h3::Error::StreamBlocked) => {}
                    Err(e) => return Err(format!("send_request: {e}")),
                }
            }

            loop {
                match h3.poll(&mut conn) {
                    Ok((_, quiche::h3::Event::Headers { list, .. })) => {
                        for header in &list {
                            if header.name() == b":status" {
                                status = String::from_utf8_lossy(header.value()).parse().ok();
                            }
                        }
                    }
                    Ok((stream_id, quiche::h3::Event::Data)) => {
                        let mut chunk = [0u8; 4096];
                        while let Ok(read) = h3.recv_body(&mut conn, stream_id, &mut chunk) {
                            if read == 0 {
                                break;
                            }
                            body.extend_from_slice(&chunk[..read]);
                        }
                    }
                    Ok((_, quiche::h3::Event::Finished)) => {
                        flush!();
                        return Ok(H3Response {
                            status: status.ok_or("finished without a :status")?,
                            body,
                        });
                    }
                    Ok((_, quiche::h3::Event::Reset(code))) => {
                        return Err(format!("stream reset with code {code}"));
                    }
                    Ok(_) => {}
                    Err(quiche::h3::Error::Done) => break,
                    Err(e) => return Err(format!("h3 poll: {e}")),
                }
            }
        }

        flush!();
    }
}

#[tokio::test]
async fn h3_serves_a_request_end_to_end() {
    let server = spawn_h3_server(HandlerConfig::Respond {
        status: 200,
        body: Some("hello over http/3".to_string()),
        headers: std::collections::BTreeMap::new(),
    })
    .await;

    let response = h3_get(server, "/hello")
        .await
        .expect("request should succeed");

    assert_eq!(response.status, 200);
    assert_eq!(
        String::from_utf8_lossy(&response.body),
        "hello over http/3",
        "the handler's body must arrive intact"
    );
}

#[tokio::test]
async fn h3_reuses_one_connection_for_several_requests() {
    // 🔁 A second request on the same connection proves stream state is torn
    // down per stream and not per connection.
    let server = spawn_h3_server(HandlerConfig::Respond {
        status: 200,
        body: Some("ok".to_string()),
        headers: std::collections::BTreeMap::new(),
    })
    .await;

    for attempt in 1..=3 {
        let response = h3_get(server, &format!("/attempt-{attempt}"))
            .await
            .unwrap_or_else(|e| panic!("request {attempt} failed: {e}"));
        assert_eq!(response.status, 200, "request {attempt}");
        assert_eq!(String::from_utf8_lossy(&response.body), "ok");
    }
}

#[tokio::test]
async fn h3_streams_a_body_larger_than_one_packet() {
    // 🌊 Exercises the flow-control path: pending body buffers plus writable
    // events, which is exactly what `process_writes` now drives.
    let payload = "x".repeat(512 * 1024);
    let server = spawn_h3_server(HandlerConfig::Respond {
        status: 200,
        body: Some(payload.clone()),
        headers: std::collections::BTreeMap::new(),
    })
    .await;

    let response = h3_get(server, "/large")
        .await
        .expect("request should succeed");

    assert_eq!(response.status, 200);
    assert_eq!(
        response.body.len(),
        payload.len(),
        "a 512 KiB body must stream back whole, not truncated at a packet boundary"
    );
    assert_eq!(response.body, payload.as_bytes());
}

// MARK: - Malformed HTTP/3 frames
//
// 🧨 RFC 9114 §7.1 gives each frame type a place it is allowed to appear. A
// frame in the wrong place is not a parse curiosity: a peer that tolerates it
// while the next hop does not is how two ends of a chain disagree about where a
// message ended. These drive raw bytes onto a request stream, because the point
// is to send what a well-behaved client library refuses to send.

/// Write raw bytes onto a fresh client-initiated bidirectional stream and
/// report how the server closed the connection.
async fn h3_raw_stream(server: SocketAddr, frame: &[u8]) -> Result<Option<u64>, String> {
    let mut config = quiche::Config::with_boring_ssl_ctx_builder(
        quiche::PROTOCOL_VERSION,
        boring::ssl::SslContextBuilder::new(boring::ssl::SslMethod::tls()).unwrap(),
    )
    .unwrap();
    config.verify_peer(false);
    config.set_application_protos(&[ALPN]).unwrap();
    config.set_max_idle_timeout(5_000);
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
    let mut conn = quiche::connect(Some("h3.pingclair.test"), &scid, local, server, &mut config)
        .map_err(|e| format!("connect: {e}"))?;

    let mut out = [0u8; 1350];
    let mut buf = [0u8; 65535];
    let mut sent = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);

    while let Ok((write, info)) = conn.send(&mut out) {
        socket.send_to(&out[..write], info.to).await.unwrap();
    }

    loop {
        if conn.is_closed() {
            // 🎯 The application error code the server chose is the assertion.
            return Ok(conn.peer_error().map(|error| error.error_code));
        }
        let timeout = conn
            .timeout()
            .unwrap_or(Duration::from_millis(20))
            .min(Duration::from_millis(100));

        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => return Err("timed out".to_string()),
            received = socket.recv_from(&mut buf) => {
                let (len, from) = received.unwrap();
                let info = quiche::RecvInfo { from, to: local };
                if conn.recv(&mut buf[..len], info).is_err() {
                    return Ok(conn.peer_error().map(|error| error.error_code));
                }
            }
            _ = tokio::time::sleep(timeout) => conn.on_timeout(),
        }

        if conn.is_established() && !sent {
            // 🧵 Stream 0 is the first client-initiated bidirectional stream, so
            // the server reads this as a request.
            let _ = conn.stream_send(0, frame, false);
            sent = true;
        }

        while let Ok((write, info)) = conn.send(&mut out) {
            socket.send_to(&out[..write], info.to).await.unwrap();
        }
    }
}

/// H3_FRAME_UNEXPECTED, from the error codes in RFC 9114 §8.1.
const H3_FRAME_UNEXPECTED: u64 = 0x0105;

#[tokio::test]
async fn h3_rejects_a_settings_frame_on_a_request_stream() {
    // 📕 RFC 9114 §7.2.4: SETTINGS belongs on the control stream only. Meeting
    // one on a request stream must be H3_FRAME_UNEXPECTED.
    let server = spawn_h3_server(HandlerConfig::Respond {
        status: 200,
        body: Some("ok".to_string()),
        headers: std::collections::BTreeMap::new(),
    })
    .await;

    // Frame type 0x04 (SETTINGS), length 0.
    let code = h3_raw_stream(server, &[0x04, 0x00])
        .await
        .expect("the server should close the connection rather than hang");

    assert_eq!(
        code,
        Some(H3_FRAME_UNEXPECTED),
        "a SETTINGS frame on a request stream must close the connection with H3_FRAME_UNEXPECTED"
    );
}

#[tokio::test]
async fn h3_rejects_a_data_frame_before_any_headers() {
    // 📕 RFC 9114 §4.1: a request begins with HEADERS. DATA arriving first has
    // no message to belong to.
    let server = spawn_h3_server(HandlerConfig::Respond {
        status: 200,
        body: Some("ok".to_string()),
        headers: std::collections::BTreeMap::new(),
    })
    .await;

    // Frame type 0x00 (DATA), length 3, payload "abc".
    let code = h3_raw_stream(server, &[0x00, 0x03, b'a', b'b', b'c'])
        .await
        .expect("the server should close the connection rather than hang");

    assert_eq!(
        code,
        Some(H3_FRAME_UNEXPECTED),
        "a DATA frame before HEADERS must close the connection with H3_FRAME_UNEXPECTED"
    );
}
