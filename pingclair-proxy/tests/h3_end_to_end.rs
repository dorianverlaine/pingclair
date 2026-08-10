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
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

/// 🧾 Reads one bounded HTTP/1 request head from a test upstream.
async fn read_http_head(stream: &mut tokio::net::TcpStream) -> String {
    use tokio::io::AsyncReadExt;

    let mut request = Vec::new();
    let mut chunk = [0u8; 1024];
    while request.len() < 64 * 1024 {
        let read = stream.read(&mut chunk).await.unwrap();
        if read == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8(request).unwrap()
}

/// 🧵 Starts one real FastCGI responder and returns its address plus observed environment.
async fn spawn_fastcgi_responder(
    status: u16,
    body: Vec<u8>,
) -> (
    SocketAddr,
    tokio::task::JoinHandle<std::collections::BTreeMap<String, String>>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut environment = std::collections::BTreeMap::new();
        loop {
            let mut record_header = [0u8; 8];
            stream.read_exact(&mut record_header).await.unwrap();
            let record_type = record_header[1];
            let content_length = u16::from_be_bytes([record_header[4], record_header[5]]) as usize;
            let padding = record_header[6] as usize;
            let mut content = vec![0u8; content_length];
            stream.read_exact(&mut content).await.unwrap();
            let mut discard = vec![0u8; padding];
            stream.read_exact(&mut discard).await.unwrap();
            if record_type == 4 && !content.is_empty() {
                let mut offset = 0;
                while offset < content.len() {
                    let name_length = read_fastcgi_size(&content, &mut offset);
                    let value_length = read_fastcgi_size(&content, &mut offset);
                    let name = String::from_utf8_lossy(
                        &content[offset..offset.saturating_add(name_length)],
                    )
                    .into_owned();
                    offset += name_length;
                    let value = String::from_utf8_lossy(
                        &content[offset..offset.saturating_add(value_length)],
                    )
                    .into_owned();
                    offset += value_length;
                    environment.insert(name, value);
                }
            }
            if record_type == 5 && content.is_empty() {
                break;
            }
        }

        let header = format!(
            "Status: {status}\r\nContent-Type: application/octet-stream\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n"
        );
        write_fastcgi_record(&mut stream, 6, header.as_bytes()).await;
        for chunk in body.chunks(65_000) {
            write_fastcgi_record(&mut stream, 6, chunk).await;
        }
        write_fastcgi_record(&mut stream, 6, &[]).await;
        let mut end_request = [0u8; 8];
        end_request[4] = 0;
        write_fastcgi_record(&mut stream, 3, &end_request).await;
        stream.shutdown().await.unwrap();
        environment
    });
    (address, task)
}

/// 🌊 Starts a responder whose second SSE record is deliberately delayed.
async fn spawn_slow_fastcgi_sse_responder() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        loop {
            let mut record_header = [0u8; 8];
            stream.read_exact(&mut record_header).await.unwrap();
            let record_type = record_header[1];
            let content_length = u16::from_be_bytes([record_header[4], record_header[5]]) as usize;
            let padding = record_header[6] as usize;
            let mut discard = vec![0u8; content_length + padding];
            stream.read_exact(&mut discard).await.unwrap();
            if record_type == 5 && content_length == 0 {
                break;
            }
        }
        write_fastcgi_record(
            &mut stream,
            6,
            b"Status: 200 OK\r\nContent-Type: text/event-stream\r\n\r\n",
        )
        .await;
        write_fastcgi_record(&mut stream, 6, b"data: first\n\n").await;
        tokio::time::sleep(Duration::from_millis(750)).await;
        write_fastcgi_record(&mut stream, 6, b"data: second\n\n").await;
        write_fastcgi_record(&mut stream, 6, &[]).await;
        let mut end_request = [0u8; 8];
        end_request[4] = 0;
        write_fastcgi_record(&mut stream, 3, &end_request).await;
        stream.shutdown().await.unwrap();
    });
    (address, task)
}

/// 📐 Reads one FastCGI name/value length from a PARAMS record.
fn read_fastcgi_size(content: &[u8], offset: &mut usize) -> usize {
    let first = content[*offset];
    if first & 0x80 == 0 {
        *offset += 1;
        first as usize
    } else {
        let value = u32::from_be_bytes([
            first,
            content[*offset + 1],
            content[*offset + 2],
            content[*offset + 3],
        ]);
        *offset += 4;
        (value & 0x7fff_ffff) as usize
    }
}

/// 📤 Writes one padded FastCGI record to the scripted responder socket.
async fn write_fastcgi_record(stream: &mut tokio::net::TcpStream, record_type: u8, content: &[u8]) {
    use tokio::io::AsyncWriteExt;

    let padding = (8 - content.len() % 8) % 8;
    let mut frame = Vec::with_capacity(8 + content.len() + padding);
    frame.push(1);
    frame.push(record_type);
    frame.extend_from_slice(&1u16.to_be_bytes());
    frame.extend_from_slice(&(content.len() as u16).to_be_bytes());
    frame.push(padding as u8);
    frame.push(0);
    frame.extend_from_slice(content);
    frame.resize(frame.len() + padding, 0);
    stream.write_all(&frame).await.unwrap();
}

/// Perform one HTTP/3 request and read the complete response.
///
/// A hand-driven client rather than a library one: this has to exercise the
/// server's own event loop, so the test must not depend on tokio-quiche's
/// client path being correct.
async fn h3_get(server: SocketAddr, path: &str) -> Result<H3Response, String> {
    h3_get_with_headers(server, path, &[]).await
}

/// 🔐 Performs an H3 GET with explicit client fields for middleware security tests.
async fn h3_get_with_headers(
    server: SocketAddr,
    path: &str,
    extra_headers: &[(&str, &str)],
) -> Result<H3Response, String> {
    h3_get_observing_first_chunk(server, path, extra_headers, None).await
}

/// 🌊 Performs an H3 request and optionally publishes its first body chunk.
async fn h3_get_observing_first_chunk(
    server: SocketAddr,
    path: &str,
    extra_headers: &[(&str, &str)],
    mut first_body_tx: Option<tokio::sync::oneshot::Sender<Vec<u8>>>,
) -> Result<H3Response, String> {
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
    config.set_initial_max_data(64 * 1024 * 1024);
    config.set_initial_max_stream_data_bidi_local(32 * 1024 * 1024);
    config.set_initial_max_stream_data_bidi_remote(32 * 1024 * 1024);
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
    let mut response_headers = Vec::new();
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
                let mut request = vec![
                    quiche::h3::Header::new(b":method", b"GET"),
                    quiche::h3::Header::new(b":scheme", b"https"),
                    quiche::h3::Header::new(b":authority", b"h3.pingclair.test"),
                    quiche::h3::Header::new(b":path", path.as_bytes()),
                ];
                request.extend(extra_headers.iter().map(|(name, value)| {
                    quiche::h3::Header::new(name.as_bytes(), value.as_bytes())
                }));
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
                            } else {
                                response_headers.push((
                                    String::from_utf8_lossy(header.name()).into_owned(),
                                    String::from_utf8_lossy(header.value()).into_owned(),
                                ));
                            }
                        }
                    }
                    Ok((stream_id, quiche::h3::Event::Data)) => {
                        let mut chunk = [0u8; 4096];
                        while let Ok(read) = h3.recv_body(&mut conn, stream_id, &mut chunk) {
                            if read == 0 {
                                break;
                            }
                            if let Some(sender) = first_body_tx.take() {
                                let _ = sender.send(chunk[..read].to_vec());
                            }
                            body.extend_from_slice(&chunk[..read]);
                        }
                    }
                    Ok((_, quiche::h3::Event::Finished)) => {
                        flush!();
                        return Ok(H3Response {
                            status: status.ok_or("finished without a :status")?,
                            headers: response_headers,
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

#[tokio::test]
async fn h3_forward_auth_mutates_the_backend_request_and_streams_denials() {
    use tokio::io::AsyncWriteExt;

    let auth_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let auth_address = auth_listener.local_addr().unwrap();
    let auth_task = tokio::spawn(async move {
        for expected_uri in ["/allow", "/deny"] {
            let (mut stream, _) = auth_listener.accept().await.unwrap();
            let request = read_http_head(&mut stream).await;
            let lower = request.to_ascii_lowercase();
            assert!(lower.starts_with("get /auth "));
            assert!(lower.contains("x-forwarded-method: get\r\n"));
            assert!(
                lower.contains(&format!("x-forwarded-uri: {expected_uri}\r\n")),
                "auth request did not preserve the original URI: {request}"
            );
            if expected_uri == "/allow" {
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nX-User: alice\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await
                    .unwrap();
            } else {
                let denial = vec![b'd'; 20 * 1024 * 1024];
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            denial.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
                stream.write_all(&denial).await.unwrap();
            }
        }
    });

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_address = backend_listener.local_addr().unwrap();
    let backend_task = tokio::spawn(async move {
        let (mut stream, _) = backend_listener.accept().await.unwrap();
        let request = read_http_head(&mut stream).await;
        assert!(
            request
                .lines()
                .any(|line| line.eq_ignore_ascii_case("X-Identity: alice")),
            "the backend did not receive the auth identity: {request}"
        );
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nauthorized",
            )
            .await
            .unwrap();
    });

    // 🧾 The real adapter must produce the same handler tree the H3 server executes.
    let source = format!(
        r#":443 {{
            intercept {{
                @denied status 403
                replace_status @denied 401
            }}
            forward_auth http://{auth_address} {{
                uri /auth
                copy_headers X-User>X-Identity
            }}
            reverse_proxy http://{backend_address}
        }}"#
    );
    let config = pingclair_config::compile(&source).unwrap();
    let handler = config.servers[0].routes[0].handler.clone();
    let server = spawn_h3_server(handler).await;

    let accepted = h3_get_with_headers(server, "/allow", &[("x-identity", "attacker")])
        .await
        .unwrap();
    assert_eq!(accepted.status, 200);
    assert_eq!(accepted.body, b"authorized");

    let denied = h3_get(server, "/deny").await.unwrap();
    assert_eq!(denied.status, 401);
    assert_eq!(denied.body.len(), 20 * 1024 * 1024);
    assert!(denied.body.iter().all(|byte| *byte == b'd'));

    auth_task.await.unwrap();
    backend_task.await.unwrap();
}

/// 🐘 HTTP/3 reaches the same FastCGI exchange and streams a 20 MiB response.
#[tokio::test]
async fn h3_fastcgi_streams_a_large_response_and_builds_h3_cgi_variables() {
    let body: Vec<u8> = (0..20 * 1024 * 1024)
        .map(|index| (index % 251) as u8)
        .collect();
    let (fastcgi_address, fastcgi_task) = spawn_fastcgi_responder(200, body.clone()).await;
    // 🧾 The real adapter must produce the FastCGI handler the QUIC server executes.
    let source = format!(
        r#":443 {{
            reverse_proxy {fastcgi_address} {{
                transport fastcgi {{
                    root /srv/www
                    split .php
                }}
                header_up X-Protocol h3
            }}
        }}"#
    );
    let config = pingclair_config::compile(&source).unwrap();
    let handler = config.servers[0].routes[0].handler.clone();
    let server = spawn_h3_server(handler).await;

    let response = h3_get(server, "/index.php/tail?item=1").await.unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.body, body);
    // 🍪 HTTP/3 must keep a repeated CGI header name as two fields, exactly
    // like H1/H2 does; collapsing them would silently drop a cookie.
    assert_eq!(
        response
            .headers
            .iter()
            .filter(|(name, _)| name == "set-cookie")
            .count(),
        2
    );

    let environment = fastcgi_task.await.unwrap();
    assert_eq!(
        environment.get("SERVER_PROTOCOL").map(String::as_str),
        Some("HTTP/3.0")
    );
    assert_eq!(
        environment.get("SCRIPT_FILENAME").map(String::as_str),
        Some("/srv/www/index.php")
    );
    assert_eq!(
        environment.get("PATH_INFO").map(String::as_str),
        Some("/tail")
    );
    assert_eq!(
        environment.get("REQUEST_URI").map(String::as_str),
        Some("/index.php/tail?item=1")
    );
    assert_eq!(
        environment.get("HTTP_X_PROTOCOL").map(String::as_str),
        Some("h3")
    );
}

/// 🧭 HTTP/3 evaluates FastCGI response handlers before committing CGI bytes.
#[tokio::test]
async fn h3_fastcgi_handle_response_streams_the_configured_error_file() {
    let (fastcgi_address, fastcgi_task) = spawn_fastcgi_responder(404, Vec::new()).await;
    let errors = tempfile::tempdir().unwrap();
    std::fs::write(errors.path().join("404.html"), "h3-fastcgi-error").unwrap();
    let errors = errors.path().to_string_lossy();
    // 🧾 This Pingclairfile drives adapter, matcher, response decision, and H3 runtime together.
    let source = format!(
        r#":443 {{
            reverse_proxy {fastcgi_address} {{
                transport fastcgi {{
                    root /srv/www
                    split .php
                }}
                @err status 4xx
                handle_response @err {{
                    root * {errors}
                    rewrite * /{{http.reverse_proxy.status_code}}.html
                    file_server
                }}
            }}
        }}"#
    );
    let config = pingclair_config::compile(&source).unwrap();
    let handler = config.servers[0].routes[0].handler.clone();
    let server = spawn_h3_server(handler).await;

    let response = h3_get(server, "/missing.php").await.unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"h3-fastcgi-error");
    fastcgi_task.await.unwrap();
}

/// 🌊 HTTP/3 exposes the first FastCGI SSE record before a later record exists.
#[tokio::test]
async fn h3_fastcgi_sends_the_first_sse_event_immediately() {
    let (fastcgi_address, fastcgi_task) = spawn_slow_fastcgi_sse_responder().await;
    // 🧾 The DSL carries immediate flushing through the FastCGI terminal path.
    let source = format!(
        r#":443 {{
            reverse_proxy {fastcgi_address} {{
                flush_interval -1
                transport fastcgi
            }}
        }}"#
    );
    let config = pingclair_config::compile(&source).unwrap();
    let handler = config.servers[0].routes[0].handler.clone();
    let server = spawn_h3_server(handler).await;
    let (first_tx, first_rx) = tokio::sync::oneshot::channel();
    let request = tokio::spawn(async move {
        h3_get_observing_first_chunk(server, "/events.php", &[], Some(first_tx)).await
    });

    let first = tokio::time::timeout(Duration::from_millis(400), first_rx)
        .await
        .expect("the first H3 SSE record must beat the responder delay")
        .unwrap();
    assert_eq!(first, b"data: first\n\n");
    let response = request.await.unwrap().unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"data: first\n\ndata: second\n\n");
    fastcgi_task.await.unwrap();
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
