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
use pingclair_proxy::client_auth::{ClientAuthTable, CompiledClientAuth, PublishedListenerPolicy};
use pingclair_proxy::quic::{CertTable, QuicServer};
use pingclair_proxy::server::PingclairProxy;
// 🔗 Through `tokio-quiche`, so the test client and the server under test are
// provably the same quiche. See the note in `quic.rs`.
use tokio_quiche::quiche;
use tokio_quiche::quiche::h3::NameValue;

const ALPN: &[u8] = b"h3";

fn self_signed_pem(names: &[&str]) -> (String, String) {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(names.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .unwrap();
    (cert.pem(), signing_key.serialize_pem())
}

/// Start an H3 server on an ephemeral port serving `handler` at `/*`.
async fn spawn_h3_server(handler: HandlerConfig) -> SocketAddr {
    spawn_h3_server_with(|address| ServerConfig {
        listen: vec![address.to_string()],
        routes: vec![RouteConfig {
            path: "/*".to_string(),
            handler,
            methods: None,
            matcher: None,
        }],
        ..Default::default()
    })
    .await
}

/// 🧾 Starts an H3 server from a whole `ServerConfig`, so a test can exercise
/// server-level settings such as `log` rather than only a route's handler.
///
/// The port is only known after binding, so the caller receives it and fills it
/// into the configuration it already compiled.
async fn spawn_h3_server_with(build: impl FnOnce(SocketAddr) -> ServerConfig) -> SocketAddr {
    spawn_h3_listener(|address| vec![build(address)], &["h3.pingclair.test"], None).await
}

/// 🎧 Starts one HTTP/3 listener carrying several sites, optionally demanding a
/// client certificate.
///
/// Several sites on one socket is the shape mutual TLS has to survive: SNI
/// decides what a client must prove and `:authority` decides which site it
/// reaches, so a listener with only one site cannot show whether those two are
/// held together.
async fn spawn_h3_listener(
    build: impl FnOnce(SocketAddr) -> Vec<ServerConfig>,
    certificate_names: &[&str],
    client_auth: Option<Arc<ClientAuthTable>>,
) -> SocketAddr {
    spawn_h3_listener_with_policy(build, certificate_names, client_auth)
        .await
        .0
}

/// 🔐 Starts an H3 listener and returns its shared publication handle.
async fn spawn_h3_listener_with_policy(
    build: impl FnOnce(SocketAddr) -> Vec<ServerConfig>,
    certificate_names: &[&str],
    client_auth: Option<Arc<ClientAuthTable>>,
) -> (SocketAddr, Arc<PublishedListenerPolicy>) {
    let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();

    // 🔌 Bind first so the test knows the port; `QuicServer` rebinds the same
    // address once this probe socket is dropped.
    let probe = std::net::UdpSocket::bind(listen).unwrap();
    let address = probe.local_addr().unwrap();
    drop(probe);

    let listener_policy = Arc::new(PublishedListenerPolicy::new(
        client_auth.unwrap_or_else(|| Arc::new(ClientAuthTable::default())),
    ));
    let proxy = PingclairProxy::with_published_listener_policy(Arc::clone(&listener_policy));
    proxy.update_config(build(address));

    let certs = Arc::new(CertTable::new());
    let (cert, key) = self_signed_pem(certificate_names);
    for name in certificate_names {
        certs.upsert_pem(name, &cert, &key).unwrap();
    }

    let server = QuicServer::new(address, Arc::new(proxy), certs, 8, Vec::new());
    tokio::spawn(async move {
        if let Err(e) = server.run().await {
            eprintln!("H3 server stopped: {e}");
        }
    });

    // 🕰️ The listener binds inside `run()`; give it a moment before probing.
    tokio::time::sleep(Duration::from_millis(200)).await;
    (address, listener_policy)
}

#[derive(Debug)]
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
    first_body_tx: Option<tokio::sync::oneshot::Sender<Vec<u8>>>,
) -> Result<H3Response, String> {
    h3_attempt(
        H3Attempt {
            server,
            path,
            extra_headers,
            ..H3Attempt::to(server, path)
        },
        first_body_tx,
    )
    .await
}

/// 🎛️ One HTTP/3 request, with everything a mutual-TLS test needs to vary.
///
/// The three fields beyond the ordinary ones exist because mutual TLS is
/// decided from things an HTTP client normally derives for you: `sni` is what
/// the handshake asks for, `authority` is what the request asks for, and
/// letting them differ is the whole point of the check being tested.
struct H3Attempt<'a> {
    server: SocketAddr,
    path: &'a str,
    /// 🏷️ The name sent in the ClientHello.
    sni: &'a str,
    /// 🏠 The `:authority` pseudo-header, which is what routing reads.
    authority: &'a str,
    extra_headers: &'a [(&'a str, &'a str)],
    /// 🪪 A client certificate and key, in PEM.
    identity: Option<(&'a str, &'a str)>,
    /// 🔤 The `:method` pseudo-header.
    method: &'a str,
    /// 📦 A request body, sent after the headers. Empty means the request
    /// finishes with its headers, which is what every GET here does.
    body: &'a [u8],
}

impl<'a> H3Attempt<'a> {
    /// 🧾 The ordinary request every other test in this file makes.
    fn to(server: SocketAddr, path: &'a str) -> Self {
        Self {
            server,
            path,
            sni: "h3.pingclair.test",
            authority: "h3.pingclair.test",
            extra_headers: &[],
            identity: None,
            method: "GET",
            body: &[],
        }
    }
}

/// 📦 Performs one HTTP/3 POST carrying a body of a known size.
///
/// Deliberately sends no `content-length`: HTTP/3 has no chunked encoding, so
/// a body without a declared length is the case where this proxy has to choose
/// the upstream framing itself — and that framing is what a buffering test can
/// actually see on the wire.
async fn h3_post(server: SocketAddr, path: &str, body: &[u8]) -> Result<H3Response, String> {
    h3_attempt(
        H3Attempt {
            method: "POST",
            body,
            ..H3Attempt::to(server, path)
        },
        None,
    )
    .await
}

async fn h3_attempt(
    attempt: H3Attempt<'_>,
    mut first_body_tx: Option<tokio::sync::oneshot::Sender<Vec<u8>>>,
) -> Result<H3Response, String> {
    let H3Attempt {
        server,
        path,
        sni,
        authority,
        extra_headers,
        identity,
        method,
        body: request_body,
    } = attempt;

    let mut ssl = boring::ssl::SslContextBuilder::new(boring::ssl::SslMethod::tls()).unwrap();
    if let Some((certificate_pem, key_pem)) = identity {
        let certificate =
            boring::x509::X509::from_pem(certificate_pem.as_bytes()).expect("client certificate");
        let key = boring::pkey::PKey::private_key_from_pem(key_pem.as_bytes())
            .expect("client private key");
        ssl.set_certificate(&certificate)
            .expect("set client certificate");
        ssl.set_private_key(&key).expect("set client key");
    }
    let mut config =
        quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, ssl).unwrap();
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

    let mut conn = quiche::connect(Some(sni), &scid, local, server, &mut config)
        .map_err(|e| format!("connect: {e}"))?;

    let mut out = [0u8; 1350];
    let mut buf = [0u8; 65535];
    let mut h3: Option<quiche::h3::Connection> = None;
    let mut sent = false;
    let mut request_stream: Option<u64> = None;
    let mut body_sent = 0usize;
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
                    quiche::h3::Header::new(b":method", method.as_bytes()),
                    quiche::h3::Header::new(b":scheme", b"https"),
                    quiche::h3::Header::new(b":authority", authority.as_bytes()),
                    quiche::h3::Header::new(b":path", path.as_bytes()),
                ];
                request.extend(extra_headers.iter().map(|(name, value)| {
                    quiche::h3::Header::new(name.as_bytes(), value.as_bytes())
                }));
                match h3.send_request(&mut conn, &request, request_body.is_empty()) {
                    Ok(id) => {
                        sent = true;
                        request_stream = Some(id);
                    }
                    Err(quiche::h3::Error::StreamBlocked) => {}
                    Err(e) => return Err(format!("send_request: {e}")),
                }
            }

            // 📦 A body is written across as many turns of this loop as the
            // stream's flow-control window needs, which is what makes it a
            // useful test subject: a large body genuinely arrives at the
            // server in several pieces, so a buffer that coalesces them is
            // visible on the upstream's wire and one that does not is too.
            if let Some(stream_id) = request_stream
                && body_sent < request_body.len()
            {
                match h3.send_body(&mut conn, stream_id, &request_body[body_sent..], true) {
                    Ok(written) => body_sent += written,
                    Err(quiche::h3::Error::Done) => {}
                    Err(e) => return Err(format!("send_body: {e}")),
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

/// 📊 The scrape endpoint answers over HTTP/3 with the same body and the same
/// media type it answers with over HTTP/1 and HTTP/2.
///
/// Worth its own test because the two transports are separate execution paths
/// here, and "implemented, but only on one protocol" is this codebase's most
/// repeated defect. A monitoring endpoint that silently disappears for
/// HTTP/3-capable scrapers is exactly the shape that goes unnoticed.
#[tokio::test]
async fn h3_metrics_directive_serves_the_same_scrape() {
    pingclair_proxy::metrics::init();
    let server = spawn_h3_server(HandlerConfig::Metrics {
        disable_openmetrics: false,
    })
    .await;

    let response = h3_get(server, "/metrics")
        .await
        .expect("request should succeed");

    assert_eq!(response.status, 200);
    assert_eq!(
        response
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
            .map(|(_, value)| value.as_str()),
        Some("text/plain; version=0.0.4; charset=utf-8"),
        "HTTP/3 must not invent a different media type for the same body"
    );
    let body = String::from_utf8_lossy(&response.body);
    // 🧭 A plain counter rather than one of the labelled families: the text
    // encoder omits a family that has no series yet, and in this in-process
    // test nothing has driven the labelled ones. Asserting on those would make
    // the test pass or fail on what else ran, not on the exporter.
    assert!(
        body.contains("# HELP pingclair_access_log_dropped_total")
            && body.contains("# TYPE pingclair_access_log_dropped_total counter")
            && body.contains("\npingclair_access_log_dropped_total 0"),
        "the exposition format must arrive intact — HELP, TYPE and sample; got {}",
        &body[..body.len().min(400)]
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

/// 🔁 A response header replacement runs on HTTP/3 too.
///
/// The two transports write response headers through different code — one
/// through Pingora's `ResponseHeader`, one by building a quiche header list —
/// so an operation added to the shared policy has to be applied twice, and the
/// second one is easy to forget. Both have to end at the same bytes.
#[tokio::test]
async fn h3_header_replace_rewrites_an_upstream_value() {
    use tokio::io::AsyncWriteExt;

    let backend_listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let backend_address = backend_listener.local_addr().unwrap();
    let backend_task = tokio::spawn(async move {
        let (mut stream, _) = backend_listener.accept().await.unwrap();
        let _ = read_http_head(&mut stream).await;
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nX-Backend: internal-host-7\r\nContent-Length: 2\r\n\
                  Connection: close\r\n\r\nok",
            )
            .await
            .unwrap();
    });

    let source = format!(
        r#":443 {{
            header X-Backend ^internal- external-
            reverse_proxy http://{backend_address}
        }}"#
    );
    let config = pingclair_config::compile(&source).unwrap();
    let handler = config.servers[0].routes[0].handler.clone();
    let server = spawn_h3_server(handler).await;

    let response = h3_get(server, "/probe").await.unwrap();
    assert_eq!(response.status, 200);
    let value = response
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("x-backend"))
        .map(|(_, value)| value.as_str());
    assert_eq!(
        value,
        Some("external-host-7"),
        "HTTP/3 must apply the same replacement as HTTP/1.1 and HTTP/2"
    );

    backend_task.await.unwrap();
}

/// 🔤🏷️ `method` and `request_header` change the upstream request on H3 too.
///
/// Both are request setters, and this repository has shipped two defects where
/// a setter ran on one transport and not the other — silently, because both
/// answered 200 and only the bytes differed. So the check is what the backend
/// received, not what the client got back.
#[tokio::test]
async fn h3_method_and_request_header_reach_the_upstream() {
    use tokio::io::AsyncWriteExt;

    let backend_listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let backend_address = backend_listener.local_addr().unwrap();
    let backend_task = tokio::spawn(async move {
        let (mut stream, _) = backend_listener.accept().await.unwrap();
        let request = read_http_head(&mut stream).await;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
        request
    });

    // 🧾 Through the real adapter, because the adapter is where the two
    // transports' handler trees could diverge in the first place.
    let source = format!(
        r#":443 {{
            method post
            request_header X-Set first
            request_header +X-Added second
            request_header -X-Dropped
            request_header X-Edit ^before$ after
            reverse_proxy http://{backend_address}
        }}"#
    );
    let config = pingclair_config::compile(&source).unwrap();
    let handler = config.servers[0].routes[0].handler.clone();
    let server = spawn_h3_server(handler).await;

    let response = h3_get_with_headers(
        server,
        "/probe",
        &[("x-dropped", "please-remove-me"), ("x-edit", "before")],
    )
    .await
    .unwrap();
    assert_eq!(response.status, 200);

    let request = backend_task.await.unwrap();
    let lines: Vec<&str> = request.lines().collect();
    assert!(
        lines[0].starts_with("POST "),
        "`method post` must reach the upstream upper-cased: {}",
        lines[0]
    );
    let has = |name: &str, value: &str| {
        lines
            .iter()
            .any(|line| line.eq_ignore_ascii_case(&format!("{name}: {value}")))
    };
    assert!(has("X-Set", "first"), "a set header must arrive: {request}");
    assert!(
        has("X-Added", "second"),
        "an added header must arrive: {request}"
    );
    assert!(
        !request.to_ascii_lowercase().contains("x-dropped"),
        "a removed header must not arrive: {request}"
    );
    assert!(
        has("X-Edit", "after"),
        "a replacement must rewrite the value the client sent: {request}"
    );
}

/// 🔪 `abort` writes nothing on H3 either — and takes only its own stream.
///
/// The transports must differ here, and the difference is the point. On
/// HTTP/1.1 the request and the connection are the same thing, so ending one
/// ends the other. An HTTP/3 connection carries other requests that did
/// nothing wrong, so `abort` resets one stream and leaves the rest alone.
#[tokio::test]
async fn h3_abort_resets_only_its_own_stream() {
    let source = r#":443 {
            @doomed path /doomed*
            abort @doomed
            respond "fine" 200
        }"#;
    // 🧾 The whole site, not one route: `abort @doomed` and the catch-all
    // `respond` compile to two routes, and mounting only the first would make
    // every request abort — which looks exactly like the defect this test is
    // supposed to catch.
    let compiled = pingclair_config::compile(source).unwrap();
    let site = compiled.servers[0].clone();
    let server = spawn_h3_server_with(|address| ServerConfig {
        listen: vec![address.to_string()],
        ..site
    })
    .await;

    let fine = h3_get(server, "/fine").await.unwrap();
    assert_eq!(fine.status, 200);
    assert_eq!(fine.body, b"fine");

    let aborted = h3_get(server, "/doomed").await;
    assert!(
        aborted.is_err(),
        "`abort` must produce no response at all; got {:?}",
        aborted.map(|response| response.status)
    );

    // 🧭 The listener and the rest of the server survive a reset stream: the
    // failure mode worth guarding against is an abort that takes the whole
    // connection, or the whole server, with it.
    let after = h3_get(server, "/fine").await.unwrap();
    assert_eq!(after.status, 200, "an abort must not poison the listener");
}

/// 🧾 Reads one whole chunked HTTP/1 request from a backend socket and returns
/// its body frames.
///
/// A chunk boundary is one write this proxy made, which is the only place a
/// buffering decision is visible: the request that arrives and the response
/// that leaves are byte-for-byte identical whether the body was held or not.
async fn read_chunked_request_frames(stream: &mut tokio::net::TcpStream) -> Vec<Vec<u8>> {
    use tokio::io::AsyncReadExt;

    let mut raw = Vec::new();
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        let read = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut chunk))
            .await
            .expect("the backend read stalled")
            .expect("the backend read failed");
        assert!(read > 0, "the request ended before its last chunk");
        raw.extend_from_slice(&chunk[..read]);
        if raw.ends_with(b"\r\n0\r\n\r\n") {
            break;
        }
    }

    let head_end = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("the request head must end")
        + 4;
    let mut rest = &raw[head_end..];
    let mut frames = Vec::new();
    loop {
        let line_end = rest
            .windows(2)
            .position(|window| window == b"\r\n")
            .expect("every chunk starts with a size line");
        let size = usize::from_str_radix(
            std::str::from_utf8(&rest[..line_end]).expect("a chunk size is ASCII"),
            16,
        )
        .expect("a chunk size is hexadecimal");
        rest = &rest[line_end + 2..];
        if size == 0 {
            break;
        }
        frames.push(rest[..size].to_vec());
        rest = &rest[size + 2..];
    }
    frames
}

/// 🧱 `request_buffers` holds the body on HTTP/3 too, and holds it the same way.
///
/// The two transports write the upstream request body through entirely
/// separate code — Pingora's filters on one side, this crate's own QUIC loop
/// on the other — so a setting implemented once is implemented on one
/// protocol. The observation is the backend's wire: a quarter-megabyte body
/// crosses several QUIC frames, and the buffered route must still hand the
/// backend a single chunk while the streaming route hands it several.
#[tokio::test]
async fn h3_request_buffers_hold_the_body_until_the_client_finishes() {
    use tokio::io::AsyncWriteExt;

    let backend_listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let backend_address = backend_listener.local_addr().unwrap();
    let backend_task = tokio::spawn(async move {
        let mut observed = Vec::new();
        for _ in 0..2 {
            let (mut stream, _) = backend_listener.accept().await.unwrap();
            observed.push(read_chunked_request_frames(&mut stream).await);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
        }
        observed
    });

    let source = format!(
        r#":443 {{
            handle /buffered/* {{
                reverse_proxy http://{backend_address} {{
                    request_buffers unlimited
                }}
            }}

            reverse_proxy http://{backend_address}
        }}"#
    );
    let site = pingclair_config::compile(&source).unwrap().servers[0].clone();
    let server = spawn_h3_server_with(|address| ServerConfig {
        listen: vec![address.to_string()],
        ..site
    })
    .await;

    let body = vec![b'x'; 256 * 1024];
    for path in ["/buffered/upload", "/streamed/upload"] {
        let response = h3_post(server, path, &body).await.unwrap();
        assert_eq!(response.status, 200, "the proxied POST must succeed");
    }

    let observed = backend_task.await.unwrap();
    assert_eq!(
        observed[0].len(),
        1,
        "`request_buffers` must hand the backend one chunk, saw {} on HTTP/3",
        observed[0].len()
    );
    assert_eq!(
        observed[0][0].len(),
        body.len(),
        "the buffered chunk must be the whole body"
    );
    assert!(
        observed[1].len() > 1,
        "without buffering the backend must see the stream as it arrived, saw {} chunk(s)",
        observed[1].len()
    );
    assert_eq!(
        observed[1].iter().map(Vec::len).sum::<usize>(),
        body.len(),
        "streaming must deliver the same number of bytes"
    );
}

/// 🧱 `response_buffers` holds the backend's body on HTTP/3 too.
///
/// The backend writes half its body, pauses, then writes the rest. What the
/// client eventually receives is identical either way, so the assertion is on
/// the *first* body chunk the client sees: buffered, it already contains both
/// halves; streaming, it contains only the first.
#[tokio::test]
async fn h3_response_buffers_hold_the_body_until_the_upstream_finishes() {
    use tokio::io::AsyncWriteExt;

    let backend_listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let backend_address = backend_listener.local_addr().unwrap();
    let backend_task = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) = backend_listener.accept().await.unwrap();
            let _ = read_http_head(&mut stream).await;
            // 📏 No `Content-Length`: the body ends with the connection, which
            // is what lets the backend pause in the middle of one.
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\
                      Connection: close\r\n\r\nfirst",
                )
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(600)).await;
            stream.write_all(b"second").await.unwrap();
            stream.shutdown().await.unwrap();
        }
    });

    let source = format!(
        r#":443 {{
            handle /buffered/* {{
                reverse_proxy http://{backend_address} {{
                    response_buffers unlimited
                }}
            }}

            reverse_proxy http://{backend_address}
        }}"#
    );
    let site = pingclair_config::compile(&source).unwrap().servers[0].clone();
    let server = spawn_h3_server_with(|address| ServerConfig {
        listen: vec![address.to_string()],
        ..site
    })
    .await;

    let first_chunk_of = |path: &'static str| async move {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let response = h3_get_observing_first_chunk(server, path, &[], Some(tx))
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"firstsecond", "the whole body must arrive");
        rx.await.expect("a body chunk must have been observed")
    };

    assert_eq!(
        first_chunk_of("/streamed/probe").await,
        b"first".to_vec(),
        "without buffering the client must see the first half before the second exists"
    );
    assert_eq!(
        first_chunk_of("/buffered/probe").await,
        b"firstsecond".to_vec(),
        "`response_buffers` must withhold the body until the backend finishes"
    );

    backend_task.await.unwrap();
}

/// 🔻 A backend that refuses the connection must still fail closed on H3.
///
/// This is the other half of the local/remote split introduced in
/// `pingclair_proxy::upstream_failure`. That change makes the proxy stop
/// blaming a backend for failures this process caused — and the way to get
/// that wrong is to stop blaming the backend for anything, which would silently
/// disable passive health checking and failover on a transport whose tests
/// nobody runs by hand.
///
/// ⚠️ The matching **local**-failure case is not tested here, and that is a
/// known gap rather than an oversight: driving a real descriptor exhaustion
/// needs `setrlimit`, and these tests run the H3 server *in process*, so
/// lowering the limit would poison every other test in this binary. The local
/// path is covered by `upstream_failure`'s unit tests and by
/// `test_local_descriptor_exhaustion_does_not_mark_the_backend_down` in
/// `pingclair/tests/integration.rs`, which spawns the real binary and proves
/// the error shape that both transports receive from the shared connector.
/// Recorded in TRIAGE.
#[tokio::test]
async fn h3_refused_backend_still_fails_closed() {
    // 🚪 Bind and immediately drop, so the address is real, local, and closed.
    // Nothing is listening, so `connect()` gets `ECONNREFUSED` — a genuine
    // remote failure rather than a local one.
    let dead_address = {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        listener.local_addr().unwrap()
    };

    let source = format!(
        r#":443 {{
            reverse_proxy http://{dead_address}
        }}"#
    );
    let config = pingclair_config::compile(&source).unwrap();
    let handler = config.servers[0].routes[0].handler.clone();
    let server = spawn_h3_server(handler).await;

    let refused = h3_get(server, "/anything").await.unwrap();
    assert_eq!(
        refused.status, 502,
        "a refused backend is the backend's failure and must still surface as \
         a bad gateway"
    );
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

/// 🧾 HTTP/3 traffic reaches the access log, and reaches the right destination.
///
/// Before this, `quic.rs` contained no reference to access logging at all: a
/// site that turned HTTP/3 on stopped producing records for that share of its
/// traffic without saying so. The assertions below are the two halves that
/// matter — the record exists, and `hostnames` narrowed it the same way it does
/// on HTTP/1.1.
#[tokio::test]
async fn h3_requests_reach_the_access_log_selected_by_hostnames() {
    let dir = tempfile::tempdir().unwrap();
    let matching = dir.path().join("match.log");
    let other = dir.path().join("other.log");

    // 🧾 Written in the DSL so the adapter compiles it, exactly as a user's
    // configuration would be.
    let source = format!(
        r#"h3.pingclair.test {{
            log wanted {{
                hostnames h3.pingclair.test
                output file {}
                format json
            }}
            log unwanted {{
                hostnames somewhere.else
                output file {}
                format json
            }}
            respond "logged" 200
        }}"#,
        matching.display(),
        other.display()
    );
    let compiled = pingclair_config::compile(&source).expect("the log block compiles");
    let template = compiled.servers[0].clone();

    let server = spawn_h3_server_with(move |address| ServerConfig {
        listen: vec![address.to_string()],
        ..template
    })
    .await;

    let response = h3_get(server, "/logged?token=secret").await.unwrap();
    assert_eq!(response.status, 200);

    // 🕰️ The writer thread owns the sink, so the line is queued rather than
    // written before the response returns.
    let mut recorded = String::new();
    for _ in 0..50 {
        recorded = std::fs::read_to_string(&matching).unwrap_or_default();
        if recorded.contains("HTTP/3") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    assert!(
        recorded.contains("HTTP/3"),
        "the HTTP/3 request produced no access record: {recorded:?}"
    );
    assert!(
        recorded.contains("\"status\":200"),
        "the record must carry the status the client saw: {recorded:?}"
    );
    assert!(
        !recorded.contains("secret"),
        "the query string must be redacted before it reaches the log: {recorded:?}"
    );
    assert!(
        std::fs::read_to_string(&other)
            .unwrap_or_default()
            .is_empty(),
        "a logger scoped to another hostname must stay empty"
    );
}

// MARK: - Mutual TLS (K4): HTTP/3 gives the same answer as HTTP/1.1 and HTTP/2

/// 🏛️ A throwaway CA and the leaves it signs.
///
/// The second authority in each test matters as much as the first: a client
/// certificate the server was never told about is the only way to tell a trust
/// pool that is consulted from one that is merely configured.
struct H3Authority {
    ca_pem: String,
    params: rcgen::CertificateParams,
    key: rcgen::KeyPair,
}

impl H3Authority {
    fn new(common_name: &str) -> Self {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("ca params");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, common_name);
        let key = rcgen::KeyPair::generate().expect("ca key");
        let ca_pem = params.self_signed(&key).expect("ca certificate").pem();
        Self {
            ca_pem,
            params,
            key,
        }
    }

    fn issue(&self, name: &str) -> (String, String) {
        let mut params =
            rcgen::CertificateParams::new(vec![name.to_string()]).expect("leaf params");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        let key = rcgen::KeyPair::generate().expect("leaf key");
        let certificate = params
            .signed_by(&key, &rcgen::Issuer::from_params(&self.params, &self.key))
            .expect("leaf certificate");
        (certificate.pem(), key.serialize_pem())
    }
}

/// 🚫 Asserts the connection was refused *by TLS*, not merely that it failed.
///
/// `is_err()` on its own would also pass if the server crashed, if the port
/// were wrong, or if the request timed out — three failures that have nothing
/// to do with client certificates. A refused handshake shows up as the peer
/// closing the connection, so that is what gets asserted; a timeout would mean
/// the test proved nothing.
fn assert_handshake_refused(outcome: Result<H3Response, String>, what_went_wrong: &str) {
    match outcome {
        Ok(response) => panic!("{what_went_wrong}: answered {}", response.status),
        Err(error) => assert!(
            error.starts_with("connection closed"),
            "{what_went_wrong}. The connection did fail, but not as a rejected handshake, so this \
             run proves nothing: {error}"
        ),
    }
}

/// 🧾 An HTTP/3 listener with one mutual-TLS site beside one ordinary site.
async fn spawn_h3_mtls_listener(
    mode: pingclair_core::config::ClientAuthMode,
    ca_pem: &str,
) -> (SocketAddr, tempfile::TempDir) {
    use pingclair_core::config::{ClientAuthConfig, TrustPool};

    let material = tempfile::tempdir().expect("trust material dir");
    let ca_path = material.path().join("client-ca.pem");
    std::fs::write(&ca_path, ca_pem).expect("write client CA");

    let policy = Arc::new(
        CompiledClientAuth::compile(&ClientAuthConfig {
            mode,
            trust_pool: Some(TrustPool::File {
                pem_files: vec![ca_path.to_string_lossy().into_owned()],
            }),
            ..Default::default()
        })
        .expect("the trust pool compiles"),
    );
    let mut table = ClientAuthTable::default();
    table.insert(&["secure.h3.test"], policy);

    let address = spawn_h3_listener(
        |address| {
            let route = |body: &str| RouteConfig {
                path: "/*".to_string(),
                handler: HandlerConfig::Respond {
                    status: 200,
                    body: Some(body.to_string()),
                    headers: Default::default(),
                },
                methods: None,
                matcher: None,
            };
            vec![
                ServerConfig {
                    name: Some("open.h3.test".to_string()),
                    listen: vec![address.to_string()],
                    routes: vec![route("open-ok")],
                    ..Default::default()
                },
                ServerConfig {
                    name: Some("secure.h3.test".to_string()),
                    listen: vec![address.to_string()],
                    routes: vec![route("secure-ok")],
                    ..Default::default()
                },
            ]
        },
        &["open.h3.test", "secure.h3.test"],
        Some(Arc::new(table)),
    )
    .await;
    (address, material)
}

/// 🪪 `require_and_verify` has to mean the same thing over QUIC.
///
/// The point of doing this at all: HTTP/1.1 and HTTP/2 go through Pingora's
/// acceptor while HTTP/3 goes through `tokio-quiche`, two separate TLS setups.
/// A policy enforced on only one of them is a policy any client opts out of by
/// choosing the other transport — and `Alt-Svc` invites them to.
#[tokio::test]
async fn h3_client_auth_admits_only_the_trusted_client() {
    let authority = H3Authority::new("H3 Client CA");
    let stranger = H3Authority::new("Somebody Else's CA");
    let (address, _material) = spawn_h3_mtls_listener(
        pingclair_core::config::ClientAuthMode::RequireAndVerify,
        &authority.ca_pem,
    )
    .await;
    let trusted = authority.issue("client.h3.test");
    let foreign = stranger.issue("client.h3.test");

    let trusted_ref: (&str, &str) = (&trusted.0, &trusted.1);
    let foreign_ref: (&str, &str) = (&foreign.0, &foreign.1);

    let no_certificate = h3_attempt(
        H3Attempt {
            sni: "secure.h3.test",
            authority: "secure.h3.test",
            ..H3Attempt::to(address, "/probe")
        },
        None,
    )
    .await;
    assert_handshake_refused(
        no_certificate,
        "a client with no certificate completed an HTTP/3 handshake to a site that requires one",
    );

    let untrusted = h3_attempt(
        H3Attempt {
            sni: "secure.h3.test",
            authority: "secure.h3.test",
            identity: Some(foreign_ref),
            ..H3Attempt::to(address, "/probe")
        },
        None,
    )
    .await;
    assert_handshake_refused(
        untrusted,
        "a certificate from an untrusted CA was accepted over HTTP/3; the trust pool is not being \
         consulted",
    );

    let admitted = h3_attempt(
        H3Attempt {
            sni: "secure.h3.test",
            authority: "secure.h3.test",
            identity: Some(trusted_ref),
            ..H3Attempt::to(address, "/probe")
        },
        None,
    )
    .await
    .expect("the client holding a certificate from the configured CA was turned away");
    assert_eq!(admitted.status, 200);
    assert_eq!(admitted.body, b"secure-ok");

    // 🌐 The ordinary site sharing the socket must stay ordinary.
    let open = h3_attempt(
        H3Attempt {
            sni: "open.h3.test",
            authority: "open.h3.test",
            ..H3Attempt::to(address, "/probe")
        },
        None,
    )
    .await
    .expect("a site without client_auth started demanding certificates over HTTP/3");
    assert_eq!(open.status, 200);
    assert_eq!(open.body, b"open-ok");
}

/// 🔄 A published H3 trust-pool rotation applies to the first new handshake.
#[tokio::test]
async fn h3_client_auth_ca_rotation_rejects_the_previous_authority() {
    use pingclair_core::config::{ClientAuthConfig, ClientAuthMode, TrustPool};

    let first = H3Authority::new("First H3 Client CA");
    let second = H3Authority::new("Second H3 Client CA");
    let material = tempfile::tempdir().expect("trust material dir");
    let first_path = material.path().join("first.pem");
    let second_path = material.path().join("second.pem");
    std::fs::write(&first_path, &first.ca_pem).unwrap();
    std::fs::write(&second_path, &second.ca_pem).unwrap();
    let table_for = |path: &std::path::Path| {
        let compiled = Arc::new(
            CompiledClientAuth::compile(&ClientAuthConfig {
                mode: ClientAuthMode::RequireAndVerify,
                trust_pool: Some(TrustPool::File {
                    pem_files: vec![path.to_string_lossy().into_owned()],
                }),
                ..Default::default()
            })
            .unwrap(),
        );
        let mut table = ClientAuthTable::default();
        table.insert(&["secure.h3.test"], compiled);
        Arc::new(table)
    };
    let (address, listener_policy) = spawn_h3_listener_with_policy(
        |address| {
            vec![ServerConfig {
                name: Some("secure.h3.test".to_string()),
                listen: vec![address.to_string()],
                routes: vec![RouteConfig {
                    path: "/*".to_string(),
                    handler: HandlerConfig::Respond {
                        status: 200,
                        body: Some("secure-ok".to_string()),
                        headers: Default::default(),
                    },
                    methods: None,
                    matcher: None,
                }],
                ..Default::default()
            }]
        },
        &["secure.h3.test"],
        Some(table_for(&first_path)),
    )
    .await;
    let first_identity = first.issue("client.h3.test");
    let second_identity = second.issue("client.h3.test");
    fn attempt<'a>(address: SocketAddr, identity: (&'a str, &'a str)) -> H3Attempt<'a> {
        H3Attempt {
            sni: "secure.h3.test",
            authority: "secure.h3.test",
            identity: Some(identity),
            ..H3Attempt::to(address, "/probe")
        }
    }
    assert_eq!(
        h3_attempt(
            attempt(address, (&first_identity.0, &first_identity.1)),
            None,
        )
        .await
        .unwrap()
        .status,
        200
    );
    assert_handshake_refused(
        h3_attempt(
            attempt(address, (&second_identity.0, &second_identity.1)),
            None,
        )
        .await,
        "the not-yet-trusted H3 client was accepted before rotation",
    );

    listener_policy.begin_publish();
    listener_policy.publish_client_auth(table_for(&second_path));
    listener_policy.finish_publish();

    assert_handshake_refused(
        h3_attempt(
            attempt(address, (&first_identity.0, &first_identity.1)),
            None,
        )
        .await,
        "the old H3 client CA remained trusted after publication",
    );
    assert_eq!(
        h3_attempt(
            attempt(address, (&second_identity.0, &second_identity.1)),
            None,
        )
        .await
        .unwrap()
        .status,
        200
    );
}

/// 🛡️ SNI and `:authority` must name the same site, exactly as `Host` must on
/// the TCP listener.
///
/// Without this the HTTP/3 socket would be the easy way around mutual TLS:
/// handshake as the site that demands nothing, then ask for the site that
/// demands a certificate.
#[tokio::test]
async fn h3_client_auth_refuses_an_authority_the_handshake_did_not_name() {
    let authority = H3Authority::new("H3 Client CA");
    let (address, _material) = spawn_h3_mtls_listener(
        pingclair_core::config::ClientAuthMode::RequireAndVerify,
        &authority.ca_pem,
    )
    .await;
    let (trusted_cert, trusted_key) = authority.issue("client.h3.test");

    let smuggled = h3_attempt(
        H3Attempt {
            sni: "open.h3.test",
            authority: "secure.h3.test",
            ..H3Attempt::to(address, "/probe")
        },
        None,
    )
    .await
    .expect("the request should be answered, not dropped");
    assert_eq!(
        smuggled.status, 421,
        "an HTTP/3 request reached a mutual-TLS site by naming a different site in its handshake"
    );

    // 🚫 Holding a valid certificate does not excuse the mismatch either;
    // otherwise the check would only stop the attacker who forgot to bring one.
    let smuggled_with_certificate = h3_attempt(
        H3Attempt {
            sni: "open.h3.test",
            authority: "secure.h3.test",
            identity: Some((&trusted_cert, &trusted_key)),
            ..H3Attempt::to(address, "/probe")
        },
        None,
    )
    .await
    .expect("the request should be answered, not dropped");
    assert_eq!(smuggled_with_certificate.status, 421);

    // 👍 Naming the same site in both places is ordinary traffic.
    let honest = h3_attempt(
        H3Attempt {
            sni: "open.h3.test",
            authority: "open.h3.test",
            ..H3Attempt::to(address, "/probe")
        },
        None,
    )
    .await
    .expect("an honest request was refused");
    assert_eq!(honest.status, 200);
}

/// 🔍 `verify_if_given` over QUIC: admit the empty-handed client, refuse the
/// one whose certificate does not chain to the trust pool.
#[tokio::test]
async fn h3_client_auth_verify_if_given_checks_only_what_is_offered() {
    let authority = H3Authority::new("H3 Client CA");
    let stranger = H3Authority::new("Somebody Else's CA");
    let (address, _material) = spawn_h3_mtls_listener(
        pingclair_core::config::ClientAuthMode::VerifyIfGiven,
        &authority.ca_pem,
    )
    .await;
    let (foreign_cert, foreign_key) = stranger.issue("client.h3.test");

    let empty_handed = h3_attempt(
        H3Attempt {
            sni: "secure.h3.test",
            authority: "secure.h3.test",
            ..H3Attempt::to(address, "/probe")
        },
        None,
    )
    .await
    .expect("`verify_if_given` must admit a client that offers no certificate");
    assert_eq!(empty_handed.status, 200);

    let untrusted = h3_attempt(
        H3Attempt {
            sni: "secure.h3.test",
            authority: "secure.h3.test",
            identity: Some((&foreign_cert, &foreign_key)),
            ..H3Attempt::to(address, "/probe")
        },
        None,
    )
    .await;
    assert_handshake_refused(
        untrusted,
        "`verify_if_given` verified nothing over HTTP/3: an untrusted certificate was accepted",
    );
}

/// 🎫 Attempts two QUIC handshakes, reusing the first one's session on the
/// second, and reports whether the second actually resumed.
///
/// Deliberately raw rather than layered on `h3_attempt`: what is being measured
/// is a property of the handshake, and everything HTTP would only be noise.
async fn h3_session_resumes(server: SocketAddr, sni: &str) -> bool {
    async fn handshake(
        server: SocketAddr,
        sni: &str,
        session: Option<Vec<u8>>,
    ) -> (bool, Option<Vec<u8>>) {
        let ssl = boring::ssl::SslContextBuilder::new(boring::ssl::SslMethod::tls()).unwrap();
        let mut config =
            quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, ssl).unwrap();
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
        let mut conn =
            quiche::connect(Some(sni), &scid, local, server, &mut config).expect("connect");
        if let Some(session) = &session {
            conn.set_session(session)
                .expect("install the saved session");
        }

        let mut out = [0u8; 1350];
        let mut buf = [0u8; 65535];
        // ⏳ Long enough for the server's NewSessionTicket, which arrives after
        // the handshake completes rather than as part of it.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        loop {
            while let Ok((write, info)) = conn.send(&mut out) {
                socket.send_to(&out[..write], info.to).await.unwrap();
            }
            if conn.is_closed() {
                return (false, None);
            }
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => break,
                received = socket.recv_from(&mut buf) => {
                    let (len, from) = received.unwrap();
                    let info = quiche::RecvInfo { from, to: local };
                    let _ = conn.recv(&mut buf[..len], info);
                }
                _ = tokio::time::sleep(Duration::from_millis(50)) => conn.on_timeout(),
            }
            if conn.is_established() && (session.is_some() || conn.session().is_some()) {
                break;
            }
        }
        (conn.is_resumed(), conn.session().map(<[u8]>::to_vec))
    }

    let (_, saved) = handshake(server, sni, None).await;
    let Some(saved) = saved else {
        // 🎫 No ticket was ever issued, so there is nothing to resume with.
        return false;
    };
    handshake(server, sni, Some(saved)).await.0
}

/// 🚫 A mutual-TLS listener must not resume a TLS session.
///
/// A resumed TLS 1.3 handshake carries no `CertificateRequest`: BoringSSL
/// restores the peer's chain from the ticket and never re-checks it, so a
/// ticket would keep admitting its holder after the certificate behind it
/// expired or the trust pool changed.
///
/// 🎯 The control is the whole test. Asserting only "the mutual-TLS listener
/// did not resume" would pass just as happily if this harness could never
/// resume anything — so the ordinary listener has to resume first, in the same
/// process, through the same code.
#[tokio::test]
async fn h3_client_auth_turns_session_resumption_off() {
    let ordinary = spawn_h3_server(HandlerConfig::Respond {
        status: 200,
        body: Some("ok".to_string()),
        headers: Default::default(),
    })
    .await;
    assert!(
        h3_session_resumes(ordinary, "h3.pingclair.test").await,
        "this harness cannot resume a session even against an ordinary listener, so it cannot \
         show that a mutual-TLS listener refuses to"
    );

    let authority = H3Authority::new("H3 Client CA");
    let (mtls, _material) = spawn_h3_mtls_listener(
        pingclair_core::config::ClientAuthMode::VerifyIfGiven,
        &authority.ca_pem,
    )
    .await;
    assert!(
        !h3_session_resumes(mtls, "secure.h3.test").await,
        "a mutual-TLS listener resumed a TLS session; a resumed handshake asks for no certificate, \
         so the ticket outlives the policy that issued it"
    );
}

/// 🗂️ `try_files` gives HTTP/3 the same answer it gives HTTP/1.1 and HTTP/2,
/// including the `=code` candidate that raises a status rather than matching.
///
/// 🤡 The parity gap this pins, fixed 2026-08-11: H3 evaluated a pipeline
/// element's matcher through a *boolean* helper, so the `file` matcher's
/// `Error` verdict collapsed to no-match. The same site therefore answered 404
/// over HTTP/2 and fell through to the next handler over HTTP/3 — a difference
/// nothing in the configuration expressed. It was unreachable from the DSL
/// until `try_files` started expanding into that matcher, and reachable
/// through a `php_fastcgi` expansion before that.
#[tokio::test]
async fn h3_try_files_falls_back_and_raises_a_status_code_candidate() {
    let tree = tempfile::tempdir().expect("document root");
    std::fs::write(tree.path().join("index.html"), b"shell").expect("write shell");
    let root = tree.path().to_string_lossy().into_owned();

    // 🧾 The real adapter must produce the handler the QUIC server executes:
    // a JSON handler here would skip the expansion under test.
    let source = format!(
        r#":443 {{
            root * {root}
            route /strict/* {{
                try_files {{path}} =410
                file_server
            }}
            route {{
                try_files {{path}} /index.html
                file_server
            }}
        }}"#
    );
    let config = pingclair_config::compile(&source).expect("the try_files site compiles");
    // 🧭 The whole server, not one route: the two `route` blocks compile to two
    // routes, and taking only the first would silently test the wrong one.
    let compiled = config.servers[0].clone();
    let server = spawn_h3_server_with(|address| ServerConfig {
        listen: vec![address.to_string()],
        // 🎧 The listener's certificate names the host, and the site must be
        // the catch-all that answers it — the same shape `spawn_h3_server`
        // builds for the single-handler tests.
        name: None,
        names: Vec::new(),
        ..compiled
    })
    .await;

    // 🎯 The ordinary fallback: no file behind the route, so the shell answers.
    let shell = h3_get(server, "/client/route")
        .await
        .expect("request should succeed");
    assert_eq!(shell.status, 200);
    assert_eq!(String::from_utf8_lossy(&shell.body), "shell");

    // 🎯 A real file is served as itself rather than hijacked to the shell.
    let real = h3_get(server, "/index.html")
        .await
        .expect("request should succeed");
    assert_eq!(real.status, 200);
    assert_eq!(String::from_utf8_lossy(&real.body), "shell");

    // 🎯 `=410` raises. The status is deliberately one the file server would
    // never produce on its own: with `=404` this assertion would pass whether
    // the candidate raised or the file server simply failed to find the file,
    // which is exactly the difference under test.
    let strict = h3_get(server, "/strict/missing")
        .await
        .expect("request should succeed");
    assert_eq!(
        strict.status, 410,
        "`=410` must raise on HTTP/3 exactly as it does on HTTP/1.1 and HTTP/2"
    );
}
