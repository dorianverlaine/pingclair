//! 🧾 `max_header_bytes` over HTTP/3: an oversized request is refused on its
//! own stream with a 431 that names the field, and the connection it shares
//! with other requests survives.

use std::collections::HashMap;

use super::*;

/// 🧾 A site whose request header section may total at most 1 KiB, written
/// as a Pingclairfile so the DSL spelling of the limit is what gets tested.
const HEADER_LIMITED_SITE: &str = r#"
:443 {
    limits {
        max_header_bytes 1024
    }
    respond "admitted"
}
"#;

/// 🔀 Sends every request on one QUIC connection at once and reads each
/// response by its stream.
///
/// The single-request client in the parent module opens a connection per
/// request, which cannot show whether one request's failure took its
/// neighbours down with it. That is exactly what this file is about.
async fn h3_concurrent_gets(
    server: SocketAddr,
    requests: &[&[(&str, &str)]],
) -> Result<Vec<H3Response>, String> {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
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
    let mut next_request = 0;
    // 🧭 Stream id to request index, and each request's partial response.
    let mut stream_index = HashMap::new();
    let mut responses: Vec<Option<H3Response>> = requests.iter().map(|_| None).collect();
    let mut partial: HashMap<u64, H3Response> = HashMap::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);

    loop {
        while let Ok((write, info)) = conn.send(&mut out) {
            socket.send_to(&out[..write], info.to).await.unwrap();
        }
        if responses.iter().all(Option::is_some) {
            return Ok(responses.into_iter().map(Option::unwrap).collect());
        }
        if conn.is_closed() {
            return Err(format!("connection closed: {:?}", conn.peer_error()));
        }
        let timeout = conn
            .timeout()
            .unwrap_or(Duration::from_millis(20))
            .min(Duration::from_millis(100));
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => return Err("timed out".to_string()),
            received = socket.recv_from(&mut buf) => {
                let (len, from) = received.unwrap();
                conn.recv(&mut buf[..len], quiche::RecvInfo { from, to: local })
                    .map_err(|e| format!("recv: {e}"))?;
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
        let Some(h3) = h3.as_mut() else { continue };
        while next_request < requests.len() {
            let mut fields = vec![
                quiche::h3::Header::new(b":method", b"GET"),
                quiche::h3::Header::new(b":scheme", b"https"),
                quiche::h3::Header::new(b":authority", b"h3.pingclair.test"),
                quiche::h3::Header::new(b":path", b"/"),
            ];
            fields.extend(
                requests[next_request].iter().map(|(name, value)| {
                    quiche::h3::Header::new(name.as_bytes(), value.as_bytes())
                }),
            );
            match h3.send_request(&mut conn, &fields, true) {
                Ok(id) => {
                    stream_index.insert(id, next_request);
                    next_request += 1;
                }
                Err(quiche::h3::Error::StreamBlocked) => break,
                Err(e) => return Err(format!("send_request: {e}")),
            }
        }
        loop {
            match h3.poll(&mut conn) {
                Ok((id, quiche::h3::Event::Headers { list, .. })) => {
                    let response = partial.entry(id).or_insert(H3Response {
                        status: 0,
                        headers: Vec::new(),
                        body: Vec::new(),
                    });
                    for field in &list {
                        if field.name() == b":status" {
                            response.status =
                                String::from_utf8_lossy(field.value()).parse().unwrap_or(0);
                        } else {
                            response.headers.push((
                                String::from_utf8_lossy(field.name()).into_owned(),
                                String::from_utf8_lossy(field.value()).into_owned(),
                            ));
                        }
                    }
                }
                Ok((id, quiche::h3::Event::Data)) => {
                    let mut chunk = [0u8; 4096];
                    while let Ok(read) = h3.recv_body(&mut conn, id, &mut chunk) {
                        if let Some(response) = partial.get_mut(&id) {
                            response.body.extend_from_slice(&chunk[..read]);
                        }
                    }
                }
                Ok((id, quiche::h3::Event::Finished)) => {
                    let index = stream_index[&id];
                    responses[index] = partial.remove(&id);
                }
                Ok((id, quiche::h3::Event::Reset(code))) => {
                    return Err(format!("stream {id} reset with code {code}"));
                }
                Ok(_) => {}
                Err(quiche::h3::Error::Done) => break,
                Err(e) => return Err(format!("h3 poll: {e}")),
            }
        }
    }
}

/// 🔎 An oversized request gets a 431 naming its field, and a request sharing
/// its connection is served.
///
/// Before the fix the site's limit was handed to quiche as its field-section
/// limit, and quiche counts 32 bytes more per field than the site's check:
/// a 2000-byte field against 1024 closed the whole connection with
/// H3_EXCESSIVE_LOAD, so both requests failed and nothing named the field.
#[tokio::test]
async fn h3_oversized_header_fails_only_its_own_stream_and_names_the_field() {
    let site = pingclair_config::compile(HEADER_LIMITED_SITE)
        .unwrap()
        .servers[0]
        .clone();
    let server = spawn_h3_server_with(|address| ServerConfig {
        listen: vec![address.to_string()],
        ..site
    })
    .await;

    let big = "x".repeat(2000);
    let oversized: &[(&str, &str)] = &[("x-big", &big)];
    let ordinary: &[(&str, &str)] = &[("x-small", "fine")];
    let responses = h3_concurrent_gets(server, &[oversized, ordinary])
        .await
        .expect("both requests must complete on one connection");

    let summary: Vec<(u16, String)> = responses
        .iter()
        .map(|response| {
            (
                response.status,
                String::from_utf8_lossy(&response.body).into_owned(),
            )
        })
        .collect();
    assert_eq!(
        summary,
        vec![
            (
                431,
                "Request Header Fields Too Large: the x-big field alone exceeds the header size limit"
                    .to_string()
            ),
            (200, "admitted".to_string()),
        ]
    );
}
