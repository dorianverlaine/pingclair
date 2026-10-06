//! ⌛ Over HTTP/3, `lb_try_duration` bounds how long to keep trying a backend,
//! never how long an answer already under way may take — the same line the
//! HTTP/1.1 and HTTP/2 tests in `pingclair/tests/integration/retry_duration.rs`
//! draw.

use super::*;
use tokio::io::AsyncWriteExt;

/// ⌛ Shorter than the origin below takes, so anything that still treats the
/// retry budget as a response deadline fails these tests.
const TRY_DURATION: &str = "300ms";

/// 🧾 Starts an H3 server for one Pingclairfile site that proxies to
/// `upstream` with a short `lb_try_duration`.
async fn spawn_retry_budget_site(upstream: SocketAddr) -> SocketAddr {
    let source = format!(
        ":443 {{\n reverse_proxy http://{upstream} {{\n lb_try_duration {TRY_DURATION}\n }}\n}}"
    );
    let site = pingclair_config::compile(&source).unwrap().servers[0].clone();
    spawn_h3_server_with(|address| ServerConfig {
        listen: vec![address.to_string()],
        ..site
    })
    .await
}

/// 🐢 An origin that waits `header_delay` before answering, then sends
/// `events` server-sent events `event_gap` apart and closes.
async fn slow_event_origin(
    header_delay: Duration,
    events: usize,
    event_gap: Duration,
) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                read_http_head(&mut stream).await;
                tokio::time::sleep(header_delay).await;
                // 🔚 Close-delimited, so the origin needs no framing of its own
                // and the end of the body is the end of the connection.
                if stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\
                          Connection: close\r\n\r\n",
                    )
                    .await
                    .is_err()
                {
                    return;
                }
                for index in 0..events {
                    if index > 0 {
                        tokio::time::sleep(event_gap).await;
                    }
                    let event = format!("data: {index}\n\n");
                    if stream.write_all(event.as_bytes()).await.is_err() {
                        return;
                    }
                }
                let _ = stream.shutdown().await;
            });
        }
    });
    address
}

/// 📜 The complete body `slow_event_origin` sends for `events` events.
fn expected_events(events: usize) -> Vec<u8> {
    (0..events)
        .flat_map(|index| format!("data: {index}\n\n").into_bytes())
        .collect()
}

/// 🐢 Headers that arrive after the retry budget still reach the client,
/// instead of the 504 HTTP/3 used to send once the origin had answered.
#[tokio::test]
async fn h3_slow_response_header_outlives_lb_try_duration() {
    let origin = slow_event_origin(Duration::from_millis(900), 1, Duration::ZERO).await;
    let server = spawn_retry_budget_site(origin).await;

    let response = h3_get(server, "/").await.unwrap();
    assert_eq!((response.status, response.body), (200, expected_events(1)));
}

/// 🌊 An event stream that runs past the retry budget arrives whole.
#[tokio::test]
async fn h3_event_stream_outlives_lb_try_duration() {
    const EVENTS: usize = 4;
    // ⏸️ Each pause is longer than the whole budget, so a budget applied per
    // read cuts the stream just as surely as one applied to the total.
    let origin = slow_event_origin(Duration::ZERO, EVENTS, Duration::from_millis(450)).await;
    let server = spawn_retry_budget_site(origin).await;

    let response = h3_get(server, "/").await;
    assert_eq!(
        response.map(|response| (response.status, response.body)),
        Ok((200, expected_events(EVENTS)))
    );
}
