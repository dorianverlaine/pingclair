// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 📜 RFC conformance: one requirement per test, cited by the section that
//! decides it.
//!
//! This repository's authority order is **RFC > Caddy > nginx**, so a test here
//! names the clause it pins and never another server's behaviour. A property
//! that only exists because Caddy or nginx does it differently lives in
//! `parity`, and says so in its own doc comment.
//!
//! 🚧 A requirement the current build does not meet is marked `#[ignore]` with
//! the tracking issue in the attribute, because a conformance test for an
//! unfixed defect must fail — that is what makes it evidence. The ignored set is
//! therefore the outstanding list, and it shrinks one fix at a time:
//!
//! ```text
//! cargo +1.98.1 nextest run -p pingclair --test integration --run-ignored all
//! ```

#[path = "rfc_conformance/request_framing.rs"]
mod request_framing;

#[path = "rfc_conformance/field_values.rs"]
mod field_values;

#[path = "rfc_conformance/response_framing.rs"]
mod response_framing;

#[path = "rfc_conformance/hop_by_hop.rs"]
mod hop_by_hop;

#[path = "rfc_conformance/upstream_requests.rs"]
mod upstream_requests;

#[path = "rfc_conformance/redirects.rs"]
mod redirects;

#[path = "rfc_conformance/parity.rs"]
mod parity;

use super::{TestServer, read_http1_to_end};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 🧾 A site whose directives are the ones under test, with the harness's
/// readiness route in front of them.
///
/// Shared by every module in this tree so a fixture cannot drift from its
/// siblings: the readiness path and token are the harness placeholders, and the
/// body is the part each test varies.
fn site(body: &str) -> String {
    format!(
        r#"
        {{
            admin off
        }}

        :__PINGCLAIR_TEST_PORT__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            {body}
        }}
        "#
    )
}

/// 🔌 One raw HTTP/1.1 request, answered to the end of the connection.
///
/// Returns the lowercased head and the bytes that followed it, which is what
/// framing assertions need: a `400` has to be in the status line, and a smuggled
/// second response would show up in the body.
async fn raw_http1(server: &TestServer, request: &[u8]) -> (String, Vec<u8>) {
    let mut stream = tokio::net::TcpStream::connect(server.address(0))
        .await
        .unwrap();
    stream.write_all(request).await.unwrap();
    let response = read_http1_to_end(&mut stream).await;
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap_or(response.len());
    (
        String::from_utf8_lossy(&response[..split]).to_ascii_lowercase(),
        response.get(split + 4..).unwrap_or_default().to_vec(),
    )
}

/// 📝 A TCP origin that records the request head it was sent and replays a
/// scripted response.
///
/// A proxy bug of the kind this tree keeps finding changes what the origin sees
/// — a padding character, a trailer, a length — so the check has to be made
/// against the bytes that arrived rather than against a mock's opinion.
struct ScriptedUpstream {
    address: SocketAddr,
    seen: Arc<tokio::sync::Mutex<String>>,
}

impl ScriptedUpstream {
    /// Starts an origin that writes each chunk in order, pausing between them.
    ///
    /// A pause turns one helper into both an ordinary origin (one chunk, no
    /// pause) and a slow one, which is what the streaming checks need: the
    /// interesting question there is when the bytes left the proxy, not what
    /// they contained.
    async fn start(chunks: Vec<Vec<u8>>, pause: Duration) -> Self {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind a scripted upstream");
        let address = listener.local_addr().expect("upstream address");
        let seen = Arc::new(tokio::sync::Mutex::new(String::new()));
        let recorder = Arc::clone(&seen);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let recorder = Arc::clone(&recorder);
                let chunks = chunks.clone();
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    let mut chunk = [0u8; 4096];
                    // The head is all any assertion here looks at; a request
                    // body would only slow the test down.
                    while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                        match stream.read(&mut chunk).await {
                            Ok(0) | Err(_) => break,
                            Ok(read) => head.extend_from_slice(&chunk[..read]),
                        }
                    }
                    recorder
                        .lock()
                        .await
                        .push_str(&String::from_utf8_lossy(&head));
                    for (index, chunk) in chunks.iter().enumerate() {
                        if index > 0 && !pause.is_zero() {
                            tokio::time::sleep(pause).await;
                        }
                        if stream.write_all(chunk).await.is_err() {
                            return;
                        }
                        let _ = stream.flush().await;
                    }
                    let _ = stream.shutdown().await;
                });
            }
        });
        Self { address, seen }
    }

    /// 📥 The request head the origin received, exactly as it arrived.
    async fn request_head(&self) -> String {
        self.seen.lock().await.clone()
    }
}

/// 🧪 The address of an origin nothing is listening on.
///
/// Learned by binding and releasing, so a test that asserts "the dial was
/// attempted" cannot accidentally talk to something else on a fixed port.
fn closed_port() -> u16 {
    super::free_port()
}
