// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🗜️ The proxy compresses only what it is allowed to rewrite, and says so
//! honestly.
//!
//! 📌 Compressing a response changes its bytes. Every test here pins one
//! field that has to change with them, or one response that must not be
//! touched at all, because a client or a shared cache downstream trusts it.

use super::TestServer;
use super::no_proxy_client;
use super::response_pipeline::{gunzip, proxy_pingclairfile, spawn_scripted_origin};

/// 📄 A compressible body comfortably above the 256-byte floor.
fn compressible_body() -> String {
    "compressible proxied text ".repeat(64)
}

/// 🧾 An origin reply carrying `extra` header lines and `body`.
fn origin_reply(status_line: &str, extra: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status_line}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// 🛡️ Compression adds `Accept-Encoding` to the origin's `Vary` rather than
/// replacing it.
///
/// Replacing it erased `Vary: Cookie`, so a shared cache keyed the stored copy
/// on the coding alone and could hand one signed-in user's page to another.
#[tokio::test]
async fn test_compression_keeps_the_origin_vary_members() {
    let body = compressible_body();
    let (origin, _hits) =
        spawn_scripted_origin(origin_reply("200 OK", "Vary: Cookie\r\n", &body)).await;
    let mut server = TestServer::new_pingclairfile(&proxy_pingclairfile(origin, ""));
    assert!(server.wait_until_ready().await, "server failed to start");

    let reply = no_proxy_client()
        .get(server.url(0, "/page"))
        .header("Accept-Encoding", "gzip")
        .send()
        .await
        .unwrap();
    assert_eq!(reply.status(), 200);
    assert_eq!(reply.headers().get("content-encoding").unwrap(), "gzip");
    let vary: Vec<String> = reply
        .headers()
        .get_all("vary")
        .iter()
        .flat_map(|value| value.to_str().unwrap().split(','))
        .map(|token| token.trim().to_ascii_lowercase())
        .collect();
    assert_eq!(vary, ["cookie", "accept-encoding"]);
    assert_eq!(gunzip(&reply.bytes().await.unwrap()), body);
}
