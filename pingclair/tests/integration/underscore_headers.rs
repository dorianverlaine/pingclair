// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🛡️ Which underscore-named request fields an origin receives.
//!
//! A CGI or FastCGI backend folds `x_probe` and `x-probe` onto the same
//! variable, so an underscore spelling is an alias for the hyphenated header —
//! the injection path GHSA-f59h-q822-g45g closes by dropping every underscore
//! name before routing. `expected_underscore_headers` lists the names an origin
//! is entitled to, matching Caddy's server option of the same name (#295): a
//! trailing `*` matches a prefix, the hyphenated spelling of an allowlisted
//! name is dropped so the alias cannot take the other route to the variable,
//! and a repeated allowlisted field drops every occurrence.
//!
//! 📌 The assertions read the *origin's* view of the request. A filter that
//! runs and a filter that silently does nothing look identical from this side
//! of the proxy, which is how #269 went unnoticed on one transport.

use super::{TestServer, no_proxy_client};
use std::net::SocketAddr;

/// 🧾 The fields these tests ask about, so a response can be compared as a set.
const INTERESTING: &[&str] = &[
    "x_probe",
    "x-probe",
    "webhook_event",
    "webhook-event",
    "webhook_bad.dot",
    "global_field",
    "x_other",
];

/// 🔎 An origin that answers with the field names it received, one per line.
async fn spawn_field_echo() -> SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 16384];
                let Ok(read) = stream.read(&mut buffer).await else {
                    return;
                };
                let request = String::from_utf8_lossy(&buffer[..read]);
                let mut fields: Vec<String> = request
                    .lines()
                    .skip(1)
                    .take_while(|line| !line.is_empty())
                    .filter_map(|line| {
                        let (name, _) = line.split_once(':')?;
                        Some(name.to_ascii_lowercase())
                    })
                    .collect();
                fields.sort();
                let body = fields.join("\n");
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    address
}

/// 🧾 One site behind the harness's loopback listener, with `global` and the
/// addressed `servers <address>` block written into its global options.
fn pingclairfile(origin: SocketAddr, global: &str, addressed: &str) -> String {
    format!(
        r#"
        {{
            admin off
            {global}
            {addressed}
        }}

        http://__PINGCLAIR_TEST_LISTEN__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            reverse_proxy http://{origin}
        }}
        "#
    )
}

/// 🔎 Sends the probe fields, optionally repeating `X_Probe`, and returns the
/// interesting fields that reached the origin, sorted.
async fn probe(server: &TestServer, repeat_probe: bool) -> Vec<String> {
    let mut request = no_proxy_client()
        .get(server.url(0, "/"))
        .header("X_Probe", "kept")
        .header("X-Probe", "alias")
        .header("Webhook_Event", "prefix")
        .header("Webhook-Event", "alias")
        .header("Webhook_Bad.Dot", "unvetted")
        .header("Global_Field", "global")
        .header("X_Other", "dropped");
    if repeat_probe {
        request = request.header("X_Probe", "second");
    }
    let body = request
        .send()
        .await
        .expect("the site must answer")
        .text()
        .await
        .expect("a body");
    let mut seen: Vec<String> = body
        .lines()
        .filter(|name| INTERESTING.contains(name))
        .map(str::to_owned)
        .collect();
    seen.sort();
    seen
}

/// 🚫 Without an allowlist, every underscore spelling goes and the hyphenated
/// one stays: the default is Caddy's, and it is what the origin sees.
#[tokio::test]
async fn underscore_fields_are_dropped_by_default() {
    let origin = spawn_field_echo().await;
    let mut server = TestServer::new_pingclairfile(&pingclairfile(origin, "", ""));
    assert!(server.wait_until_ready().await, "server failed to start");

    assert_eq!(probe(&server, false).await, ["webhook-event", "x-probe"]);
}

/// 🛡️ A `servers { … }` allowlist keeps the exact spelling and a trailing-star
/// prefix, and drops the hyphenated alias of each.
#[tokio::test]
async fn the_server_allowlist_keeps_only_the_names_it_lists() {
    let origin = spawn_field_echo().await;
    let mut server = TestServer::new_pingclairfile(&pingclairfile(
        origin,
        "servers {
            expected_underscore_headers X_Probe Webhook_*
        }",
        "",
    ));
    assert!(server.wait_until_ready().await, "server failed to start");

    assert_eq!(probe(&server, false).await, ["webhook_event", "x_probe"]);
    // 🔁 Two copies of an allowlisted field drop together, because the extra
    // one is what a spoofed request adds.
    assert_eq!(probe(&server, true).await, ["webhook_event"]);
}

/// 🧭 An addressed `servers <address>` block replaces the global list for that
/// listener: `Global_Field` is in the global list and is dropped here.
#[tokio::test]
async fn an_addressed_block_overrides_the_global_allowlist() {
    let origin = spawn_field_echo().await;
    let mut server = TestServer::new_pingclairfile(&pingclairfile(
        origin,
        "servers {
            expected_underscore_headers Global_Field
        }",
        "servers 127.0.0.1:__PINGCLAIR_TEST_PORT__ {
            expected_underscore_headers X_Probe Webhook_*
        }",
    ));
    assert!(server.wait_until_ready().await, "server failed to start");

    assert_eq!(probe(&server, false).await, ["webhook_event", "x_probe"]);
}
