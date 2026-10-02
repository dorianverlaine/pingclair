// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🛡️ Which request headers may name the client behind a trusted proxy.
//!
//! The test client connects from loopback and loopback is a trusted proxy, so
//! the client plays the part of a proxy reporting a visitor. The question is
//! which of its headers count. `CF-Connecting-IP` used to count whenever the
//! peer was trusted, ahead of everything else, so any client reaching the
//! server through an ingress that passes headers through untouched could name
//! itself with it. It now counts only when `client_ip_headers` lists it.

use super::{TestServer, no_proxy_client};

/// 🧾 A site that trusts loopback and echoes the verified client address,
/// with `servers_options` written into the global `servers` block.
fn echo_identity_server(servers_options: &str) -> TestServer {
    TestServer::new_pingclairfile(&format!(
        r#"
        {{
            admin off
            servers {{
                trusted_proxies static 127.0.0.1/32
                {servers_options}
            }}
        }}

        http://__PINGCLAIR_TEST_LISTEN__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            respond "{{client_ip}}"
        }}
        "#
    ))
}

/// 🔎 Sends one request per header set and collects each verified address.
async fn identities(server: &TestServer, cases: &[&[(&str, &str)]]) -> Vec<String> {
    let client = no_proxy_client();
    let mut seen = Vec::new();
    for headers in cases {
        let mut request = client.get(server.url(0, "/whoami"));
        for (name, value) in *headers {
            request = request.header(*name, *value);
        }
        seen.push(request.send().await.unwrap().text().await.unwrap());
    }
    seen
}

/// 🚫 Without `client_ip_headers`, `CF-Connecting-IP` names nobody: the
/// forwarding chain decides, and with no chain the peer itself is the client.
#[tokio::test]
async fn test_cf_connecting_ip_is_ignored_unless_configured() {
    let mut server = echo_identity_server("");
    assert!(server.wait_until_ready().await, "server failed to start");

    let seen = identities(
        &server,
        &[
            &[
                ("CF-Connecting-IP", "203.0.113.7"),
                ("X-Forwarded-For", "198.51.100.9"),
            ],
            &[("CF-Connecting-IP", "203.0.113.7")],
        ],
    )
    .await;
    assert_eq!(seen, vec!["198.51.100.9", "127.0.0.1"]);
}

/// ☁️ `client_ip_headers CF-Connecting-IP` makes that header the only source:
/// it names the client, and an `X-Forwarded-For` beside it is not consulted.
#[tokio::test]
async fn test_configured_client_ip_headers_are_the_only_source() {
    let mut server = echo_identity_server("client_ip_headers CF-Connecting-IP");
    assert!(server.wait_until_ready().await, "server failed to start");

    let seen = identities(
        &server,
        &[
            &[
                ("CF-Connecting-IP", "203.0.113.7"),
                ("X-Forwarded-For", "198.51.100.9"),
            ],
            &[("X-Forwarded-For", "198.51.100.9")],
        ],
    )
    .await;
    assert_eq!(seen, vec!["203.0.113.7", "127.0.0.1"]);
}

/// 🪞 An origin whose body is the `X-Forwarded-For` it received.
async fn spawn_forwarded_for_echo() -> std::net::SocketAddr {
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
                let request = String::from_utf8_lossy(&buffer[..read]).to_string();
                let chain = request
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.trim()
                            .eq_ignore_ascii_case("x-forwarded-for")
                            .then(|| value.trim().to_string())
                    })
                    .unwrap_or_default();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{chain}",
                    chain.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    address
}

/// 📤 The chain sent upstream follows the same restriction.
///
/// With `client_ip_headers X-Real-Client`, a client-supplied
/// `X-Forwarded-For` names nobody here — yet it used to be forwarded upstream
/// as the start of the chain, so an origin that reads `X-Forwarded-For` saw
/// whatever address the client chose. The upstream chain now starts from the
/// client the configured header named.
#[tokio::test]
async fn test_upstream_forwarded_for_starts_from_the_configured_client() {
    let origin = spawn_forwarded_for_echo().await;
    let mut server = TestServer::new_pingclairfile(&format!(
        r#"
        {{
            admin off
            servers {{
                trusted_proxies static 127.0.0.1/32
                client_ip_headers X-Real-Client
            }}
        }}

        http://__PINGCLAIR_TEST_LISTEN__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            reverse_proxy http://{origin}
        }}
        "#
    ));
    assert!(server.wait_until_ready().await, "server failed to start");

    let seen = identities(
        &server,
        &[
            &[
                ("X-Real-Client", "203.0.113.7"),
                ("X-Forwarded-For", "10.9.9.9"),
            ],
            &[("X-Forwarded-For", "10.9.9.9")],
        ],
    )
    .await;
    assert_eq!(seen, vec!["203.0.113.7, 127.0.0.1", "127.0.0.1"]);
}
