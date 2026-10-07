//! 🏷️ Who identifies a proxied response over HTTP/3.
//!
//! Caddy sets its own `Server` before the handler chain and lets the proxy's
//! copy of the upstream headers replace it, so a client sees the origin's
//! product string when there is one and the proxy's name when there is not.
//! This server used to insert its own over whatever arrived, on both
//! transports (#159).

use super::*;

/// 🏷️ The upstream's `Server` value is what a client reads.
#[tokio::test]
async fn h3_keeps_the_upstreams_server_field_line() {
    let (upstream, _heads, _hits) = spawn_scripted_upstream(
        b"HTTP/1.1 200 OK\r\nServer: audit-upstream/u1\r\nContent-Length: 2\r\n\r\nok",
    )
    .await;
    let server =
        spawn_h3_from_pingclairfile(&format!(":443 {{\n reverse_proxy http://{upstream}\n}}"))
            .await;

    let response = h3_attempt(H3Attempt::to(server, "/"), None).await.unwrap();
    let identifications: Vec<String> = response
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("server"))
        .map(|(_, value)| value.to_ascii_lowercase())
        .collect();
    assert_eq!(identifications, vec!["audit-upstream/u1".to_string()]);
    // 🤝 `Via` names this intermediary, which is what the field is for.
    let via = response
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("via"))
        .map(|(_, value)| value.to_ascii_lowercase())
        .unwrap_or_default();
    assert!(via.contains("1.1 pingclair"), "got: {via:?}");
}

/// 🏷️ A response the server writes itself still identifies it.
#[tokio::test]
async fn h3_local_responses_carry_our_server_field_line() {
    let server = spawn_h3_from_pingclairfile(":443 {\n respond \"local\"\n}").await;

    let response = h3_attempt(H3Attempt::to(server, "/"), None).await.unwrap();
    let identifications: Vec<String> = response
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("server"))
        .map(|(_, value)| value.to_ascii_lowercase())
        .collect();
    assert_eq!(identifications, vec!["pingclair".to_string()]);
}
