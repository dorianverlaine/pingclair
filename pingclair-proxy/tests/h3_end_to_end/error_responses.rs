//! 🚫 Locally raised error statuses carry a body that explains them over
//! HTTP/3, matching what HTTP/1.1 and HTTP/2 send.

use super::*;

/// 🔎 The single value of one response field, by lowercase name.
fn field<'a>(response: &'a H3Response, name: &str) -> Option<&'a str> {
    response
        .headers
        .iter()
        .find(|(field_name, _)| field_name == name)
        .map(|(_, value)| value.as_str())
}

/// 🧾 Starts an H3 server for the first site of a Pingclairfile, keeping its
/// site-level settings such as `rate_limit` and `error_page` rather than only
/// the first route's handler.
async fn spawn_h3_site(source: &str) -> SocketAddr {
    let site = pingclair_config::compile(source).unwrap().servers[0].clone();
    spawn_h3_server_with(|address| ServerConfig {
        listen: vec![address.to_string()],
        ..site
    })
    .await
}

/// 🚦 A rate-limit rejection over HTTP/3 has a body and keeps `Retry-After`.
///
/// Before the fix it was a lone `:status 429` header block.
#[tokio::test]
async fn h3_rate_limit_rejection_carries_a_body() {
    let server = spawn_h3_site(
        ":443 {\n rate_limit 1 60s {\n key header X-Client\n }\n respond \"admitted\"\n}",
    )
    .await;

    let client = [("x-client", "h3")];
    let admitted = h3_get_with_headers(server, "/", &client).await.unwrap();
    assert_eq!(admitted.status, 200);

    let rejected = h3_get_with_headers(server, "/", &client).await.unwrap();
    assert_eq!(
        (
            rejected.status,
            field(&rejected, "content-type"),
            field(&rejected, "retry-after").is_some(),
            rejected.body.as_slice(),
        ),
        (429, Some("text/plain"), true, &b"Too Many Requests"[..]),
        "headers: {:?}",
        rejected.headers
    );
}
