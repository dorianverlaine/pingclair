//! 💬 Typed text values resolve over HTTP/3 too.

use super::*;

/// 💬 `Format(…)`, `from:` and a resolved `header_down` end at the same bytes
/// on HTTP/3 as on HTTP/1.1 and HTTP/2 — the parity the shared resolver exists
/// to keep.
#[tokio::test]
async fn h3_typed_text_resolves_redirects_headers_and_error_bodies() {
    let (backend_address, mut heads, _hits) = spawn_scripted_upstream(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    )
    .await;
    let source = format!(
        r#"HTTPListener(on: ":443") {{
        Site(host: "*") {{
            Route(when: .path(exact: "/go")) {{
                Redirect(to: Format("https://pingclair.com{{uri}}", uri: .uri),
                         status: .permanentRedirect)
            }}
            Route(when: .path(exact: "/boom")) {{ Fail(status: 503) }}
            ErrorRoute(for: [.serverError]) {{
                ResponseHeader(.set("X-Code", from: .errorStatus))
                Respond(body: Format("status {{code}}", code: .errorStatus))
            }}
            Fallback {{
                RequestHeader(.set("X-Real-IP", from: .clientIP))
                Proxy(to: "{backend_address}",
                      headersDown: [.set("X-Test", from: .host)])
            }}
        }}
    }}"#
    );
    let site = pingclair_config::compile(&source)
        .unwrap()
        .servers
        .remove(0);
    let server = spawn_h3_server_with(|address| ServerConfig {
        listen: vec![address.to_string()],
        ..site
    })
    .await;

    let response = h3_get(server, "/go?x=1").await.unwrap();
    assert_eq!(response.status, 308);
    let location = response
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("location"))
        .map(|(_, value)| value.as_str());
    assert_eq!(location, Some("https://pingclair.com/go?x=1"));

    let response = h3_get(server, "/boom").await.unwrap();
    assert_eq!(response.status, 503);
    let code = response
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("x-code"))
        .map(|(_, value)| value.as_str());
    assert_eq!(code, Some("503"));
    assert_eq!(String::from_utf8_lossy(&response.body), "status 503");

    let response = h3_get(server, "/echo").await.unwrap();
    assert_eq!(
        response.status,
        200,
        "body={:?}",
        String::from_utf8_lossy(&response.body)
    );
    let down = response
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("x-test"))
        .map(|(_, value)| value.as_str());
    assert_eq!(
        down,
        Some("h3.pingclair.test"),
        "`header_down` resolves over HTTP/3 through the shared policy"
    );
    let head = heads.recv().await.unwrap().to_ascii_lowercase();
    assert!(head.contains("x-real-ip: 127.0.0.1"), "{head}");
}
