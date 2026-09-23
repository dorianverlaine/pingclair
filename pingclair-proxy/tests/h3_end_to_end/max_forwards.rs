//! 🧭 `TRACE` and `Max-Forwards` over HTTP/3 (RFC 9110 §7.6.2).
//!
//! The H3 path decides these from the same shared policy as H1/H2. Each case
//! here goes through a real `reverse_proxy` route, so "answered locally" is
//! checked by the upstream never seeing the request at all.

use super::*;

/// 🔎 The one value of a response field, by lowercase name.
fn field<'a>(response: &'a H3Response, name: &str) -> Option<&'a str> {
    response
        .headers
        .iter()
        .find(|(field_name, _)| field_name == name)
        .map(|(_, value)| value.as_str())
}

/// 🧭 `TRACE` is refused and a spent `OPTIONS` is answered here, neither one
/// reaching the upstream; a live `OPTIONS` budget arrives one smaller.
#[tokio::test]
async fn h3_max_forwards_is_checked_and_spent() {
    let (upstream, mut heads, hits) = spawn_scripted_upstream(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    )
    .await;
    let server =
        spawn_h3_from_pingclairfile(&format!(":443 {{\n reverse_proxy http://{upstream}\n}}"))
            .await;

    for (method, max_forwards, status) in [
        ("TRACE", None, 405),
        ("TRACE", Some("3"), 405),
        ("OPTIONS", Some("0"), 200),
    ] {
        let extra: Vec<(&str, &str)> = max_forwards
            .map(|value| ("max-forwards", value))
            .into_iter()
            .collect();
        let response = h3_attempt(
            H3Attempt {
                method,
                extra_headers: &extra,
                ..H3Attempt::to(server, "/")
            },
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            (response.status, field(&response, "allow")),
            (status, Some("GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS")),
            "{method} with Max-Forwards {max_forwards:?}"
        );
    }
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 0);

    let response = h3_attempt(
        H3Attempt {
            method: "OPTIONS",
            extra_headers: &[("max-forwards", "5")],
            ..H3Attempt::to(server, "/")
        },
        None,
    )
    .await
    .unwrap();
    assert_eq!(response.status, 200);
    let head = heads.recv().await.unwrap();
    let forwarded: Vec<&str> = head
        .lines()
        .filter(|line| {
            line.split_once(':')
                .is_some_and(|(name, _)| name.eq_ignore_ascii_case("max-forwards"))
        })
        .collect();
    assert_eq!(forwarded.len(), 1, "{head}");
    assert_eq!(
        forwarded[0].split_once(':').unwrap().1.trim(),
        "4",
        "{head}"
    );
}
