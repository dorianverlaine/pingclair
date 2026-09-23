//! 🧾 What an HTTP/3 response carries besides its body: the fields a status
//! and a method require, and the content they forbid.
//!
//! H1/H2 gets several of these from Pingora for free. The H3 path assembles
//! its own header list, so each rule here is one this proxy has to apply
//! itself, and each test is one the H3 path once failed.

use super::*;

/// 🔎 Every value of one response field, by lowercase name.
fn fields<'a>(response: &'a H3Response, name: &str) -> Vec<&'a str> {
    response
        .headers
        .iter()
        .filter(|(field_name, _)| field_name == name)
        .map(|(_, value)| value.as_str())
        .collect()
}

/// 🕰️ A locally generated response carries a current `Date`.
///
/// RFC 9110 §6.6.1 requires one on every 2xx, 3xx and 4xx from a server with
/// a clock. The H3 header list is assembled here rather than by Pingora, and
/// before the fix nothing on that path wrote the field at all.
#[tokio::test]
async fn h3_local_response_carries_a_date() {
    let server = spawn_h3_from_pingclairfile(":443 {\n respond \"ok\" 200\n}").await;

    let response = h3_get(server, "/").await.unwrap();
    let dates = fields(&response, "date");
    assert_eq!(dates.len(), 1, "exactly one `date`: {:?}", response.headers);
    // 📌 IMF-fixdate is always 29 characters, e.g. `Sun, 06 Nov 1994 08:49:37 GMT`.
    assert!(
        dates[0].len() == 29 && dates[0].ends_with(" GMT"),
        "`date` must be an IMF-fixdate: {}",
        dates[0]
    );
}

/// 🕰️ A proxied response's `Date` is this server's, not the upstream's.
///
/// Matches H1/H2, where Pingora overwrites the field: it states when the
/// message on this connection was produced. The upstream here claims 1994.
#[tokio::test]
async fn h3_proxied_response_date_is_replaced() {
    let (upstream, _, _) = spawn_scripted_upstream(
        b"HTTP/1.1 200 OK\r\nDate: Sun, 06 Nov 1994 08:49:37 GMT\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    )
    .await;
    let server =
        spawn_h3_from_pingclairfile(&format!(":443 {{\n reverse_proxy http://{upstream}\n}}"))
            .await;

    let response = h3_get(server, "/").await.unwrap();
    let dates = fields(&response, "date");
    assert_eq!(dates.len(), 1, "exactly one `date`: {dates:?}");
    assert_ne!(dates[0], "Sun, 06 Nov 1994 08:49:37 GMT");
}
