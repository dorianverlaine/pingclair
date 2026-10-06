//! 🔌 `CONNECT` over HTTP/3 (RFC 9114 §4.4, RFC 9110 §9.3.6).
//!
//! A well-formed `CONNECT` carries only `:method` and `:authority`. The parser
//! used to call that shape malformed and reset the stream, while the one
//! nonstandard shape with `:scheme` and `:path` reached a 501. The two are now
//! the other way round: the well-formed request gets the same 405 with `Allow`
//! as HTTP/1.1, and the ill-formed one is reset.

use super::*;

/// 🔌 A §4.4 `CONNECT` gets 405 with `Allow` and never reaches the upstream.
#[tokio::test]
async fn h3_connect_is_refused_with_allow() {
    let (upstream, _heads, hits) = spawn_scripted_upstream(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    )
    .await;
    let server =
        spawn_h3_from_pingclairfile(&format!(":443 {{\n reverse_proxy http://{upstream}\n}}"))
            .await;

    let response = h3_attempt(
        H3Attempt {
            method: "CONNECT",
            authority: "h3.pingclair.test:443",
            ..H3Attempt::to(server, "")
        },
        None,
    )
    .await
    .unwrap();
    assert_eq!(connect_answer(&response), (405, Some(ALLOW.to_string())));
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 0);
}

/// 🧭 The methods every refusal here advertises.
const ALLOW: &str = "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS";

/// 🔎 The status and `Allow` value of one answer, which is all a refusal is.
fn connect_answer(response: &H3Response) -> (u16, Option<String>) {
    let allow = response
        .headers
        .iter()
        .find(|(name, _)| name == "allow")
        .map(|(_, value)| value.clone());
    (response.status, allow)
}

/// 🔌 A `CONNECT` is refused the same way whether or not its authority names
/// a site, and a target without a usable port is a 400 (RFC 9110 §9.3.6).
///
/// The named site is the point: an authority that matches nothing used to
/// get the no-matching-site 404, so the answer depended on which hostname the
/// client typed rather than on the method (pingclair#283).
#[tokio::test]
async fn h3_unmatched_connect_gets_the_same_refusal() {
    // 🧾 Written in the DSL so the site name goes through the adapter a real
    // configuration takes; only the listener is filled in after binding.
    let mut site = pingclair_config::compile("h3.pingclair.test {\n respond \"site-body\" 200\n}")
        .unwrap()
        .servers
        .remove(0);
    let server = spawn_h3_server_with(move |address| {
        site.listen = vec![address.to_string()];
        site
    })
    .await;

    let mut answers = Vec::new();
    for authority in ["elsewhere.test:443", "elsewhere.test", "h3.pingclair.test"] {
        let response = h3_attempt(
            H3Attempt {
                method: "CONNECT",
                authority,
                ..H3Attempt::to(server, "")
            },
            None,
        )
        .await
        .unwrap();
        answers.push((authority, connect_answer(&response)));
    }
    assert_eq!(
        answers,
        [
            ("elsewhere.test:443", (405, Some(ALLOW.to_string()))),
            ("elsewhere.test", (400, Some(ALLOW.to_string()))),
            ("h3.pingclair.test", (400, Some(ALLOW.to_string()))),
        ]
    );
}

/// 🚫 A `CONNECT` that also sends `:scheme` and `:path` is malformed (§4.4).
#[tokio::test]
async fn h3_connect_with_a_path_resets_with_message_error() {
    let server = spawn_h3_from_pingclairfile(":443 {\n respond \"ok\" 200\n}").await;
    let outcome = h3_attempt(
        H3Attempt {
            method: "CONNECT",
            ..H3Attempt::to(server, "/")
        },
        None,
    )
    .await
    .map(|response| response.status);
    assert_eq!(outcome, Err("stream reset with code 270".to_string()));
}
