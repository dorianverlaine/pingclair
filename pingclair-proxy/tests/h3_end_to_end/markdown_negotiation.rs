//! 🧭 `ServeFiles(…).negotiate([.markdown])` over HTTP/3.

use super::*;

/// 🔎 One header field of the H3 response, by case-insensitive name.
fn field<'a>(response: &'a H3Response, name: &str) -> Option<&'a str> {
    response
        .headers
        .iter()
        .find(|(field, _)| field.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

/// 🔎 Whether the response says its answer varies by `Accept`.
fn varies_by_accept(response: &H3Response) -> bool {
    response
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("vary"))
        .any(|(_, value)| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("accept"))
        })
}

#[tokio::test]
async fn h3_markdown_negotiation_serves_the_twin_and_refuses_what_it_must() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("index.html"), "<h1>home</h1>").unwrap();
    std::fs::write(root.path().join("index.md"), "# home").unwrap();
    std::fs::write(root.path().join("bare.html"), "<h1>bare</h1>").unwrap();
    let source = format!(
        r#"HTTPListener(on: ":8080") {{
        Site(host: "*") {{
            Fallback {{ ServeFiles(root: "{}").negotiate([.markdown]) }}
        }}
    }}"#,
        root.path().display()
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

    // 📝 An explicit preference gets the sibling, `Vary: Accept` included.
    let markdown = h3_attempt(
        H3Attempt {
            extra_headers: &[("accept", "text/markdown")],
            ..H3Attempt::to(server, "/")
        },
        None,
    )
    .await
    .unwrap();
    assert_eq!(markdown.status, 200);
    assert_eq!(
        field(&markdown, "content-type"),
        Some("text/markdown; charset=utf-8")
    );
    assert_eq!(String::from_utf8_lossy(&markdown.body), "# home");
    assert!(varies_by_accept(&markdown), "{:?}", markdown.headers);

    // 🌐 A browser's quality tie is the HTML on this transport too.
    let html = h3_attempt(
        H3Attempt {
            extra_headers: &[("accept", "text/html,*/*;q=0.8")],
            ..H3Attempt::to(server, "/")
        },
        None,
    )
    .await
    .unwrap();
    assert_eq!(html.status, 200);
    assert_eq!(
        field(&html, "content-type"),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(String::from_utf8_lossy(&html.body), "<h1>home</h1>");
    assert!(varies_by_accept(&html));

    // 🚫 The page exists, the client refuses the HTML, and no twin stands in.
    let refused = h3_attempt(
        H3Attempt {
            extra_headers: &[("accept", "text/markdown")],
            ..H3Attempt::to(server, "/bare.html")
        },
        None,
    )
    .await
    .unwrap();
    assert_eq!(refused.status, 406);
    assert!(varies_by_accept(&refused));
    assert!(
        String::from_utf8_lossy(&refused.body).contains("not acceptable"),
        "{:?}",
        refused.body
    );
}
