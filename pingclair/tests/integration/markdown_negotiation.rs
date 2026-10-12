// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧭 `file_server { negotiate markdown }` end to end over H1 and H2.

use super::{TestServer, no_proxy_client};

fn site(root: &std::path::Path) -> String {
    format!(
        r#":__PINGCLAIR_TEST_PORT__ {{
    root * {}
    handle __PINGCLAIR_TEST_READINESS_PATH__ {{
        respond "__PINGCLAIR_TEST_READINESS_TOKEN__"
    }}
    handle {{
        file_server {{
            negotiate markdown
        }}
    }}
}}"#,
        root.display()
    )
}

fn tree() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("index.html"), "<h1>home</h1>").unwrap();
    std::fs::write(root.path().join("index.md"), "# home").unwrap();
    std::fs::write(root.path().join("page.html"), "<h1>page</h1>").unwrap();
    std::fs::write(root.path().join("page.md"), "# page").unwrap();
    std::fs::write(root.path().join("bare.html"), "<h1>bare</h1>").unwrap();
    std::fs::write(root.path().join("asset.png"), b"png-bytes").unwrap();
    root
}

#[tokio::test]
async fn markdown_negotiation_serves_the_twin_and_keeps_browsers_on_html() {
    let root = tree();
    let mut server = TestServer::new_pingclairfile(&site(root.path()));
    assert!(server.wait_until_ready().await, "server failed to start");

    let h2 = reqwest::Client::builder()
        .no_proxy()
        .http2_prior_knowledge()
        .build()
        .unwrap();
    for (protocol, client) in [("h1", no_proxy_client()), ("h2", h2)] {
        // 📝 An explicit preference gets the sibling, `Vary` included.
        let response = client
            .get(server.url(0, "/"))
            .header("Accept", "text/markdown")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 200, "{protocol}");
        assert_eq!(
            response.headers()["content-type"],
            "text/markdown; charset=utf-8",
            "{protocol}"
        );
        assert!(
            varies_by_accept(response.headers()),
            "{protocol}: {:#?}",
            response.headers()
        );
        assert_eq!(response.text().await.unwrap(), "# home", "{protocol}");

        // 🌐 A browser's quality tie is the HTML, and it varies too.
        let response = client
            .get(server.url(0, "/"))
            .header(
                "Accept",
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            )
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 200, "{protocol}");
        assert_eq!(
            response.headers()["content-type"],
            "text/html; charset=utf-8",
            "{protocol}"
        );
        assert!(varies_by_accept(response.headers()), "{protocol}");
        assert_eq!(
            response.text().await.unwrap(),
            "<h1>home</h1>",
            "{protocol}"
        );

        // 🤖 The header coding agents send names both types at q=1; naming
        // Markdown breaks the tie toward it.
        let response = client
            .get(server.url(0, "/"))
            .header("Accept", "text/markdown, text/html")
            .send()
            .await
            .unwrap();
        assert_eq!(response.text().await.unwrap(), "# home", "{protocol}");

        // 📄 An `.html` URL reads its own twin.
        let response = client
            .get(server.url(0, "/page.html"))
            .header("Accept", "text/markdown")
            .send()
            .await
            .unwrap();
        assert_eq!(response.text().await.unwrap(), "# page", "{protocol}");

        // 🚫 The page exists, the client refuses the HTML, and no twin stands
        // in: 406 rather than a representation it said no to.
        let response = client
            .get(server.url(0, "/bare.html"))
            .header("Accept", "text/markdown")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 406, "{protocol}");
        assert!(varies_by_accept(response.headers()), "{protocol}");
        assert!(
            response.text().await.unwrap().contains("not acceptable"),
            "{protocol}"
        );

        // 🖼️ An asset never negotiates, so it never fragments its cache on a
        // header it does not depend on.
        let response = client
            .get(server.url(0, "/asset.png"))
            .header("Accept", "text/markdown")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 200, "{protocol}");
        assert!(!varies_by_accept(response.headers()), "{protocol}");
        assert_eq!(
            response.bytes().await.unwrap(),
            &b"png-bytes"[..],
            "{protocol}"
        );
    }
}

#[tokio::test]
async fn a_range_reads_the_markdown_it_negotiated() {
    let root = tree();
    let mut server = TestServer::new_pingclairfile(&site(root.path()));
    assert!(server.wait_until_ready().await, "server failed to start");
    let response = no_proxy_client()
        .get(server.url(0, "/"))
        .header("Accept", "text/markdown")
        .header("Range", "bytes=0-1")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 206);
    assert_eq!(
        response.headers()["content-range"],
        "bytes 0-1/6",
        "the range counted the Markdown bytes"
    );
    assert_eq!(response.text().await.unwrap(), "# ");
}

/// 🔎 Whether a response says its answer varies by `Accept`.
fn varies_by_accept(headers: &reqwest::header::HeaderMap) -> bool {
    headers
        .get_all("vary")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("accept"))
        })
}
