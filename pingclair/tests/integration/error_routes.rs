// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🚨 `handle_errors` routes answer with their own pages.
//!
//! Caddy's documented shape for a static error page is
//! `handle_errors { root * /srv/errors  rewrite * /{err.status_code}.html  file_server }`.
//! The `file_server` in it used to be looked up in the slot of the route that
//! raised the error, so the page was never served: HTTP/1 and HTTP/2 sent the
//! bare error text instead.

use super::{TestServer, free_port, no_proxy_client, read_http1_to_end};

/// 📂 A site whose own root holds no error pages, and whose error route has a
/// root that does. Serving from the wrong one shows up as a missing page.
struct ErrorPageSite {
    _site_root: tempfile::TempDir,
    _error_root: tempfile::TempDir,
    config: String,
}

fn error_page_site(extra: &str) -> ErrorPageSite {
    let site_root = tempfile::tempdir().expect("site root");
    let error_root = tempfile::tempdir().expect("error root");
    std::fs::write(site_root.path().join("present.txt"), "present").unwrap();
    for status in [404, 413, 502, 503] {
        std::fs::write(
            error_root.path().join(format!("{status}.html")),
            format!("<h1>page for {status}</h1>"),
        )
        .unwrap();
    }
    let config = format!(
        r#"
        {{
            admin off
        }}

        http://__PINGCLAIR_TEST_LISTEN__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            root * {site_root}

            handle_errors {{
                root * {error_root}
                rewrite * /{{err.status_code}}.html
                file_server
            }}

            handle /boom {{
                error "exploded" 503
            }}

            {extra}

            file_server
        }}
        "#,
        site_root = site_root.path().display(),
        error_root = error_root.path().display(),
    );
    ErrorPageSite {
        _site_root: site_root,
        _error_root: error_root,
        config,
    }
}

/// 🚨 A raised status and a missing file both render the error route's page,
/// with the error's status, on HTTP/1.1 and HTTP/2.
///
/// The request's `Range` and validators belong to the resource that failed,
/// not to the page, so they must not turn the error into a `206` or `304`.
#[tokio::test]
async fn test_handle_errors_file_server_serves_the_error_page() {
    let site = error_page_site("");
    let mut server = TestServer::new_pingclairfile(&site.config);
    assert!(server.wait_until_ready().await, "server failed to start");

    let h2 = reqwest::Client::builder()
        .no_proxy()
        .http2_prior_knowledge()
        .build()
        .unwrap();
    for (protocol, client) in [("h1", no_proxy_client()), ("h2", h2)] {
        let mut seen = Vec::new();
        for (method, path) in [
            (reqwest::Method::GET, "/boom"),
            (reqwest::Method::POST, "/boom"),
            (reqwest::Method::GET, "/missing.txt"),
            (reqwest::Method::GET, "/present.txt"),
        ] {
            let response = client
                .request(method.clone(), server.url(0, path))
                .header("Range", "bytes=0-1")
                .header("If-None-Match", "*")
                .send()
                .await
                .unwrap();
            seen.push((
                method.to_string(),
                path,
                response.status().as_u16(),
                response.text().await.unwrap(),
            ));
        }
        let expected = |method: &str, path, status, body: &str| {
            (method.to_string(), path, status, body.to_string())
        };
        assert_eq!(
            seen,
            vec![
                expected("GET", "/boom", 503, "<h1>page for 503</h1>"),
                expected("POST", "/boom", 503, "<h1>page for 503</h1>"),
                expected("GET", "/missing.txt", 404, "<h1>page for 404</h1>"),
                // 🎯 The site's own files still answer as before.
                expected("GET", "/present.txt", 304, ""),
            ],
            "{protocol}"
        );
    }
}

/// 🧾 A header block over the limit is refused before error routing.
///
/// `handle_errors` answers for a site's handlers, and a request refused before
/// routing never reached one — Caddy refuses an oversized header block before
/// any handler runs. The site's page replaced the one sentence naming the
/// field that was too large, which is the client's entire diagnosis, and
/// HTTP/3 already answered with the plain refusal (#288).
#[tokio::test]
async fn test_an_oversized_header_block_never_reaches_the_error_route() {
    let site = error_page_site("limits {\n    max_header_bytes 8192\n}\n");
    let mut server = TestServer::new_pingclairfile(&site.config);
    assert!(server.wait_until_ready().await, "server failed to start");

    let big = "x".repeat(9_000);
    for http2 in [false, true] {
        let builder = reqwest::Client::builder().no_proxy();
        let client = if http2 {
            builder.http2_prior_knowledge()
        } else {
            builder.http1_only()
        }
        .build()
        .unwrap();
        let response = client
            .get(server.url(0, "/present.txt"))
            .header("X-Big", &big)
            .send()
            .await
            .unwrap();
        let status = response.status().as_u16();
        let body = response.text().await.unwrap();
        assert_eq!(status, 431, "http2={http2}");
        assert!(
            body.contains("x-big"),
            "http2={http2}: the refusal must name the field: {body}"
        );
        assert!(
            !body.contains("page for"),
            "http2={http2}: the site's page must not replace the refusal: {body}"
        );
    }

    // 🎯 Control: an error the handler chain produced still reaches the route,
    // so this refuses one shape rather than turning error routing off.
    let missing = no_proxy_client()
        .get(server.url(0, "/missing.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 404);
    assert!(
        missing.text().await.unwrap().contains("page for 404"),
        "a handler's error must keep reaching the error route"
    );
    server.stop();
}

/// 🚨 Errors the server produces itself, not only the ones a handler raises,
/// reach `handle_errors`: a proxy that cannot reach its upstream (502), and a
/// body over its limit (413), whether it declared its length or streamed past
/// it. Caddy routes all three through the error routes.
///
/// 🤡 They used to bypass them entirely and answer with the built-in text, so
/// the error pages an operator wrote for exactly these cases never appeared.
#[tokio::test]
async fn test_handle_errors_answers_proxy_and_body_size_errors() {
    let dead_port = free_port();
    // 🕳️ An upstream that accepts and reads forever, so the proxied body is
    // the only thing that can end the exchange.
    let sink_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sink = sink_listener.local_addr().unwrap();
    tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        while let Ok((mut connection, _)) = sink_listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                while matches!(connection.read(&mut buffer).await, Ok(read) if read > 0) {}
            });
        }
    });
    let site = error_page_site(&format!(
        r#"
            handle /proxy {{
                reverse_proxy 127.0.0.1:{dead_port}
            }}

            handle /upload {{
                request_body {{
                    max_size 10
                }}
                respond "accepted"
            }}

            handle /proxy-upload {{
                request_body {{
                    max_size 10
                }}
                reverse_proxy {sink}
            }}
        "#
    ));
    let mut server = TestServer::new_pingclairfile(&site.config);
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();

    let mut seen = Vec::new();
    let response = client.get(server.url(0, "/proxy")).send().await.unwrap();
    seen.push((
        "proxy",
        response.status().as_u16(),
        response.text().await.unwrap(),
    ));
    // 📏 Only the head is sent: the server refuses on the declared length and
    // closes, and a client still writing the body would race that close.
    let address = server.address(0);
    let (status, body) = raw_exchange(
        address,
        &format!(
            "POST /upload HTTP/1.1\r\nHost: {address}\r\nContent-Length: 100\r\n\
             Connection: close\r\n\r\n"
        ),
    )
    .await;
    seen.push(("declared body", status, body));
    let response = client
        .post(server.url(0, "/upload"))
        .body("tiny")
        .send()
        .await
        .unwrap();
    seen.push((
        "small body",
        response.status().as_u16(),
        response.text().await.unwrap(),
    ));

    // 🌊 A chunked body declares nothing, so the limit trips while it streams
    // to the upstream.
    let chunk = "x".repeat(100);
    let (status, body) = raw_exchange(
        address,
        &format!(
            "POST /proxy-upload HTTP/1.1\r\nHost: {address}\r\nTransfer-Encoding: chunked\r\n\
             Connection: close\r\n\r\n{:X}\r\n{chunk}\r\n0\r\n\r\n",
            chunk.len()
        ),
    )
    .await;
    seen.push(("streamed body", status, body));

    assert_eq!(
        seen,
        vec![
            ("proxy", 502, "<h1>page for 502</h1>".to_string()),
            ("declared body", 413, "<h1>page for 413</h1>".to_string()),
            ("small body", 200, "accepted".to_string()),
            ("streamed body", 413, "<h1>page for 413</h1>".to_string()),
        ]
    );
}

/// 🧾 A body over the limit is refused with one sentence on every framing.
///
/// The 413's body used to depend on the framing a client chose — nothing for a
/// declared length, `413 Request Entity Too Large` for a chunked upload, and a
/// body without the status line at all on HTTP/3 (#252).
#[tokio::test]
async fn test_a_body_over_the_limit_is_refused_with_one_sentence() {
    let mut server = TestServer::new_pingclairfile(
        r#"
        {
            admin off
        }

        http://__PINGCLAIR_TEST_LISTEN__ {
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            handle /upload {
                request_body {
                    max_size 10
                }
                respond "accepted"
            }
        }
        "#,
    );
    assert!(server.wait_until_ready().await, "server failed to start");
    let address = server.address(0);
    let expected = "413 Request Entity Too Large".to_string();

    // 📏 A declared length over the limit is refused before the body is read.
    let (declared_status, declared_body) = raw_exchange(
        address,
        &format!(
            "POST /upload HTTP/1.1\r\nHost: {address}\r\nContent-Length: 100\r\n\
             Connection: close\r\n\r\n"
        ),
    )
    .await;
    assert_eq!((declared_status, declared_body), (413, expected.clone()));

    // 🌊 A chunked body trips the same limit while it streams.
    let chunk = "x".repeat(100);
    let (streamed_status, streamed_body) = raw_exchange(
        address,
        &format!(
            "POST /upload HTTP/1.1\r\nHost: {address}\r\nTransfer-Encoding: chunked\r\n\
             Connection: close\r\n\r\n{:X}\r\n{chunk}\r\n0\r\n\r\n",
            chunk.len()
        ),
    )
    .await;
    assert_eq!((streamed_status, streamed_body), (413, expected.clone()));

    // 🔀 The same request over HTTP/2 carries the same sentence.
    let h2 = reqwest::Client::builder()
        .no_proxy()
        .http2_prior_knowledge()
        .build()
        .unwrap();
    let response = h2
        .post(server.url(0, "/upload"))
        .body("x".repeat(100))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 413);
    assert_eq!(response.text().await.unwrap(), expected);
    server.stop();
}

/// 🔢 Directives in `handle_errors` run in Caddy's order, not in file order.
///
/// The block used to run its directives in the order they were written, so a
/// `respond` written first answered before a `header` written after it ever
/// applied — the same block, a different site, depending on line order (#245).
#[tokio::test]
async fn test_handle_errors_applies_a_header_written_after_respond() {
    let mut server = TestServer::new_pingclairfile(
        r#"
        {
            admin off
        }

        http://__PINGCLAIR_TEST_LISTEN__ {
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            handle_errors {
                respond "page" 503
                header X-Error-Route ordered
            }

            handle /boom {
                error "exploded" 503
            }
        }
        "#,
    );
    assert!(server.wait_until_ready().await, "server failed to start");

    let response = no_proxy_client()
        .get(server.url(0, "/boom"))
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    let header = response
        .headers()
        .get("x-error-route")
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string);
    let body = response.text().await.unwrap();
    assert_eq!(
        (status, header, body),
        (503, Some("ordered".to_string()), "page".to_string())
    );
}

/// 🔌 Writes one raw HTTP/1.1 request and returns the status and body of the
/// connection-closing response.
async fn raw_exchange(address: std::net::SocketAddr, request: &str) -> (u16, String) {
    use tokio::io::AsyncWriteExt;
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let raw = String::from_utf8_lossy(&read_http1_to_end(&mut stream).await).into_owned();
    let status = raw
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let body = raw
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .unwrap_or_default();
    (status, body)
}
