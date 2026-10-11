// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 💬 Typed text values resolve against the request on H1 and H2: `Format(…)`
//! composes text with sources, `from:` names one, and `header_down` resolves
//! like every other response-side value.

use super::{TestServer, read_until_marker};
use std::time::Duration;
use tokio::io::AsyncWriteExt;

/// 🪞 An origin that answers a request with its own request head.
async fn echo_origin(requests: usize) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let origin = tokio::spawn(async move {
        for _ in 0..requests {
            let (mut stream, _) = listener.accept().await.unwrap();
            let head = read_until_marker(&mut stream, b"\r\n\r\n", Duration::from_secs(2)).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                head.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.write_all(&head).await.unwrap();
        }
    });
    (address, origin)
}

#[tokio::test]
async fn typed_text_resolves_redirects_headers_and_error_bodies() {
    let (address, origin) = echo_origin(2).await;
    let source = format!(
        r#"HTTPListener(on: "__PINGCLAIR_TEST_LISTEN__") {{
        Site(host: "*") {{
            Route(when: .path(exact: "__PINGCLAIR_TEST_READINESS_PATH__")) {{
                Respond(body: "__PINGCLAIR_TEST_READINESS_TOKEN__")
            }}
            Route(when: .path(exact: "/go")) {{
                Redirect(to: Format("https://pingclair.com{{uri}}", uri: .uri),
                         status: .permanentRedirect)
            }}
            Route(when: .path(exact: "/boom")) {{ Fail(status: 503) }}
            ErrorRoute(for: [.serverError]) {{
                ResponseHeader(.set("X-Code", from: .errorStatus))
                Respond(body: Format("status {{code}} at {{u}}", code: .errorStatus, u: .uri))
            }}
            Fallback {{
                RequestHeader(.set("X-Real-IP", from: .clientIP))
                ResponseHeader(.set("X-Upstream-Host", Format("{{h}}:8443", h: .host)))
                Proxy(to: "{address}")
            }}
        }}
    }}"#
    );
    let mut server = TestServer::new_native(&source);
    assert!(server.wait_until_ready().await, "server failed to start");

    let h1 = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let h2 = reqwest::Client::builder()
        .no_proxy()
        .http2_prior_knowledge()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    for (client, version) in [
        (h1, reqwest::Version::HTTP_11),
        (h2, reqwest::Version::HTTP_2),
    ] {
        // ➡️ `Format("…{uri}", uri: .uri)` keeps the target, query included.
        let response = client.get(server.url(0, "/go?x=1")).send().await.unwrap();
        assert_eq!(response.version(), version);
        assert_eq!(response.status().as_u16(), 308);
        assert_eq!(
            response.headers()["location"],
            "https://pingclair.com/go?x=1"
        );

        // 🚨 An error-route body and header read the raised status.
        let response = client.get(server.url(0, "/boom")).send().await.unwrap();
        assert_eq!(response.status().as_u16(), 503);
        assert_eq!(response.headers()["x-code"], "503");
        assert_eq!(response.text().await.unwrap(), "status 503 at /boom");

        // 💬 A source feeds the upstream request and the response.
        let response = client.get(server.url(0, "/echo")).send().await.unwrap();
        assert_eq!(
            response.headers()["x-upstream-host"],
            "127.0.0.1:8443",
            "`.host` is the hostname without the port, so the template adds one"
        );
        let head = response.text().await.unwrap().to_ascii_lowercase();
        assert!(head.contains("x-real-ip: 127.0.0.1"), "{head}");
    }
    origin.await.unwrap();
}

/// 🗄️ A proxy's `header_down` resolves against the request: `{host}` used to
/// be written to the client verbatim (the one path that stored its text
/// ready-made), which this pins for the Caddyfile spelling too.
#[tokio::test]
async fn proxy_header_down_values_resolve_against_the_request() {
    let (address, origin) = echo_origin(1).await;
    let source = format!(
        r#"
        {{
            admin off
        }}

        http://__PINGCLAIR_TEST_LISTEN__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            reverse_proxy {address} {{
                header_down X-Test "{{host}}"
                header_down X-Plain "literal"
            }}
        }}
        "#
    );
    let mut server = TestServer::new_pingclairfile(&source);
    assert!(server.wait_until_ready().await, "server failed to start");

    let response = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .get(server.url(0, "/"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.headers()["x-test"], "127.0.0.1");
    assert_eq!(response.headers()["x-plain"], "literal");
    origin.await.unwrap();
}
