// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

use super::{TestServer, raw_get_status_and_location};

const SECURE: &str = r#"
    {
        admin off
        http_port __PINGCLAIR_TEST_HTTP_PORT__
        https_port __PINGCLAIR_TEST_HTTPS_PORT__
    }
    example.test {
        tls internal
        @readiness path __PINGCLAIR_TEST_READINESS_PATH__
        respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
        respond "secure"
    }
"#;

#[tokio::test]
async fn default_https_redirect_omits_port_and_preserves_host_case() {
    let mut server = TestServer::new_pingclairfile(SECURE);
    assert!(server.wait_until_tls_ready("example.test").await);
    let mut seen = Vec::new();
    let hosts = ["ExAmPlE.TeSt", "UnKnOwN.TeSt", "[::1]", "[2001:DB8::1]"];
    for host in hosts {
        let (status, location) =
            raw_get_status_and_location(server.listener_address(0, 1), host).await;
        seen.push((status, location));
    }
    assert_eq!(
        seen,
        hosts.map(|host| (
            "HTTP/1.1 308 Permanent Redirect".into(),
            Some(format!("https://{host}/"))
        ))
    );
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let response = client
        .get(format!("http://{}/A?b=1", server.listener_address(0, 1)))
        .header("Host", "UnKnOwN.TeSt:1234")
        .send()
        .await
        .unwrap();
    assert_eq!(
        (
            response.status().as_u16(),
            response
                .headers()
                .get("location")
                .unwrap()
                .to_str()
                .unwrap()
        ),
        (308, "https://UnKnOwN.TeSt/A?b=1")
    );
}

#[tokio::test]
async fn nondefault_https_redirect_keeps_site_port() {
    let config = SECURE
        .replace("https_port __PINGCLAIR_TEST_HTTPS_PORT__", "https_port 443")
        .replace(
            "example.test {",
            "https://example.test:__PINGCLAIR_TEST_HTTPS_PORT__ {",
        );
    let mut server = TestServer::new_pingclairfile(&config);
    assert!(server.wait_until_tls_ready("example.test").await);
    let (status, location) =
        raw_get_status_and_location(server.listener_address(0, 1), "ExAmPlE.TeSt").await;
    assert_eq!(
        (status, location),
        (
            "HTTP/1.1 308 Permanent Redirect".into(),
            Some(format!(
                "https://ExAmPlE.TeSt:{}/",
                server.address(0).port()
            ))
        )
    );
}

#[tokio::test]
async fn disable_redirects_does_not_bind_plaintext_port() {
    let config = SECURE.replace("admin off", "admin off\n auto_https disable_redirects");
    let mut server = TestServer::new_pingclairfile(&config);
    assert!(server.wait_until_tls_ready("example.test").await);
    assert!(
        tokio::net::TcpStream::connect(server.listener_address(0, 1))
            .await
            .is_err()
    );
    assert!(std::net::TcpListener::bind(server.listener_address(0, 1)).is_ok());
}

#[tokio::test]
async fn unmatched_plaintext_site_returns_empty_success() {
    let mut server = TestServer::new_pingclairfile(
        r#"
        {
            admin off
        }
        http://127.0.0.1:__PINGCLAIR_TEST_PORT__ {
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
            respond "plain"
        }
    "#,
    );
    assert!(server.wait_until_ready().await);
    let mut seen = Vec::new();
    for http2 in [false, true] {
        let builder = reqwest::Client::builder()
            .no_proxy()
            .resolve("other.test", server.address(0));
        let client = if http2 {
            builder.http2_prior_knowledge()
        } else {
            builder.http1_only()
        }
        .build()
        .unwrap();
        let response = client
            .get(format!("http://other.test:{}/", server.address(0).port()))
            .send()
            .await
            .unwrap();
        seen.push((
            response.version(),
            response.status().as_u16(),
            response.headers().get("location").cloned(),
            response.text().await.unwrap(),
        ));
    }
    assert_eq!(
        seen,
        [
            (reqwest::Version::HTTP_11, 200, None, String::new()),
            (reqwest::Version::HTTP_2, 200, None, String::new()),
        ]
    );
}

#[tokio::test]
async fn hostless_http10_request_has_no_redirect() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut server = TestServer::new_pingclairfile(SECURE);
    assert!(server.wait_until_tls_ready("example.test").await);
    let mut stream = tokio::net::TcpStream::connect(server.listener_address(0, 1))
        .await
        .unwrap();
    stream
        .write_all(b"GET / HTTP/1.0\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    assert!(
        response.lines().next().unwrap().contains("404"),
        "{response}"
    );
    assert!(
        !response.to_ascii_lowercase().contains("location:"),
        "{response}"
    );
}
