// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🚫 A site that turned HTTP/3 off is not advertised over it.
//!
//! Two sites share one HTTPS port and therefore one QUIC listener. The QUIC
//! handshake for the opted-out site is refused on purpose, so an `Alt-Svc`
//! header on that site's TCP responses would send every client to a handshake
//! that cannot succeed, and the client would keep trying for the whole
//! advertised day (RFC 7838 §3.1).

use super::TestServer;

/// 🧾 `on.test` keeps HTTP/3; `off.test` opts out with `tls { http3 off }`.
const MIXED_SITES: &str = r#"
    {
        admin off
        http_port __PINGCLAIR_TEST_HTTP_PORT__
        https_port __PINGCLAIR_TEST_HTTPS_PORT__
        servers {
            protocols h1 h2 h3
        }
    }

    https://on.test:__PINGCLAIR_TEST_HTTPS_PORT__ {
        tls internal
        @readiness path __PINGCLAIR_TEST_READINESS_PATH__
        respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
        respond "on"
    }

    https://off.test:__PINGCLAIR_TEST_HTTPS_PORT__ {
        tls {
            internal
            http3 off
        }
        respond "off"
    }
"#;

/// 🔐 A client that trusts the fixture's internal authority and resolves
/// both site names to the shared listener.
fn trusting_client(server: &TestServer, http2: bool) -> reqwest::Client {
    let root_path = server
        ._temp_dir
        .path()
        .join("tls/pki/authorities/local/root.crt");
    let root = reqwest::Certificate::from_pem(&std::fs::read(root_path).unwrap()).unwrap();
    let builder = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(root)
        .resolve("on.test", server.address(0))
        .resolve("off.test", server.address(0));
    let builder = if http2 {
        builder.http2_prior_knowledge()
    } else {
        builder.http1_only()
    };
    builder.build().unwrap()
}

/// 🚫 Over HTTP/1.1 and HTTP/2 alike, only the site still served over QUIC
/// carries `Alt-Svc`.
#[tokio::test]
async fn test_alt_svc_is_withheld_from_a_site_with_http3_off() {
    let mut server = TestServer::new_pingclairfile(MIXED_SITES);
    assert!(
        server.wait_until_tls_ready("on.test").await,
        "the `tls internal` sites did not start"
    );
    let expected = format!("h3=\":{}\"; ma=86400", server.address(0).port());

    for (http2, version) in [
        (false, reqwest::Version::HTTP_11),
        (true, reqwest::Version::HTTP_2),
    ] {
        let client = trusting_client(&server, http2);
        let mut seen = Vec::new();
        for host in ["on.test", "off.test"] {
            let response = client
                .get(server.tls_url(0, host, "/"))
                .send()
                .await
                .unwrap();
            assert_eq!(response.version(), version);
            let alt_svc = response
                .headers()
                .get("alt-svc")
                .map(|value| value.to_str().unwrap().to_owned());
            seen.push((host, response.text().await.unwrap(), alt_svc));
        }
        assert_eq!(
            seen,
            [
                ("on.test", "on".to_owned(), Some(expected.clone())),
                ("off.test", "off".to_owned(), None),
            ],
            "{version:?}"
        );
    }
}
