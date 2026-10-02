// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🗜️ Encoding policy must survive the final header and representation decisions.

use super::encode::{origin, proxy_site};
use super::*;

#[tokio::test]
async fn local_policy_preserves_encoding_vary() {
    let tree = compressible_tree();
    let client = no_proxy_client();
    for encode in ["", "encode gzip"] {
        for policy in ["header Vary Origin", "header -Vary"] {
            let mut server = file_server_site(
                tree.path().to_str().unwrap(),
                &format!("{encode}\n{policy}"),
            );
            assert!(server.wait_until_ready().await);
            let response = client
                .get(server.url(0, "/big.txt"))
                .header("Accept-Encoding", "gzip")
                .send()
                .await
                .unwrap();
            let vary: Vec<_> = response
                .headers()
                .get_all("vary")
                .iter()
                .flat_map(|value| value.to_str().unwrap().split(','))
                .map(str::trim)
                .collect();
            let expected = if policy == "header -Vary" {
                vec!["Accept-Encoding"]
            } else {
                vec!["Origin", "Accept-Encoding"]
            };
            assert_eq!(vary, expected, "{encode}: {policy}");
            server.stop();
        }
    }
    let unavailable = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = unavailable.local_addr().unwrap();
    drop(unavailable);
    let mut server = proxy_site(address, "encode gzip\nheader Vary Origin");
    assert!(server.wait_until_ready().await);
    let response = client.get(server.url(0, "/text")).send().await.unwrap();
    assert_eq!(response.status(), 502);
    let vary: Vec<_> = response
        .headers()
        .get_all("vary")
        .iter()
        .flat_map(|value| value.to_str().unwrap().split(','))
        .map(str::trim)
        .collect();
    assert_eq!(vary, ["Origin", "Accept-Encoding"]);
    server.stop();
}

#[tokio::test]
async fn static_gzip_quality_has_distinct_validators() {
    let tree = compressible_tree();
    let client = no_proxy_client();
    let mut variants = Vec::new();
    for level in [1, 9] {
        let mut server = file_server_site(
            tree.path().to_str().unwrap(),
            &format!("encode {{\ngzip {level}\n}}"),
        );
        assert!(server.wait_until_ready().await);
        let response = client
            .get(server.url(0, "/big.txt"))
            .header("Accept-Encoding", "gzip")
            .send()
            .await
            .unwrap();
        let tag = response.headers()["etag"].clone();
        let wire = response.bytes().await.unwrap();
        let identity = client.get(server.url(0, "/big.txt")).send().await.unwrap();
        variants.push((tag, wire, identity.headers()["etag"].clone()));
        if variants.len() == 2 {
            let response = client
                .get(server.url(0, "/big.txt"))
                .header("Accept-Encoding", "gzip")
                .header("If-None-Match", &variants[0].0)
                .send()
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                200,
                "another quality cannot validate these bytes"
            );
        }
        server.stop();
    }
    assert_ne!(variants[0].1, variants[1].1);
    assert_ne!(variants[0].0, variants[1].0);
    assert_eq!(variants[0].2, variants[1].2);
}

#[tokio::test]
async fn request_no_transform_disables_proxy_encoding() {
    let (address, task) = origin().await;
    let mut server = proxy_site(address, "encode gzip");
    assert!(server.wait_until_ready().await);
    let client = no_proxy_client();
    for (lines, encoded) in [
        (vec!["max-age=0"], true),
        (vec!["max-age=0, No-Transform"], false),
        (vec!["max-age=0", "no-transform"], false),
    ] {
        let mut request = client
            .get(server.url(0, "/text"))
            .header("Accept-Encoding", "gzip");
        for line in lines {
            request = request.header("Cache-Control", line);
        }
        let response = request.send().await.unwrap();
        assert_eq!(response.headers().contains_key("content-encoding"), encoded);
        if !encoded {
            assert_eq!(
                response.bytes().await.unwrap(),
                "compressible text ".repeat(512).as_bytes()
            );
        }
    }
    server.stop();
    task.abort();
}

#[tokio::test]
async fn static_matchers_read_policy_headers() {
    let tree = compressible_tree();
    let client = no_proxy_client();
    for (matcher, policy, expected) in [
        ("header X-Encode yes", "header X-Encode yes", true),
        ("header !X-Encode", "header X-Encode yes", false),
        (
            "header Content-Type application/json*",
            "header Content-Type application/json",
            true,
        ),
        ("header !Content-Type", "header -Content-Type", true),
    ] {
        let settings = format!("{policy}\nencode {{\ngzip\nmatch {{\n{matcher}\n}}\n}}");
        let mut server = file_server_site(tree.path().to_str().unwrap(), &settings);
        assert!(server.wait_until_ready().await);
        let response = client
            .get(server.url(0, "/big.txt"))
            .header("Accept-Encoding", "gzip")
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.headers().contains_key("content-encoding"),
            expected,
            "{matcher}"
        );
        let tag = response.headers()["etag"].clone();
        let revalidated = client
            .get(server.url(0, "/big.txt"))
            .header("Accept-Encoding", "gzip")
            .header("If-None-Match", tag)
            .send()
            .await
            .unwrap();
        assert_eq!(
            revalidated.status(),
            304,
            "selection and preconditions must agree"
        );
        server.stop();
    }
}
