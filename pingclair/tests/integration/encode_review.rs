// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🗜️ Encoding policy must survive final header and representation decisions.

use super::encode::proxy_site;
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
