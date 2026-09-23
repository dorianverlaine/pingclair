// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔐 The admin API's 401 tells a client which credentials would work.
//!
//! RFC 9110 §15.5.2 requires every 401 to carry a `WWW-Authenticate`
//! challenge. The admin listener accepts only `Authorization: Bearer <key>`,
//! so that is the scheme it must name; a bare 401 leaves a client guessing.

use super::{TestServer, no_proxy_client};

/// 🔐 A missing key and a wrong key both get the Bearer challenge, and the
/// JSON error body is labelled as JSON.
#[tokio::test]
async fn test_admin_unauthorized_names_the_bearer_scheme() {
    const KEY: &str = "issue-92-test-key";

    let config = format!(
        r#"
        {{
            admin __PINGCLAIR_TEST_ADMIN_LISTEN__ {KEY}
        }}

        :__PINGCLAIR_TEST_PORT__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"
        }}
    "#
    );
    let mut server = TestServer::new_pingclairfile(&config).with_admin_key(KEY);
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();

    for authorization in [None, Some("Bearer not-the-key")] {
        let mut request = client.get(server.admin_url("/config"));
        if let Some(value) = authorization {
            request = request.header("Authorization", value);
        }
        let refused = request.send().await.expect("request");
        let headers = refused.headers();
        assert_eq!(
            (
                refused.status().as_u16(),
                headers.get("www-authenticate").map(|v| v.as_bytes()),
                headers.get("content-type").map(|v| v.as_bytes()),
            ),
            (401, Some(&b"Bearer"[..]), Some(&b"application/json"[..])),
            "authorization {authorization:?}"
        );
    }
}
