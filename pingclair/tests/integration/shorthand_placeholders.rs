// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧩 Caddy's shorthand placeholders, end to end.
//!
//! The configuration below is Caddy's own corpus fixture
//! (`caddytest/integration/caddyfile_adapt/shorthand_parameterized_placeholders.caddyfiletest`),
//! reduced to a site address the harness can bind. It is where the failure in
//! #135 came from, and it exercised two defects at once: `respond * "…"`
//! answered with the single byte `*` because the matcher token reached the
//! body reader, and the shorthand names resolved to nothing because only the
//! long forms were known.

use super::{TestServer, no_proxy_client};

/// 🧩 Every shorthand in the fixture resolves, with `{re.N}` reading the
/// capture of the matcher that ran.
#[tokio::test]
async fn test_caddy_shorthand_placeholders_resolve() {
    let mut server = TestServer::new_pingclairfile(
        r#"
        {
            admin off
        }

        http://:__PINGCLAIR_TEST_PORT__ {
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            @match path_regexp ^/foo(.*)$
            respond @match "{re.1}"

            respond * "{header.content-type} {labels.0} {query.p} {path.0} {re.name.0}"
        }
        "#,
    );
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();

    // 🌐 The wildcard form: a matcher token, then the body. The body is the
    // placeholders, not `*`.
    let wildcard = client
        .get(server.url(0, "/other?p=hello"))
        .header("Content-Type", "text/x-probe")
        .header("Host", "sub.example.test")
        .send()
        .await
        .unwrap();
    let status = wildcard.status().as_u16();
    let body = wildcard.text().await.unwrap();
    assert_eq!(status, 200);
    assert_eq!(
        body, "text/x-probe test hello other ",
        "header, host label, query parameter and path segment must resolve; \
         the unmatched regexp capture is empty"
    );

    // 🔢 The regexp form: `{re.1}` is capture group 1 of the matcher that ran,
    // which for `^/foo(.*)$` is `/bar` — the group begins right after `foo`,
    // and `{re.0}` would be the whole match. Caddy numbers the groups the same
    // way (`MatchRegexp.Match`, `modules/caddyhttp/matchers.go`: index 0 is
    // `FindStringSubmatch`'s first element, the whole match).
    let captured = client.get(server.url(0, "/foo/bar")).send().await.unwrap();
    assert_eq!(captured.status().as_u16(), 200);
    assert_eq!(captured.text().await.unwrap(), "/bar");
}
