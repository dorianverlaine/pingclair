// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧭 Every `uri` operand is a template, not only `rewrite`'s (issue #278).
//!
//! `uri strip_prefix /api/static/{re.sample.1}` names a prefix that exists
//! only once the `path_regexp` matcher has captured it. Before the fix the
//! strip compared the request path against the literal braces, never matched,
//! and the request went on with its path untouched — and `uri path_regexp`
//! put literal braces into the path it forwarded.

use super::TestServer;
use super::no_proxy_client;

/// 🎯 Each `uri` operation resolves its operands against the request before
/// it touches the path, the way Caddy's rewrite handler does. Before the fix
/// all three answers below were the request path, or the replacement with
/// `{http.request.scheme}` still spelled out in it.
#[tokio::test]
async fn test_uri_operands_resolve_placeholders_before_rewriting() {
    let config = r#"
        {
            admin off
        }

        http://__PINGCLAIR_TEST_LISTEN__ {
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            @images path_regexp sample ^/api/static/([^/]+)/.*\.jpg$
            handle @images {
                uri strip_prefix /api/static/{re.sample.1}
                respond "strip_prefix {path}" 200
            }
            @legacy path_regexp legacy ^/legacy/[^.]+(\.[a-z]+)$
            handle @legacy {
                uri strip_suffix {re.legacy.1}
                respond "strip_suffix {path}" 200
            }
            handle /old/* {
                uri path_regexp ^/old/(.*)$ /new/{http.request.scheme}/$1
                respond "path_regexp {path}" 200
            }
        }
    "#;
    let mut server = TestServer::new_pingclairfile(config);
    assert!(server.wait_until_ready().await, "server failed to start");

    let client = no_proxy_client();
    let mut answers = Vec::new();
    for path in [
        "/api/static/plain/icon.jpg",
        "/legacy/report.html",
        "/old/thing",
    ] {
        let reply = client.get(server.url(0, path)).send().await.unwrap();
        answers.push((path, reply.text().await.unwrap()));
    }

    assert_eq!(
        answers,
        [
            (
                "/api/static/plain/icon.jpg",
                "strip_prefix /icon.jpg".to_string()
            ),
            (
                "/legacy/report.html",
                "strip_suffix /legacy/report".to_string()
            ),
            ("/old/thing", "path_regexp /new/http/thing".to_string()),
        ]
    );
}
