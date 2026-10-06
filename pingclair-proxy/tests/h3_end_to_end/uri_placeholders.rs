//! 🧭 `uri` operands are resolved over HTTP/3 too (issue #278).
//!
//! The HTTP/3 rewrite arm is a separate copy of the HTTP/1 one, and it had
//! the same gap: only `replace` went through the placeholder resolver, so a
//! `strip_prefix` naming a regexp capture compared against literal braces and
//! stripped nothing.

use super::*;

/// 🎯 Each `uri` operation resolves its operands before touching the path.
#[tokio::test]
async fn h3_uri_operands_resolve_placeholders_before_rewriting() {
    let source = r#":443 {
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
    }"#;
    let site = pingclair_config::compile(source).unwrap().servers[0].clone();
    let server = spawn_h3_server_with(|address| ServerConfig {
        listen: vec![address.to_string()],
        ..site
    })
    .await;

    let mut answers = Vec::new();
    for path in [
        "/api/static/plain/icon.jpg",
        "/legacy/report.html",
        "/old/thing",
    ] {
        let response = h3_get(server, path).await.unwrap();
        answers.push((
            path,
            response.status,
            String::from_utf8_lossy(&response.body).into_owned(),
        ));
    }

    assert_eq!(
        answers,
        [
            (
                "/api/static/plain/icon.jpg",
                200,
                "strip_prefix /icon.jpg".to_string()
            ),
            (
                "/legacy/report.html",
                200,
                "strip_suffix /legacy/report".to_string()
            ),
            (
                "/old/thing",
                200,
                "path_regexp /new/https/thing".to_string()
            ),
        ]
    );
}
