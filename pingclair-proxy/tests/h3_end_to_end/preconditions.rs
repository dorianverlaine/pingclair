//! 🏷️ Conditional requests against `file_server` over HTTP/3.
//!
//! The H3 path builds its own header list, so a 304 here is only right if it
//! carries the validators and no `content-length` measured from its empty
//! body, which would tell a cache the file is empty.

use super::*;

/// 🧊 `If-None-Match` answers 304 on HTTP/3 exactly as on HTTP/1.1, and
/// `If-Match` with a stale tag answers 412.
#[tokio::test]
async fn h3_file_server_evaluates_preconditions() {
    let tree = tempfile::tempdir().expect("document root");
    std::fs::write(tree.path().join("f.txt"), b"0123456789").expect("write file");
    let root = tree.path().to_string_lossy().into_owned();
    let server =
        spawn_h3_from_pingclairfile(&format!(":443 {{\n root * {root}\n file_server\n}}")).await;

    let plain = h3_get(server, "/f.txt").await.expect("plain request");
    let field = |response: &H3Response, name: &str| {
        response
            .headers
            .iter()
            .find(|(field, _)| field == name)
            .map(|(_, value)| value.clone())
    };
    let etag = field(&plain, "etag").expect("an ETag");

    let revalidated = h3_get_with_headers(server, "/f.txt", &[("if-none-match", etag.as_str())])
        .await
        .expect("revalidation");
    let refused = h3_get_with_headers(server, "/f.txt", &[("if-match", "\"not-the-etag\"")])
        .await
        .expect("refused request");

    assert_eq!(
        [
            (
                revalidated.status,
                field(&revalidated, "etag"),
                field(&revalidated, "content-length"),
                revalidated.body.len(),
            ),
            (
                refused.status,
                None,
                field(&refused, "content-length"),
                refused.body.len()
            ),
        ],
        [(304, Some(etag), None, 0), (412, None, Some("0".into()), 0)]
    );
    assert!(
        field(&revalidated, "last-modified").is_some(),
        "a 304 keeps `last-modified`: {:?}",
        revalidated.headers
    );
}

/// 🚫 `POST` to a static file answers 405 with `Allow` on HTTP/3 too.
#[tokio::test]
async fn h3_file_server_refuses_post() {
    let tree = tempfile::tempdir().expect("document root");
    std::fs::write(tree.path().join("f.txt"), b"0123456789").expect("write file");
    let root = tree.path().to_string_lossy().into_owned();
    let server =
        spawn_h3_from_pingclairfile(&format!(":443 {{\n root * {root}\n file_server\n}}")).await;

    let response = h3_post(server, "/f.txt", b"payload").await.expect("post");
    let allow = response
        .headers
        .iter()
        .find(|(name, _)| name == "allow")
        .map(|(_, value)| value.as_str());
    assert_eq!(
        (response.status, allow, response.body.as_slice()),
        (405, Some("GET, HEAD"), &b""[..])
    );
}
