// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🙈 What the admin API's configuration reads show of a configured secret.
//!
//! The admin `api_key` and a DNS provider's arguments are secrets. Anyone who
//! can read `/config` — an operator's dashboard, a support bundle, a backup
//! job — used to receive them in plain text, including the very key that
//! guards the endpoint. Reads now show a placeholder, and a document carrying
//! the placeholder is refused by `/load`, so an export posted back as-is cannot
//! replace the real key with a well-known string.

use super::{TestServer, no_proxy_client};

const KEY: &str = "export-test-admin-key";
const TOKEN: &str = "export-test-dns-token";

/// 🧾 An admin listener guarded by `KEY`, and a DNS provider holding `TOKEN`.
fn secret_bearing_server() -> TestServer {
    TestServer::new_pingclairfile(&format!(
        r#"
        {{
            admin __PINGCLAIR_TEST_ADMIN_LISTEN__ {KEY}
            dns cloudflare {TOKEN}
        }}

        http://__PINGCLAIR_TEST_LISTEN__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            respond "ok"
        }}
        "#
    ))
    .with_admin_key(KEY)
}

/// 🙈 `/config` and its subtree reads mask every secret, and the masked export
/// cannot be loaded back over the real one.
#[tokio::test]
async fn test_admin_config_reads_mask_secrets() {
    let mut server = secret_bearing_server();
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();
    let read = |path: &'static str| {
        let request = client.get(server.admin_url(path)).bearer_auth(KEY);
        async move { request.send().await.unwrap().text().await.unwrap() }
    };

    let whole = read("/config").await;
    let document: serde_json::Value = serde_json::from_str(&whole).unwrap();
    let subtree_key: serde_json::Value =
        serde_json::from_str(&read("/config/admin/api_key").await).unwrap();
    let subtree_dns: serde_json::Value =
        serde_json::from_str(&read("/config/global/dns").await).unwrap();
    assert_eq!(
        (
            document["admin"]["api_key"].clone(),
            document["global"]["dns"].clone(),
            subtree_key,
            subtree_dns,
        ),
        (
            serde_json::json!("[redacted]"),
            serde_json::json!({ "name": "cloudflare", "arguments": ["[redacted]"] }),
            serde_json::json!("[redacted]"),
            serde_json::json!({ "name": "cloudflare", "arguments": ["[redacted]"] }),
        )
    );
    assert!(
        !whole.contains(KEY) && !whole.contains(TOKEN),
        "no secret anywhere in the export: {whole}"
    );

    // 🚫 Posting the export back unchanged would make `[redacted]` the admin
    // key. It is refused, and the real key keeps working.
    let reload = client
        .post(server.admin_url("/load"))
        .bearer_auth(KEY)
        .json(&document)
        .send()
        .await
        .unwrap();
    let refused = (
        reload.status().is_client_error(),
        reload.text().await.unwrap(),
    );
    assert!(refused.0, "a masked export must be refused: {}", refused.1);
    assert!(
        refused.1.contains("redacted"),
        "the refusal says why: {}",
        refused.1
    );
    let still_guarded = client
        .get(server.admin_url("/config"))
        .bearer_auth(KEY)
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(still_guarded, reqwest::StatusCode::OK);
}

/// 🙈 Credentials written into header and environment directives are masked
/// too, and a masked one cannot be posted back.
///
/// They are plain strings in the configuration, not `SecretString`s, so the
/// first round of masking passed them through: `header_up Authorization …`
/// and `X-API-Key` reached every reader of `/config`.
#[tokio::test]
async fn test_admin_config_reads_mask_configured_credentials() {
    let mut server = TestServer::new_pingclairfile(
        r#"
        {
            admin __PINGCLAIR_TEST_ADMIN_LISTEN__
        }

        http://__PINGCLAIR_TEST_LISTEN__ {
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            reverse_proxy http://127.0.0.1:9 {
                header_up Authorization "Bearer upstream-credential"
                header_up X-API-Key upstream-api-key
                header_up X-Plain visible-value
            }
        }
        "#,
    );
    assert!(server.wait_until_ready().await, "server failed to start");
    let client = no_proxy_client();

    let whole = client
        .get(server.admin_url("/config"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(
        (
            whole.contains("upstream-credential"),
            whole.contains("upstream-api-key"),
            whole.contains("visible-value"),
        ),
        (false, false, true),
        "credentials masked, ordinary values kept: {whole}"
    );

    let document: serde_json::Value = serde_json::from_str(&whole).unwrap();
    let reload = client
        .post(server.admin_url("/load"))
        .json(&document)
        .send()
        .await
        .unwrap();
    let refused = (
        reload.status().is_client_error(),
        reload.text().await.unwrap(),
    );
    assert!(
        refused.0 && refused.1.contains("redacted"),
        "a masked credential must be refused: {}",
        refused.1
    );
}
