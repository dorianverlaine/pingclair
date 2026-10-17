// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔇 Extra access-log fields and named-logger selection.

use std::time::Duration;

use super::{TestServer, no_proxy_client, wait_for_captured_line};

#[tokio::test]
async fn log_append_adds_fields_and_log_name_selects_one_destination() {
    let dir = tempfile::tempdir().expect("test directory");
    let audit = dir.path().join("audit.log");
    let other = dir.path().join("other.log");
    let config = format!(
        r#"
        {{
            admin off
        }}

        http://__PINGCLAIR_TEST_LISTEN__ {{
            @readiness path __PINGCLAIR_TEST_READINESS_PATH__
            respond @readiness "__PINGCLAIR_TEST_READINESS_TOKEN__"

            log audit {{
                output file {}
                format json
            }}
            log other {{
                output file {}
                format json
            }}
            log_append trace {{path}}
            log_append mapped mapped
            log_name audit

            map {{path}} {{mapped}} {{
                /logged hello
                default unused
            }}
            respond "ok"
        }}
        "#,
        audit.display(),
        other.display()
    );
    let mut server = TestServer::new_pingclairfile(&config);
    assert!(server.wait_until_ready().await, "server failed to start");

    let response = no_proxy_client()
        .get(server.url(0, "/logged"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let recorded =
        wait_for_captured_line(&audit, "\"path\":\"/logged\"", Duration::from_secs(10)).await;
    assert!(
        recorded.contains("\"trace\":\"/logged\""),
        "log_append must resolve a placeholder: {recorded}"
    );
    assert!(
        recorded.contains("\"mapped\":\"hello\""),
        "log_append must read a request variable by its bare name: {recorded}"
    );
    assert!(
        std::fs::read_to_string(&other)
            .unwrap_or_default()
            .is_empty(),
        "log_name must select the named logger instead of every destination"
    );
}
