// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧭 `validate` reports the Redirect lint and still succeeds.

use std::process::Command;

fn validate(config: &std::path::Path, store: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_pingclair"))
        .arg("validate")
        .arg(config)
        .env("PINGCLAIR_TLS_STORE", store)
        .output()
        .unwrap()
}

#[test]
fn cli_validate_warns_about_braces_in_a_redirect_target() {
    let dir = tempfile::tempdir().unwrap();
    let flagged = dir.path().join("flagged.pingclair");
    std::fs::write(
        &flagged,
        r#"HTTPListener(on: "127.0.0.1:18080") {
        Site(host: "*") {
            Route(when: .path(exact: "/old")) {
                Redirect(to: "https://example.com{uri}", status: .permanentRedirect)
            }
        }
    }"#,
    )
    .unwrap();
    let output = validate(&flagged, &dir.path().join("store"));
    assert!(
        output.status.success(),
        "a lint must not fail validation: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("would be sent exactly as written"),
        "the lint did not reach stdout: {stdout}"
    );
    assert!(stdout.contains("is valid!"), "{stdout}");

    // 💬 The typed spelling says what it means and draws no warning.
    let clean = dir.path().join("clean.pingclair");
    std::fs::write(
        &clean,
        r#"HTTPListener(on: "127.0.0.1:18080") {
        Site(host: "*") {
            Route(when: .path(exact: "/old")) {
                Redirect(to: Format("https://example.com{uri}", uri: .uri))
            }
        }
    }"#,
    )
    .unwrap();
    let output = validate(&clean, &dir.path().join("store"));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("exactly as written"),
        "the typed spelling drew a warning: {stdout}"
    );
}
