// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🪵 What a global `log { output … }` block does to the process log.
//!
//! The block used to compile, validate, and write nothing anywhere: an
//! operator asked for a file and got no file, no warning, and exit code 0.
//! These tests assert on the *artifact* — a file that exists and holds at
//! least one parseable record — rather than on the absence of an error, which
//! is the version of this test the bug would pass.
//!
//! 📌 Both tests drive the real binary through the shared harness, so what is
//! checked is the process logger this server actually installs.
//!
//! 🧭 One thing a `log` block does **not** move: the `🚀 Pingclair running...`
//! banner is a plain write to stdout, and supervisors — this harness among them
//! — read it there to know the process came up. A configuration that sends its
//! records to a file must not blind the thing watching the process.

use super::TestServer;
use std::path::Path;
use std::time::{Duration, Instant};

/// 🧽 A record with its colour escapes removed.
///
/// 📌 stdout and stderr keep the escapes — that stream has always carried them,
/// and a terminal is where it usually lands — so an assertion about what a
/// record *says* has to read past them. The file sink turns them off, which is
/// why the JSON test asserts on the raw bytes.
fn plain(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut escaping = false;
    for ch in text.chars() {
        match ch {
            '\u{1b}' => escaping = true,
            'm' if escaping => escaping = false,
            _ if !escaping => out.push(ch),
            _ => {}
        }
    }
    out
}

/// ⏳ Waits for `path` to hold `needle`, giving up after twenty seconds.
///
/// 📌 Absence and unreadability are the same answer here: the file may not
/// exist yet, and a half-written line is not the record being waited for.
async fn wait_for(path: &Path, needle: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let contents = std::fs::read_to_string(path).unwrap_or_default();
        if contents.contains(needle) {
            return contents;
        }
        assert!(
            Instant::now() < deadline,
            "{} never received {needle:?}; it holds:\n{contents}",
            path.display()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test]
async fn a_global_log_file_is_created_and_carries_a_record() {
    let log_dir = tempfile::tempdir().expect("a directory for the log file");
    let log_path = log_dir.path().join("process.log");
    let config = format!(
        "{{\n\tadmin off\n\tlog {{\n\t\toutput file {}\n\t\tformat json\n\t}}\n}}\n\n\
         http://__PINGCLAIR_TEST_LISTEN__ {{\n\
         \t@readiness path __PINGCLAIR_TEST_READINESS_PATH__\n\
         \trespond @readiness \"__PINGCLAIR_TEST_READINESS_TOKEN__\"\n\
         \trespond \"ok\"\n}}\n",
        log_path.display()
    );

    let mut server = TestServer::new_pingclairfile(&config);
    assert!(server.wait_until_ready().await, "server failed to start");

    // 🧭 Caddy logs the redirection itself, and an operator reading the file
    // has to be able to see this server say where its own records go.
    let contents = wait_for(&log_path, "Process log destination").await;
    assert!(
        contents.contains("process.log"),
        "the destination record must name the file:\n{contents}"
    );

    // 🚫 The assertion the issue asks for is "a record", not "no error": a file
    // that exists and is empty would satisfy the weaker version.
    let records: Vec<&str> = contents.lines().filter(|line| !line.is_empty()).collect();
    assert!(
        !records.is_empty(),
        "the log file exists but holds no records:\n{contents}"
    );
    let parsed: serde_json::Value = serde_json::from_str(records[0])
        .unwrap_or_else(|error| panic!("the first record is not JSON: {error}\n{contents}"));
    assert!(
        parsed.get("level").is_some() && parsed.get("target").is_some(),
        "a record has to carry a level and a target, got {parsed}"
    );
    // 🎨 A file is not a terminal: colour escapes would be invisible in a pager
    // and noise in a grep, and every other file logger here writes plain bytes.
    assert!(
        !contents.contains('\u{1b}'),
        "a log file must not carry terminal escapes:\n{contents:?}"
    );

    // 🚪 And the process is actually serving: the file is not evidence of a
    // server that started logging and then failed to bind.
    let client = super::no_proxy_client();
    let response = client
        .get(server.url(0, &server.readiness_path))
        .send()
        .await
        .expect("the site must answer");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response.text().await.expect("a body"),
        server.readiness_token
    );
    server.stop();
}

/// 🪵 `output stderr` moves the records, and does not duplicate them.
#[tokio::test]
async fn a_global_log_on_stderr_moves_the_records_without_copying_them() {
    let config = "{\n\tadmin off\n\tlog {\n\t\toutput stderr\n\t}\n}\n\n\
                  http://__PINGCLAIR_TEST_LISTEN__ {\n\
                  \t@readiness path __PINGCLAIR_TEST_READINESS_PATH__\n\
                  \trespond @readiness \"__PINGCLAIR_TEST_READINESS_TOKEN__\"\n\
                  \trespond \"ok\"\n}\n";

    let mut server = TestServer::new_pingclairfile(config);
    assert!(server.wait_until_ready().await, "server failed to start");

    // 📌 Text here, not JSON: this fixture leaves the format alone, which is
    // also what pins the *default* rendering — the unconfigured process output
    // keeps the shape its readers, human and script, already parse.
    let stderr = wait_for(&server.stderr_path, "Process log destination").await;
    assert!(
        plain(&stderr).contains("sink=stderr"),
        "the destination record has to name stderr:\n{}",
        plain(&stderr)
    );

    // 🔁 The same records must not also land on stdout: a sink that is *added*
    // rather than moved would double every line. The banner is the one thing
    // that stays, and it is what the readiness poll above reads.
    let stdout = std::fs::read_to_string(&server.stdout_path).expect("the captured stdout");
    assert!(
        stdout.contains(super::STARTUP_BANNER),
        "supervisors read the banner on stdout, so it must stay there:\n{stdout}"
    );
    assert!(
        !plain(&stdout).contains("Process log destination"),
        "the records must move to stderr rather than be copied to both:\n{stdout}"
    );

    let client = super::no_proxy_client();
    let response = client
        .get(server.url(0, &server.readiness_path))
        .send()
        .await
        .expect("the site must answer");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    server.stop();
}
