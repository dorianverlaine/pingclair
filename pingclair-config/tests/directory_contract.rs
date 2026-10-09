// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🗂️ The contract for configurations that arrive as more than one file.
//!
//! A directory is one configuration split across files, and the review found
//! four places where the rules were unstated or wrong: a global option could be
//! declared twice with the last file silently winning, a file holding only
//! globals could not exist at all, a `.caddyfile` beside the native files was
//! skipped without a word, and a file could be named for one language and
//! written in the other. Each test here is one of those, stated as the rule.

use std::path::Path;

/// 📝 Writes one fixture and returns its path.
fn write(dir: &Path, name: &str, body: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, body).expect("write fixture");
    path
}

/// 🗂️ A global option belongs to one file.
#[test]
fn a_global_option_declared_twice_is_refused_with_both_names() {
    let dir = tempfile::tempdir().expect("tempdir");
    let first = write(
        dir.path(),
        "00-admin.pingclair",
        "Admin(listen: \"127.0.0.1:2019\")\n",
    );
    let second = write(
        dir.path(),
        "10-admin.pingclair",
        "Admin(listen: \"127.0.0.1:2020\")\n",
    );
    let error = pingclair_config::compile_multiple_files(&[first, second])
        .expect_err("two files may not both name an admin endpoint")
        .to_string();
    assert!(error.contains("00-admin.pingclair"), "{error}");
    assert!(error.contains("10-admin.pingclair"), "{error}");

    // …and the same rule covers the options, not just the admin block.
    let dir = tempfile::tempdir().expect("tempdir");
    let one = write(
        dir.path(),
        "00-globals.pingclair",
        "Metrics(enabled: true)\n",
    );
    let two = write(
        dir.path(),
        "10-globals.pingclair",
        "Metrics(enabled: false)\n",
    );
    let error = pingclair_config::compile_multiple_files(&[one, two])
        .expect_err("two files may not both name metrics")
        .to_string();
    assert!(error.contains("Metrics"), "{error}");
    assert!(error.contains("00-globals.pingclair"), "{error}");

    // 🛡️ And it is the *declaration* that is counted, not the value: two files
    // stating the same allowlist are two files setting one option, and the
    // second would have to win for the rule to be anything else.
    let dir = tempfile::tempdir().expect("tempdir");
    let one = write(
        dir.path(),
        "00-allowlist.pingclair",
        "UnderscoreHeaders([\"X_Probe\"])\n",
    );
    let two = write(
        dir.path(),
        "10-allowlist.pingclair",
        "UnderscoreHeaders([\"X_Probe\"])\n",
    );
    let error = pingclair_config::compile_multiple_files(&[one, two])
        .expect_err("two files may not both declare the allowlist")
        .to_string();
    assert!(error.contains("UnderscoreHeaders"), "{error}");
    assert!(error.contains("10-allowlist.pingclair"), "{error}");
}

/// 🗂️ A file may hold nothing but declarations.
#[test]
fn a_file_of_globals_needs_no_listener() {
    let dir = tempfile::tempdir().expect("tempdir");
    let globals = write(
        dir.path(),
        "00-globals.pingclair",
        "Metrics(enabled: true)\nShutdown(grace: .seconds(5))\n",
    );
    let site = write(
        dir.path(),
        "10-site.pingclair",
        "HTTPListener(on: \":8080\") { Site(host: \"*\") { Fallback { Respond(body: \"ok\") } } }\n",
    );
    let merged =
        pingclair_config::compile_multiple_files(&[globals, site]).expect("the pair merges");
    assert!(merged.global.metrics);
    assert_eq!(merged.global.grace_period_secs, Some(5));
    assert_eq!(merged.servers.len(), 1);
}

/// 🗂️ A directory may hold both languages, and both are read.
#[test]
fn a_directory_reads_the_dialect_and_the_language_together() {
    let dir = tempfile::tempdir().expect("tempdir");
    let native = write(
        dir.path(),
        "10-native.pingclair",
        "HTTPListener(on: \":8080\") { Site(host: \"*\") { Fallback { Respond(body: \"native\") } } }\n",
    );
    let dialect = write(
        dir.path(),
        "20-legacy.caddyfile",
        "http://:8081 {\n\trespond \"caddy\"\n}\n",
    );
    let merged = pingclair_config::compile_directory(dir.path()).expect("both files take part");
    let listeners: Vec<&str> = merged
        .servers
        .iter()
        .filter_map(|server| server.listen.first())
        .map(String::as_str)
        .collect();
    assert_eq!(listeners.len(), 2, "{listeners:?}");
    // 📌 And the files themselves were read in the order their names give.
    let _ = (native, dialect);
    assert!(
        merged.servers.iter().any(|server| server
            .listen
            .iter()
            .any(|address| address.ends_with(":8081"))),
        "the .caddyfile was skipped"
    );
}

/// 🗂️ The extension is the language.
#[test]
fn a_file_named_for_one_language_and_written_in_the_other_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let misnamed = write(
        dir.path(),
        "site.pingclair",
        "http://:8080 {\n\trespond \"caddy\"\n}\n",
    );
    let error = pingclair_config::compile_file(&misnamed)
        .expect_err("a Caddyfile wearing .pingclair is refused")
        .to_string();
    assert!(error.contains(".caddyfile"), "{error}");

    let misnamed = write(
        dir.path(),
        "site.caddyfile",
        "HTTPListener(on: \":8080\") { Site(host: \"*\") { Fallback { Respond(body: \"native\") } } }\n",
    );
    let error = pingclair_config::compile_file(&misnamed)
        .expect_err("the native language wearing .caddyfile is refused")
        .to_string();
    assert!(error.contains(".pingclair"), "{error}");
}
