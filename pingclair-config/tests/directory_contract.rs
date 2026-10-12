// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🗂️ The contract for configurations that arrive as more than one file.
//!
//! A directory is one configuration split across files, and the review found
//! places where the rules were unstated or wrong: a global option could be
//! declared twice with the last file silently winning, a file holding only
//! globals could not exist at all, and a `.caddyfile` beside the `.pingclair`
//! files was skipped without a word. Each test here is one of those, stated as
//! the rule.

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
        "{\n    admin 127.0.0.1:2019\n}\n",
    );
    let second = write(
        dir.path(),
        "10-admin.pingclair",
        "{\n    admin 127.0.0.1:2020\n}\n",
    );
    let error = pingclair_config::compile_multiple_files(&[first, second])
        .expect_err("two files may not both name an admin endpoint")
        .to_string();
    assert!(error.contains("00-admin.pingclair"), "{error}");
    assert!(error.contains("10-admin.pingclair"), "{error}");

    // …and the same rule covers the options, not just the admin block.
    let dir = tempfile::tempdir().expect("tempdir");
    let one = write(dir.path(), "00-globals.pingclair", "{\n    metrics\n}\n");
    let two = write(dir.path(), "10-globals.pingclair", "{\n    metrics\n}\n");
    let error = pingclair_config::compile_multiple_files(&[one, two])
        .expect_err("two files may not both name metrics")
        .to_string();
    assert!(error.contains("metrics"), "{error}");
    assert!(error.contains("00-globals.pingclair"), "{error}");
}

/// 🗂️ A file may hold nothing but global options.
#[test]
fn a_file_of_globals_needs_no_site() {
    let dir = tempfile::tempdir().expect("tempdir");
    let globals = write(
        dir.path(),
        "00-globals.pingclair",
        "{\n    metrics\n    grace_period 5s\n}\n",
    );
    let site = write(
        dir.path(),
        "10-site.pingclair",
        ":8080 {\n    respond \"ok\"\n}\n",
    );
    let merged =
        pingclair_config::compile_multiple_files(&[globals, site]).expect("the pair merges");
    assert!(merged.global.metrics);
    assert_eq!(merged.global.grace_period_secs, Some(5));
    assert_eq!(merged.servers.len(), 1);
}

/// 🗂️ A directory reads `.pingclair` and `.caddyfile` files alike.
#[test]
fn a_directory_reads_both_extensions() {
    let dir = tempfile::tempdir().expect("tempdir");
    write(
        dir.path(),
        "10-site.pingclair",
        ":8080 {\n    respond \"pingclair\"\n}\n",
    );
    write(
        dir.path(),
        "20-legacy.caddyfile",
        ":8081 {\n    respond \"caddy\"\n}\n",
    );
    let merged = pingclair_config::compile_directory(dir.path()).expect("both files take part");
    let mut ports: Vec<&str> = merged
        .servers
        .iter()
        .flat_map(|server| &server.listen)
        .filter_map(|address| address.rsplit_once(':').map(|(_, port)| port))
        .collect();
    ports.sort_unstable();
    assert_eq!(ports, ["8080", "8081"]);
}
