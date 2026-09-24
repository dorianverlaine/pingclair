// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🏷️ What the binary says its version is.
//!
//! 📌 The default branch carries version 0.0.0 and a release commit sets the
//! real number. A build of main must never present itself as a release, so
//! it reports `0.0.0-dev+<sha>`; a release build reports exactly its
//! version, which is what the release workflow compares against the tag.

use std::process::Command;

/// 🏷️ The version string a binary built from this checkout must report.
fn expected_version() -> String {
    let package = env!("CARGO_PKG_VERSION");
    if package != "0.0.0" {
        return package.to_owned();
    }
    // 📦 The build script falls back to a bare `-dev` when git cannot name
    // the commit, and so does this expectation.
    let sha = Command::new("git")
        .args(["rev-parse", "--short=10", "HEAD"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|sha| !sha.is_empty());
    match sha {
        Some(sha) => format!("0.0.0-dev+{sha}"),
        None => "0.0.0-dev".to_owned(),
    }
}

fn run(args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_pingclair"))
        .args(args)
        .output()
        .unwrap();
    assert!(output.status.success(), "{args:?} failed: {output:?}");
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn test_every_version_surface_names_the_same_build() {
    let version = expected_version();
    assert_eq!(run(&["version"]), format!("v{version}\n"));
    assert_eq!(run(&["--version"]), format!("pingclair {version}\n"));
    assert_eq!(
        run(&["build-info"]).lines().next(),
        Some(format!("pingclair v{version}").as_str())
    );
    // 🧩 `list-modules --versions` prints Caddy's `<module> v<version>` shape.
    let modules = run(&["list-modules", "--versions"]);
    let first = modules.lines().next().unwrap_or_default();
    assert!(
        first.ends_with(&format!(" v{version}")),
        "list-modules --versions must carry the build version: {first}"
    );
}
