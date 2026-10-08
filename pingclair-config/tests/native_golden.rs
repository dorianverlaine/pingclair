// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧊 The native language's examples, frozen with the exact output they compile
//! to.
//!
//! The corpus in `examples/` is the readable half: one feature per file, the
//! shape a person would write. This is the other half — the compiled JSON, byte
//! for byte, so a refactor that quietly changes what a component *means* cannot
//! pass by compiling. Every native batch so far has been checked against the
//! Caddyfile's output for the same configuration; that comparison is the
//! strongest net this project has had, and it is also one we may retire. The
//! examples' own output is the net that stays.
//!
//! # ✍️ Updating one
//!
//! ```bash
//! UPDATE_GOLDEN=1 cargo +1.99.0 test -p pingclair-config --test native_golden
//! ```
//!
//! Then **read the diff**. Regenerating is how a golden is maintained;
//! regenerating without looking is how it becomes a record of whatever the code
//! happened to do.

use std::path::{Path, PathBuf};

/// 📂 The workspace root: this crate sits one level below it.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("pingclair-config sits one level below the workspace root")
        .to_path_buf()
}

fn examples_dir() -> PathBuf {
    workspace_root().join("examples")
}

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("native")
}

/// 📄 Every native example, in a stable order.
///
/// The Caddyfile-dialect files live under `examples/caddyfile/` and are read by
/// the compatibility layer's own tests; this one freezes the native corpus.
fn native_sources() -> Vec<PathBuf> {
    let mut sources: Vec<PathBuf> = std::fs::read_dir(examples_dir())
        .expect("the examples directory must exist")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_file()
                && (path
                    .extension()
                    .is_some_and(|extension| extension == "pingclair")
                    || path.file_name().is_some_and(|name| name == "Pingclairfile"))
        })
        .collect();
    sources.sort();
    sources
}

/// 🧊 Where one example's frozen output lives.
fn golden_path(source: &Path) -> PathBuf {
    let stem = source
        .file_stem()
        .and_then(|stem| stem.to_str())
        .expect("an example has a UTF-8 file name");
    golden_dir().join(format!("{stem}.json"))
}

#[test]
fn every_native_example_compiles_to_exactly_what_it_says() {
    let updating = std::env::var_os("UPDATE_GOLDEN").is_some();
    let sources = native_sources();
    assert!(
        !sources.is_empty(),
        "no native examples found — this test would pass vacuously"
    );
    let mut problems = Vec::new();
    for source in &sources {
        let text = std::fs::read_to_string(source)
            .unwrap_or_else(|error| panic!("{}: {error}", source.display()));
        let config = pingclair_config::compile(&text)
            .unwrap_or_else(|error| panic!("{}: {error}", source.display()));
        let json = serde_json::to_string_pretty(&config).expect("the config serialises");
        let golden = golden_path(source);
        match std::fs::read_to_string(&golden) {
            Ok(expected) if expected.trim_end() == json.trim_end() => {}
            Ok(_) if updating => std::fs::write(&golden, format!("{json}\n"))
                .unwrap_or_else(|error| panic!("{}: {error}", golden.display())),
            Ok(_) => problems.push(format!(
                "{}: its compiled output changed; regenerate with UPDATE_GOLDEN=1 and read the diff",
                source.display()
            )),
            Err(_) => {
                // 🌱 A new example: write its first golden and say so, rather
                // than leaving a test that only proves the file compiles.
                std::fs::write(&golden, format!("{json}\n"))
                    .unwrap_or_else(|error| panic!("{}: {error}", golden.display()));
                problems.push(format!(
                    "{}: no frozen output yet; one was written, commit it",
                    source.display()
                ));
            }
        }
    }
    assert!(
        problems.is_empty(),
        "the native corpus outgrew its goldens:\n  {}",
        problems.join("\n  ")
    );
}

#[test]
fn no_golden_is_missing_its_example() {
    let mut goldens: Vec<PathBuf> = std::fs::read_dir(golden_dir())
        .expect("the golden directory must exist")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect();
    goldens.sort();
    let sources: Vec<PathBuf> = native_sources()
        .iter()
        .map(|source| golden_path(source))
        .collect();
    let orphans: Vec<String> = goldens
        .iter()
        .filter(|golden| !sources.contains(golden))
        .map(|golden| golden.display().to_string())
        .collect();
    assert!(
        orphans.is_empty(),
        "frozen output with no example behind it:\n  {}",
        orphans.join("\n  ")
    );
}
