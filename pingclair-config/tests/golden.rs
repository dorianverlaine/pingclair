// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧊 Configurations we promise to support, frozen with the exact output they
//! compile to.
//!
//! The other config tests ask "does this compile?". That question stops being
//! useful during a refactor, because a rewrite that quietly changes what a
//! directive *means* still compiles. This crate has shipped that twice — an
//! `output file X { … }` block parsed and discarded, and a path argument that
//! became a response body — and both were green the whole time.
//!
//! So these fixtures freeze the whole compiled configuration, byte for byte.
//! A pure refactor changes none of them; anything that does change one has to
//! say why, in the diff, where a reviewer can see it.
//!
//! # 📌 Why these and not the format's own corpus
//!
//! There is a corpus of 228 configurations written by the people who define
//! the format, and it is used here — as a local measurement tool, to find
//! shapes nobody in this repository would have thought to write. It cannot be
//! this, for two reasons. Its expected output is in *its* schema, not ours, so
//! it can only ever answer "did this compile". And a directory of
//! configurations deliberately designed to fail is a trap for anyone who reads
//! it as documentation.
//!
//! These are ours: our schema, our promises, and every one of them is a
//! configuration a user could reasonably write.
//!
//! # ✍️ Updating a fixture
//!
//! ```bash
//! UPDATE_GOLDEN=1 cargo +1.97.1 test -p pingclair-config --test golden
//! ```
//!
//! Then **read the diff**. Regenerating is how a golden file is maintained;
//! regenerating without looking is how a golden file becomes a record of
//! whatever the code happened to do.

use std::path::{Path, PathBuf};

/// The line between a fixture's source and its expected output.
const SEPARATOR: &str = "----------";

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

fn fixture_paths() -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(fixtures_dir())
        .expect("the fixtures directory must exist")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "pingclairtest"))
        .collect();
    found.sort();
    found
}

/// Splits a fixture into its configuration source and its expected JSON.
fn split(contents: &str) -> (String, String) {
    match contents.split_once(&format!("\n{SEPARATOR}\n")) {
        Some((source, expected)) => (source.to_string(), expected.trim_end().to_string()),
        // 🌱 A fixture with no separator is a new one: source only, waiting for
        // its first generated output.
        None => (contents.trim_end().to_string(), String::new()),
    }
}

/// 🎯 Compiles a fixture's source into the JSON this test compares.
fn compile_to_json(source: &str) -> Result<String, String> {
    let config = pingclair_config::compile(source).map_err(|e| e.to_string())?;
    serde_json::to_string_pretty(&config).map_err(|e| e.to_string())
}

#[test]
fn every_fixture_compiles_to_exactly_what_it_says() {
    let updating = std::env::var_os("UPDATE_GOLDEN").is_some();
    let paths = fixture_paths();
    assert!(
        !paths.is_empty(),
        "no fixtures found — this test would pass vacuously"
    );

    let mut mismatches = Vec::new();
    let mut rewritten = Vec::new();

    for path in &paths {
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        let contents = std::fs::read_to_string(path).expect("a fixture must be readable");
        let (source, expected) = split(&contents);

        let actual = match compile_to_json(&source) {
            Ok(json) => json,
            // 🚫 Every fixture here is a configuration we promise to accept, so
            // a compile error is a failure rather than an alternative outcome.
            // Shapes that must be *rejected* are tested in `caddyfile_shapes`,
            // where the error message is the subject.
            Err(error) => {
                mismatches.push(format!("{name}: must compile, but did not:\n    {error}"));
                continue;
            }
        };

        if actual == expected {
            continue;
        }

        if updating {
            std::fs::write(path, format!("{source}\n{SEPARATOR}\n{actual}\n"))
                .expect("a fixture must be writable");
            rewritten.push(name.to_string());
            continue;
        }

        mismatches.push(format!(
            "{name}: compiled output no longer matches the frozen one.\n{}",
            first_difference(&expected, &actual)
        ));
    }

    if updating {
        assert!(
            !rewritten.is_empty(),
            "UPDATE_GOLDEN was set but nothing changed — drop it from the command"
        );
        // 🧭 Deliberately fails after rewriting. A regeneration run is not a
        // passing test run, and letting it go green invites `UPDATE_GOLDEN=1`
        // becoming the way the suite is made quiet.
        panic!(
            "rewrote {} fixture(s): {}\nRead the diff before committing.",
            rewritten.len(),
            rewritten.join(", ")
        );
    }

    assert!(
        mismatches.is_empty(),
        "\n{}\n\nIf the change is intended, regenerate with:\n    \
         UPDATE_GOLDEN=1 cargo +1.97.1 test -p pingclair-config --test golden\n",
        mismatches.join("\n\n")
    );
}

/// 🔍 The first line that differs, with its neighbours.
///
/// A whole-config diff is thousands of lines and a reader stops at the first
/// screenful anyway, so the useful thing to print is where they part company.
fn first_difference(expected: &str, actual: &str) -> String {
    let expected_lines: Vec<&str> = expected.lines().collect();
    let actual_lines: Vec<&str> = actual.lines().collect();

    for (i, (want, got)) in expected_lines.iter().zip(actual_lines.iter()).enumerate() {
        if want != got {
            let context = i.saturating_sub(2);
            let before = expected_lines[context..i]
                .iter()
                .map(|line| format!("      {line}"))
                .collect::<Vec<_>>()
                .join("\n");
            return format!("    line {}:\n{before}\n    - {want}\n    + {got}", i + 1);
        }
    }

    format!(
        "    output is {} line(s) long, frozen output is {}",
        actual_lines.len(),
        expected_lines.len()
    )
}

/// 📌 A fixture with no expected output would pass silently, freezing nothing.
#[test]
fn no_fixture_is_missing_its_expected_output() {
    let empty: Vec<String> = fixture_paths()
        .iter()
        .filter(|path| {
            let contents = std::fs::read_to_string(path).unwrap_or_default();
            split(&contents).1.is_empty()
        })
        .map(|path| {
            path.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into()
        })
        .collect();

    assert!(
        empty.is_empty(),
        "these fixtures have no frozen output, so they assert nothing: {empty:?}\n\
         Generate it with UPDATE_GOLDEN=1 and read the result."
    );
}
