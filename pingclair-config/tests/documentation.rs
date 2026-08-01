// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 📚 Every configuration shown to a user must still compile.
//!
//! `examples/full_featured.pingclair` shipped broken for three days: making
//! `encode br` a compile error rather than a silent downgrade to gzip was the
//! right call, but the example that used it was never updated and nothing
//! checked. Documentation does not announce when it stops being true, so the
//! only thing that keeps it true is a test that fails.
//!
//! This covers two surfaces:
//!
//! - every file under `examples/`
//! - every fenced ```pingclair or ```caddyfile block in the READMEs and `docs/`
//!
//! A block that is deliberately invalid — showing what *not* to write — should
//! be fenced as `text` rather than `pingclair`, which is also how a reader
//! tells the two apart.

use std::path::{Path, PathBuf};

/// 🗂️ Resolves the workspace root from this crate's manifest directory.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("pingclair-config sits one level below the workspace root")
        .to_path_buf()
}

/// 📄 Lists files under a directory, without recursing.
fn files_in(directory: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return Vec::new();
    };
    let mut found: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .collect();
    found.sort();
    found
}

#[test]
fn every_shipped_example_still_compiles() {
    // Setup scenarios
    let root = workspace_root();
    let examples = files_in(&root.join("examples"));
    assert!(
        !examples.is_empty(),
        "no examples found — this test would pass vacuously"
    );

    // Verification
    let mut broken = Vec::new();
    for path in &examples {
        let Ok(source) = std::fs::read_to_string(path) else {
            continue;
        };
        if let Err(error) = pingclair_config::compile(&source) {
            broken.push(format!("{}: {error}", path.display()));
        }
    }
    assert!(
        broken.is_empty(),
        "shipped examples no longer compile:\n  {}",
        broken.join("\n  ")
    );
}

/// 📝 Extracts every ```pingclair fenced block from a Markdown document.
fn pingclair_blocks(markdown: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut current: Option<String> = None;
    for line in markdown.lines() {
        let trimmed = line.trim_start();
        match &mut current {
            Some(block) => {
                if trimmed.starts_with("```") {
                    blocks.push(std::mem::take(block));
                    current = None;
                } else {
                    block.push_str(line);
                    block.push('\n');
                }
            }
            None => {
                // `caddyfile` as well as `pingclair`: the READMEs fence their
                // configurations as caddyfile because that is what GitHub
                // highlights, and those are the blocks a reader copies.
                if trimmed == "```pingclair" || trimmed == "```caddyfile" {
                    current = Some(String::new());
                }
            }
        }
    }
    blocks
}

#[test]
fn every_documented_configuration_still_compiles() {
    // Setup scenarios
    let root = workspace_root();
    let mut documents: Vec<PathBuf> = files_in(&root)
        .into_iter()
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("README") && name.ends_with(".md"))
        })
        .collect();
    documents.extend(files_in(&root.join("docs")).into_iter().filter(|path| {
        // 🚫 The Caddyfile audit documents are deliberately full of
        // configs that must NOT compile: every block there is either a
        // reproduction of a rejected Caddy feature or a red-flag
        // example. Only the user-facing manual (READMEs plus the
        // shipped STATUS/GUARDRAILS prose) is covered here.
        path.extension().is_some_and(|ext| ext == "md")
            && !path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("CADDYFILE"))
    }));

    // Verification
    let mut broken = Vec::new();
    let mut checked = 0usize;
    for path in &documents {
        let Ok(markdown) = std::fs::read_to_string(path) else {
            continue;
        };
        for (index, block) in pingclair_blocks(&markdown).into_iter().enumerate() {
            checked += 1;
            if let Err(error) = pingclair_config::compile(&block) {
                broken.push(format!(
                    "{} (config block #{}): {error}",
                    path.display(),
                    index + 1
                ));
            }
        }
    }
    assert!(
        broken.is_empty(),
        "documented configurations no longer compile:\n  {}\n\
         (a block that is deliberately invalid should be fenced as ```text)",
        broken.join("\n  ")
    );
    // Reported rather than asserted: there is no correct number of examples,
    // but a silent drop to zero would make this test meaningless.
    println!("checked {checked} documented configuration block(s)");
}
