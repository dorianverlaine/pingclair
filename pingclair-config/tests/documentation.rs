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

/// 🚩 Every directive the parser refuses must be named in all three READMEs.
///
/// 📏 What this checks, exactly: the name appears *somewhere* in each file, not
/// that it appears in the limits list. That catches the drift that matters —
/// a refused directive the documentation never mentions — and deliberately
/// tolerates a name discussed in prose as well as listed. Verified to fail
/// when a name is removed, rather than assumed to.
///
/// The claim on the tin is "Caddyfile-compatible", and a compatibility claim is
/// only worth what its stated limits are worth. Those limits drift in the
/// direction that flatters us if nobody checks: the list keeps naming things
/// that have since been implemented, and stops naming things that never were.
///
/// 🤡 The same shape has already bitten this repository twice in one week —
/// `list-modules` advertised `try_files` for weeks while the adapter refused
/// it, and the CHANGELOG called `handle_errors` a working container. Both were
/// hand-maintained copies of an answer the registry already knew.
#[test]
fn the_readme_limits_match_the_registry() {
    let root = workspace_root();
    let missing: Vec<String> = ["README.md", "README.zh.md", "README.fr.md"]
        .into_iter()
        .flat_map(|name| {
            let markdown = std::fs::read_to_string(root.join(name)).unwrap_or_default();
            pingclair_config::adapter::recognised_but_unimplemented()
                .filter(move |directive| !markdown.contains(&format!("`{directive}`")))
                .map(move |directive| format!("{name}: `{directive}`"))
        })
        .collect();

    assert!(
        missing.is_empty(),
        "the parser refuses these, and the README does not say so:\n  {}\n\
         (add them to the \"not supported yet\" list, or implement them)",
        missing.join("\n  ")
    );
}

/// 🚩 And nothing the parser implements may still be listed as unsupported.
///
/// 🤡 The doc comment above already named this failure — "the list keeps naming
/// things that have since been implemented" — and then only checked the other
/// direction. It drifted exactly as predicted: on 2026-08-13 the lists were
/// still refusing `acme_server`, `intercept`, `acme_dns`, `default_sni`, `dns`,
/// `pki` and `skip_install_trust`, all seven of them working, in all three
/// languages. A test that names a risk it does not cover reads like coverage.
///
/// 📏 Unlike its counterpart this one reads the *list block* rather than the
/// whole file, because an implemented directive is supposed to appear elsewhere
/// in the README — `intercept` has its own section. The block is found by shape
/// rather than by heading: an indented line made only of backticked names. That
/// is the one thing the English, Chinese and French files have in common.
#[test]
fn the_readme_limits_do_not_name_implemented_features() {
    let root = workspace_root();
    let implemented: std::collections::HashSet<String> =
        pingclair_config::adapter::implemented_names()
            .map(str::to_string)
            .collect();

    let stale: Vec<String> = ["README.md", "README.zh.md", "README.fr.md"]
        .into_iter()
        .flat_map(|name| {
            let markdown = std::fs::read_to_string(root.join(name)).unwrap_or_default();
            let implemented = implemented.clone();
            listed_limit_names(&markdown)
                .into_iter()
                .filter(move |listed| implemented.contains(listed))
                .map(move |listed| format!("{name}: `{listed}`"))
        })
        .collect();

    assert!(
        stale.is_empty(),
        "these are implemented, and the README still lists them as unsupported:\n  {}\n\
         (remove them from the \"not supported yet\" list)",
        stale.join("\n  ")
    );
}

/// 🧭 The names inside the "not supported yet" lists, found by their shape.
///
/// A list line is indented and holds nothing but backticked names. Prose
/// mentioning a directive always has words around it, so it never matches.
fn listed_limit_names(markdown: &str) -> Vec<String> {
    markdown
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            line.starts_with("  ")
                && trimmed.starts_with('`')
                && trimmed.ends_with('`')
                && trimmed
                    .split_whitespace()
                    .all(|token| token.starts_with('`') && token.ends_with('`') && token.len() > 2)
        })
        .flat_map(|line| {
            line.split_whitespace()
                .map(|token| token.trim_matches('`').to_string())
        })
        .collect()
}
