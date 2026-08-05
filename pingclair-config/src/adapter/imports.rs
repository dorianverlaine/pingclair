// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 📦 `import`: snippets, files, globs, arguments, and refusing to loop.
//!
//! Until now `import` looked only in the snippet table, so `import ./tls.conf`
//! failed with "undefined snippet" — a message pointing at the wrong concept
//! entirely. Splitting a configuration across files is the ordinary way to keep
//! one readable, and it did not work.
//!
//! 🧭 **Paths resolve against the importing file, not the working directory.**
//! A configuration that works when started from its own directory and fails from
//! anywhere else is worse than one that never worked, because the failure
//! arrives later and looks like something else.
//!
//! This lives in its own module rather than inside the 5500-line adapter for the
//! same reason the split is planned at all: the file is already too large to
//! navigate, and imports are a self-contained concern with a natural seam.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::caddyfile::AdapterError;
use crate::parser::caddy_ast::{Block, Directive};

/// Snippet bodies, by name.
pub type SnippetMap = HashMap<String, Vec<Directive>>;

/// 🛑 At most one wildcard per pattern.
///
/// Not a style rule: a pattern with several expansions can take long enough to
/// look like a hang, on a file the operator believes is just a list of includes.
/// Refusing names the problem instead of appearing to freeze.
fn check_glob_complexity(pattern: &str) -> Result<(), AdapterError> {
    let wildcards = pattern.matches('*').count() + pattern.matches('?').count();
    if wildcards > 1 || (pattern.contains('[') && pattern.contains(']')) {
        return Err(AdapterError::InvalidArgument(
            "import".into(),
            format!(
                "glob pattern may contain at most one wildcard and no character classes: {pattern}"
            ),
        ));
    }
    Ok(())
}

fn is_glob(pattern: &str) -> bool {
    pattern.contains('*') || pattern.contains('?') || pattern.contains('[')
}

/// 📂 Expands one import pattern into the files it names.
fn resolve_files(pattern: &str, base: Option<&Path>) -> Result<Vec<PathBuf>, AdapterError> {
    check_glob_complexity(pattern)?;

    let candidate = Path::new(pattern);
    let resolved = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        // 🧭 Relative to the importing file's own directory. `None` means the
        // source had no file — a string from a test or the admin API — and a
        // relative import then has nothing to be relative to.
        match base {
            Some(dir) => dir.join(candidate),
            None => {
                return Err(AdapterError::InvalidArgument(
                    "import".into(),
                    format!(
                        "cannot resolve the relative path {pattern} because this \
                         configuration did not come from a file"
                    ),
                ));
            }
        }
    };

    if !is_glob(pattern) {
        if !resolved.is_file() {
            return Err(AdapterError::InvalidArgument(
                "import".into(),
                format!("file to import not found: {}", resolved.display()),
            ));
        }
        return Ok(vec![resolved]);
    }

    let pattern_text = resolved.to_string_lossy().to_string();
    let mut matches: Vec<PathBuf> = glob_matches(&pattern_text)?;

    // 🙈 A trailing `*` segment skips dotfiles, so an editor's `.swp` beside the
    // configuration does not get read as configuration.
    if resolved
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.starts_with('*'))
    {
        matches.retain(|p| {
            !p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with('.'))
        });
    }

    matches.sort();
    // 📌 A glob matching nothing is not an error: "include whatever is in this
    // directory" is a legitimate thing to write about a directory that is empty
    // today. A *plain* path matching nothing is an error, because the operator
    // named one specific file.
    Ok(matches)
}

/// Expands a glob without pulling in a dependency for it.
///
/// Only the one wildcard the complexity check allows has to work, so this
/// matches a literal prefix and suffix around a single `*` or `?` in the final
/// path segment — which is every glob the format actually admits.
fn glob_matches(pattern: &str) -> Result<Vec<PathBuf>, AdapterError> {
    let path = Path::new(pattern);
    let (dir, name) = match (path.parent(), path.file_name().and_then(|n| n.to_str())) {
        (Some(dir), Some(name)) => (dir, name),
        _ => return Ok(Vec::new()),
    };
    if is_glob(dir.to_string_lossy().as_ref()) {
        return Err(AdapterError::InvalidArgument(
            "import".into(),
            format!("the wildcard must be in the file name, not a directory: {pattern}"),
        ));
    }

    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        // 🧭 A missing directory behaves like a glob with no matches rather than
        // an IO failure: the operator asked for whatever is there.
        Err(_) => return Ok(Vec::new()),
    };

    let (prefix, suffix) = match name.split_once(['*', '?']) {
        Some(parts) => parts,
        None => (name, ""),
    };
    let single_char = name.contains('?');

    let mut out = Vec::new();
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(text) = file_name.to_str() else {
            continue;
        };
        if !text.starts_with(prefix) || !text.ends_with(suffix) {
            continue;
        }
        if text.len() < prefix.len() + suffix.len() {
            continue;
        }
        // `?` matches exactly one character; `*` matches any run.
        if single_char && text.len() != prefix.len() + suffix.len() + 1 {
            continue;
        }
        if entry.path().is_file() {
            out.push(entry.path());
        }
    }
    Ok(out)
}

/// 🏷️ Substitutes `{args[N]}` in an imported body.
///
/// The deprecated `{args.N}` spelling is accepted too, because configurations
/// written against it exist and silently leaving the placeholder in place would
/// put the literal text into a header value.
///
/// An index with no argument for it resolves to empty, matching what the format
/// does — a missing argument is a thin configuration, not a crash.
fn substitute_args(directives: Vec<Directive>, args: &[String]) -> Vec<Directive> {
    if args.is_empty() {
        return directives;
    }
    fn replace(text: &str, args: &[String]) -> String {
        let mut out = text.to_string();
        for (index, value) in args.iter().enumerate() {
            out = out
                .replace(&format!("{{args[{index}]}}"), value)
                .replace(&format!("{{args.{index}}}"), value);
        }
        // 🧹 Any index the caller did not supply becomes empty rather than
        // surviving as literal braces in a value.
        for index in args.len()..args.len() + 8 {
            out = out
                .replace(&format!("{{args[{index}]}}"), "")
                .replace(&format!("{{args.{index}}}"), "");
        }
        out
    }
    directives
        .into_iter()
        .map(|d| Directive {
            name: replace(&d.name, args),
            args: d.args.iter().map(|a| replace(a, args)).collect(),
            block: d.block.map(|b| Block {
                directives: substitute_args(b.directives, args),
            }),
        })
        .collect()
}

/// 🕳️ How deep block recursion may go.
///
/// Separate from cycle detection, and both are needed. Cycles are about a name
/// coming back around; this is about a *single* configuration nesting so deep
/// that walking it exhausts the stack. Nesting is the exact shape that produced
/// a remotely triggerable denial of service in this codebase before, so the
/// guard is explicit rather than implied by some other limit.
const MAX_BLOCK_DEPTH: usize = 32;

/// 🔁 Where an expansion currently is, for refusing to go in circles.
pub struct ImportContext<'a> {
    /// Directory the importing file lives in, if it came from one.
    pub base: Option<&'a Path>,
    /// Snippet names and file paths currently being expanded.
    active: Vec<String>,
    /// How many blocks deep this walk currently is.
    depth: usize,
}

impl<'a> ImportContext<'a> {
    pub fn new(base: Option<&'a Path>) -> Self {
        Self {
            base,
            active: Vec::new(),
            depth: 0,
        }
    }

    /// Marks a node as being expanded, refusing if it already is.
    ///
    /// 🛑 A depth counter would also stop a cycle, but only by running out —
    /// after sixteen expansions, with an error naming whichever import happened
    /// to be last. Tracking the chain lets the message name the cycle itself,
    /// which is the part the operator has to break.
    fn enter(&mut self, node: &str) -> Result<(), AdapterError> {
        if self.active.iter().any(|n| n == node) {
            let mut chain = self.active.clone();
            chain.push(node.to_string());
            return Err(AdapterError::RecursiveSnippet(chain.join(" → ")));
        }
        self.active.push(node.to_string());
        Ok(())
    }

    fn leave(&mut self) {
        self.active.pop();
    }
}

/// 📦 Expands every `import` in `directives`.
pub fn expand(
    directives: Vec<Directive>,
    snippets: &SnippetMap,
    context: &mut ImportContext<'_>,
) -> Result<Vec<Directive>, AdapterError> {
    // 🕳️ Checked on entry so the very first call is counted, and so the error
    // names nesting rather than surfacing as a crash.
    if context.depth > MAX_BLOCK_DEPTH {
        return Err(AdapterError::InvalidArgument(
            "import".into(),
            format!("configuration nests more than {MAX_BLOCK_DEPTH} blocks deep"),
        ));
    }

    let mut out = Vec::new();

    for d in directives {
        if d.name != "import" {
            let block = match d.block {
                Some(block) => {
                    context.depth += 1;
                    let inner = expand(block.directives, snippets, context);
                    context.depth -= 1;
                    Some(Block { directives: inner? })
                }
                None => None,
            };
            out.push(Directive {
                name: d.name,
                args: d.args,
                block,
            });
            continue;
        }

        let Some(pattern) = d.args.first().cloned() else {
            return Err(AdapterError::ArgumentCount("import".into(), 1, 0));
        };
        let args: Vec<String> = d.args[1..].to_vec();

        // 🥇 Snippets win over files, so a snippet named like a path stays
        // reachable and no filesystem lookup happens for the common case.
        if let Some(body) = snippets.get(&pattern) {
            context.enter(&pattern)?;
            let expanded = expand(body.clone(), snippets, context)?;
            context.leave();
            out.extend(substitute_args(expanded, &args));
            continue;
        }

        for file in resolve_files(&pattern, context.base)? {
            let canonical = file
                .canonicalize()
                .unwrap_or_else(|_| file.clone())
                .display()
                .to_string();
            context.enter(&canonical)?;

            let source = std::fs::read_to_string(&file).map_err(|e| {
                AdapterError::InvalidArgument(
                    "import".into(),
                    format!("cannot read {}: {e}", file.display()),
                )
            })?;
            let parsed = crate::parser::parse(&source).map_err(|e| {
                AdapterError::InvalidArgument("import".into(), format!("{}: {e}", file.display()))
            })?;

            // 🧭 An imported file's own relative imports resolve against *its*
            // directory, not the directory of whoever imported it.
            let mut nested = ImportContext {
                base: file.parent(),
                active: std::mem::take(&mut context.active),
                depth: context.depth,
            };
            let (nested_snippets, body) = super::caddyfile::collect_snippets(parsed)?;
            let mut merged = nested_snippets;
            for (name, value) in snippets {
                merged.entry(name.clone()).or_insert_with(|| value.clone());
            }
            let expanded = expand(body, &merged, &mut nested)?;
            context.active = nested.active;
            context.leave();

            out.extend(substitute_args(expanded, &args));
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, body).expect("write fixture");
        path
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("pingclair-import-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    #[test]
    fn a_relative_path_resolves_against_the_importing_file() {
        let dir = temp_dir("relative");
        write(&dir, "part.conf", "header X-From part\n");
        let main = write(
            &dir,
            "main.conf",
            "example.com {\n\timport ./part.conf\n}\n",
        );

        let source = std::fs::read_to_string(&main).unwrap();
        let config = crate::compile_named(&source, Some(&main)).expect("must compile");
        let rendered = format!("{:?}", config.servers[0]);
        assert!(rendered.contains("X-From"), "imported: {rendered}");
    }

    #[test]
    fn a_missing_plain_path_is_an_error_naming_the_file() {
        let dir = temp_dir("missing");
        let main = write(
            &dir,
            "main.conf",
            "example.com {\n\timport ./nope.conf\n}\n",
        );
        let source = std::fs::read_to_string(&main).unwrap();
        let error = crate::compile_named(&source, Some(&main))
            .expect_err("must fail")
            .to_string();
        assert!(error.contains("nope.conf"), "must name the file: {error}");
    }

    /// 📌 A glob matching nothing is fine: "whatever is in this directory" is a
    /// legitimate thing to say about a directory that is empty today.
    #[test]
    fn a_glob_matching_nothing_is_not_an_error() {
        let dir = temp_dir("emptyglob");
        let main = write(
            &dir,
            "main.conf",
            "example.com {\n\timport ./parts/*.conf\n}\n",
        );
        let source = std::fs::read_to_string(&main).unwrap();
        assert!(crate::compile_named(&source, Some(&main)).is_ok());
    }

    #[test]
    fn a_glob_imports_every_match_and_skips_dotfiles() {
        let dir = temp_dir("glob");
        // 🗂️ Parts in their own directory, which is how this is written in
        // practice — and it keeps the glob from matching the importing file.
        let parts = dir.join("conf.d");
        std::fs::create_dir_all(&parts).expect("parts dir");
        write(&parts, "a.conf", "header X-A one\n");
        write(&parts, "b.conf", "header X-B two\n");
        write(&parts, ".hidden.conf", "header X-Hidden three\n");
        let main = write(
            &dir,
            "Pingclairfile",
            "example.com {\n\timport ./conf.d/*.conf\n}\n",
        );

        let source = std::fs::read_to_string(&main).unwrap();
        let config = crate::compile_named(&source, Some(&main)).expect("must compile");
        let rendered = format!("{:?}", config.servers[0]);
        assert!(
            rendered.contains("X-A") && rendered.contains("X-B"),
            "both parts must be imported: {rendered}"
        );
        assert!(
            !rendered.contains("X-Hidden"),
            "an editor's dotfile must not become configuration: {rendered}"
        );
    }

    /// 🔁 A glob that matches the importing file is a cycle, and has to be
    /// refused rather than recursed into.
    ///
    /// This is easy to write by accident — `import ./*.conf` from a file that is
    /// itself a `.conf` — and it is how the first version of the test above was
    /// written. Refusing it is the whole reason cycle detection tracks paths
    /// rather than counting depth.
    #[test]
    fn a_glob_matching_the_importing_file_is_a_cycle() {
        let dir = temp_dir("selfglob");
        write(&dir, "part.conf", "header X-P one\n");
        let main = write(&dir, "main.conf", "example.com {\n\timport ./*.conf\n}\n");
        let source = std::fs::read_to_string(&main).unwrap();
        assert!(
            crate::compile_named(&source, Some(&main)).is_err(),
            "importing itself through a glob must be refused"
        );
    }

    /// 🛑 Several wildcards are refused rather than expanded, because the
    /// expansion can take long enough to look like a hang.
    #[test]
    fn more_than_one_wildcard_is_refused() {
        assert!(check_glob_complexity("a/*/b/*.conf").is_err());
        assert!(check_glob_complexity("[ab].conf").is_err());
        assert!(check_glob_complexity("*.conf").is_ok());
    }

    #[test]
    fn a_snippet_takes_arguments() {
        let config = crate::compile(
            "(hdr) {\n\theader X-Tag {args[0]}\n}\n\nexample.com {\n\timport hdr production\n}\n",
        )
        .expect("must compile");
        let rendered = format!("{:?}", config.servers[0]);
        assert!(rendered.contains("production"), "{rendered}");
    }

    /// 🔁 A cycle is named, not counted out. The message has to say which
    /// imports form the loop, because that is the part to break.
    #[test]
    fn a_snippet_cycle_is_refused_and_named() {
        let error = crate::compile(
            "(a) {\n\timport b\n}\n(b) {\n\timport a\n}\n\nexample.com {\n\timport a\n}\n",
        )
        .expect_err("must fail")
        .to_string();
        assert!(error.contains('a') && error.contains('b'), "{error}");
    }

    #[test]
    fn a_file_cycle_is_refused() {
        let dir = temp_dir("filecycle");
        write(&dir, "one.conf", "import ./two.conf\n");
        write(&dir, "two.conf", "import ./one.conf\n");
        let main = write(&dir, "main.conf", "example.com {\n\timport ./one.conf\n}\n");
        let source = std::fs::read_to_string(&main).unwrap();
        assert!(crate::compile_named(&source, Some(&main)).is_err());
    }

    /// 🧪 A relative import with no file to be relative to says so, rather than
    /// silently resolving against whatever directory the process happens to be
    /// in — which would make the same configuration behave differently depending
    /// on where it was started.
    #[test]
    fn a_relative_import_without_a_source_file_is_refused() {
        let error = crate::compile("example.com {\n\timport ./part.conf\n}\n")
            .expect_err("must fail")
            .to_string();
        assert!(error.contains("did not come from a file"), "{error}");
    }
}
