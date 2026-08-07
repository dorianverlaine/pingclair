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
use crate::parser::caddy_ast::{Block, Directive, TokenRun};

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
            // 🚫 Deliberately no token run. Snippet arguments are substituted
            // into the *text* here, so the tokens in the file say `{args[0]}`
            // while `args` now says what it expanded to. A parser reading the
            // tokens would see the placeholder and undo the expansion.
            tokens: crate::parser::caddy_ast::TokenRun::synthetic(),
            name: replace(&d.name, args),
            args: d.args.iter().map(|a| replace(a, args)).collect(),
            block: d.block.map(|b| Block {
                directives: substitute_args(b.directives, args),
            }),
        })
        .collect()
}

/// 🌊 Builds the `{blocks.<key>}` mapping from an import block.
///
/// Each top-level directive in the block becomes one mapping entry. Upstream
/// stores the tokens that follow the directive's name — its arguments plus the
/// contents of its block — and the tree restores that shape: a block's own
/// directives are spliced as siblings, and arguments become a synthetic
/// directive named after the first one so the line re-parses the same way.
fn collect_named_blocks(block: &Block) -> Result<HashMap<String, Vec<Directive>>, AdapterError> {
    let mut named = HashMap::new();
    for d in &block.directives {
        // 🚫 A `{` where a mapping key belongs has no name to be looked up by,
        // and upstream refuses it by name — an anonymous block can never be
        // addressed by `{blocks.*}`.
        if d.name == "{" || (d.name.is_empty() && d.block.is_some()) {
            return Err(AdapterError::InvalidArgument(
                "import".into(),
                "anonymous blocks are not supported".into(),
            ));
        }
        let content = match (d.args.is_empty(), d.block.as_ref()) {
            (true, None) => Vec::new(),
            (true, Some(inner)) => inner.directives.clone(),
            (false, nested) => vec![Directive {
                name: d.args[0].clone(),
                args: d.args[1..].to_vec(),
                block: nested.cloned(),
                tokens: TokenRun::synthetic(),
            }],
        };
        named.insert(d.name.clone(), content);
    }
    Ok(named)
}

/// 🔁 Slices an import block into an imported body in place of `{block}` and
/// `{blocks.<key>}`.
///
/// Upstream performs this substitution on the token stream, and the tree keeps
/// the same rules: an exact placeholder on a line of its own splices the
/// mapped directives, a missing key splices nothing, nested snippet
/// definitions keep their placeholders for their own future expansion, and
/// spliced content is not walked again.
fn substitute_block_placeholders(
    directives: Vec<Directive>,
    block: &[Directive],
    named: &HashMap<String, Vec<Directive>>,
) -> Result<Vec<Directive>, AdapterError> {
    let mut out = Vec::with_capacity(directives.len());
    for d in directives {
        if d.name == "{block}" {
            out.extend(block.iter().cloned());
            continue;
        }
        if let Some(key) = d
            .name
            .strip_prefix("{blocks.")
            .and_then(|rest| rest.strip_suffix('}'))
        {
            if let Some(content) = named.get(key) {
                out.extend(content.iter().cloned());
            }
            continue;
        }
        // 🚫 A placeholder inside an argument list cannot be spliced without
        // changing how many arguments there are — the token layer re-parses
        // the whole line and the tree cannot. Refusing names the shape rather
        // than emitting a directive that silently means something else.
        for arg in &d.args {
            if arg == "{block}" || (arg.starts_with("{blocks.") && arg.ends_with('}')) {
                return Err(AdapterError::InvalidArgument(
                    "import".into(),
                    format!(
                        "`{arg}` inside an argument list is substituted by the token layer \
                         upstream, which the directive tree cannot express; rewrite the \
                         snippet so the placeholder is a directive on its own line"
                    ),
                ));
            }
        }
        let block = if d.name.starts_with('(') && d.name.ends_with(')') {
            d.block
        } else {
            match d.block {
                Some(b) => Some(Block {
                    directives: substitute_block_placeholders(b.directives, block, named)?,
                }),
                None => None,
            }
        };
        out.push(Directive { block, ..d });
    }
    Ok(out)
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
    snippets: &mut SnippetMap,
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
                // 📎 Untouched apart from its block, so it keeps the tokens it
                // was read from — an import splices directives, it does not
                // rewrite them.
                tokens: d.tokens,
            });
            continue;
        }

        let Some(pattern) = d.args.first().cloned() else {
            return Err(AdapterError::ArgumentCount("import".into(), 1, 0));
        };
        let args: Vec<String> = d.args[1..].to_vec();

        // 🌊 An import block feeds two substitutions into the imported body:
        // `{block}` splices the whole block and `{blocks.<key>}` splices one
        // named sub-block. The empty case is a real import too — a snippet
        // written with a placeholder compiles even when the call supplies no
        // block, and the placeholder simply splices nothing.
        let (block_directives, named_blocks) = match &d.block {
            Some(block) => (block.directives.clone(), collect_named_blocks(block)?),
            None => (Vec::new(), HashMap::new()),
        };

        // 🥇 Snippets win over files, so a snippet named like a path stays
        // reachable and no filesystem lookup happens for the common case.
        if let Some(body) = snippets.get(&pattern) {
            context.enter(&pattern)?;
            // 🧭 The order mirrors upstream's token pass: arguments are
            // replaced and block placeholders spliced *before* the body is
            // expanded again, so a placeholder inside a nested import's block
            // resolves against this import's mapping, and the block's own
            // content never sees this import's arguments.
            let substituted = substitute_args(body.clone(), &args);
            let substituted =
                substitute_block_placeholders(substituted, &block_directives, &named_blocks)?;
            let expanded = expand(substituted, snippets, context)?;
            context.leave();
            out.extend(expanded);
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
            // 🗺️ Snippet definitions from an imported file are part of the
            // merged token stream, so they must be visible to imports that
            // come *later* in the configuration. Scoping them to the file's
            // own body dropped the site that followed the import — a file of
            // snippets compiled green and contributed nothing.
            //
            // The file's definitions win over outer ones, which is the same
            // precedence the previous local merge gave the file's own body,
            // and the order stays in-order the way Caddy registers snippets
            // while it parses.
            for (name, body) in nested_snippets {
                snippets.insert(name, body);
            }
            let substituted = substitute_args(body, &args);
            let substituted =
                substitute_block_placeholders(substituted, &block_directives, &named_blocks)?;
            let expanded = expand(substituted, snippets, &mut nested)?;
            context.active = nested.active;
            context.leave();

            out.extend(expanded);
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

    /// 🔁 `{block}` splices the whole import block at the directive that asks
    /// for it, arguments and nested blocks included.
    #[test]
    fn a_block_placeholder_splices_the_whole_import_block() {
        let config = crate::compile(
            "(wrap) {\n\theader {\n\t\t{block}\n\t}\n}\n\n\
             example.com {\n\timport wrap {\n\t\tFoo bar\n\t}\n}\n",
        )
        .expect("a block import must compile");
        let rendered = format!("{:?}", config.servers[0]);
        assert!(
            rendered.contains("Foo") && rendered.contains("bar"),
            "the block must reach the header: {rendered}"
        );
    }

    /// 🗺️ `{blocks.<key>}` splices one named sub-block and leaves the others
    /// behind.
    #[test]
    fn a_named_block_placeholder_splices_only_that_key() {
        let config = crate::compile(
            "(pick) {\n\theader {\n\t\t{blocks.first}\n\t}\n}\n\n\
             example.com {\n\timport pick {\n\t\tfirst {\n\t\t\tFoo a\n\t\t}\n\t\t\
             second {\n\t\t\tBar b\n\t\t}\n\t}\n}\n",
        )
        .expect("a named block import must compile");
        let rendered = format!("{:?}", config.servers[0]);
        assert!(
            rendered.contains("Foo") && !rendered.contains("Bar"),
            "only the named sub-block may reach the header: {rendered}"
        );
    }

    /// 🪆 A placeholder inside a nested import's block resolves against the
    /// outer import's mapping, exactly as it does on the upstream token
    /// stream.
    #[test]
    fn a_placeholder_inside_a_nested_import_block_uses_the_outer_mapping() {
        let config = crate::compile(
            "(outer) {\n\theader {\n\t\t{blocks.bar}\n\t}\n\t\
             import inner {\n\t\tbar {\n\t\t\t{blocks.foo}\n\t\t}\n\t}\n}\n\
             (inner) {\n\theader {\n\t\t{blocks.bar}\n\t}\n}\n\n\
             example.com {\n\timport outer {\n\t\tfoo {\n\t\t\tFoo a\n\t\t}\n\t\t\
             bar {\n\t\t\tBar b\n\t\t}\n\t}\n}\n",
        )
        .expect("nested block imports must compile");
        let rendered = format!("{:?}", config.servers[0]);
        assert!(
            rendered.contains("Foo") && rendered.contains("Bar"),
            "both mappings must reach a header: {rendered}"
        );
    }

    /// 🧹 A placeholder with no block and a missing key both splice nothing,
    /// so a snippet written with them still compiles when the call is bare.
    #[test]
    fn an_unfed_block_placeholder_splices_nothing() {
        let config = crate::compile(
            "(quiet) {\n\theader {\n\t\treverse_proxy localhost:3000\n\t\t{block}\n\t\t\
             {blocks.missing}\n\t}\n}\n\nexample.com {\n\timport quiet\n}\n",
        )
        .expect("unfed placeholders must be removed");
        let rendered = format!("{:?}", config.servers[0]);
        assert!(
            rendered.contains("reverse_proxy")
                && !rendered.contains("{block}")
                && !rendered.contains("missing"),
            "the placeholders must vanish but the rest must survive: {rendered}"
        );
    }

    /// 🏠 A block import can assemble a whole site, addresses included, the
    /// way Caddy's own `import site test.domain { … }` does.
    #[test]
    fn a_block_import_can_build_a_site() {
        let config = crate::compile(
            "(site) {\n\thttps://{args[0]} {\n\t\t{block}\n\t}\n}\n\n\
             import site test.domain {\n\trespond \"hi\" 200\n}\n",
        )
        .expect("a block import may build a site");
        assert_eq!(config.servers.len(), 1);
        assert_eq!(config.servers[0].name.as_deref(), Some("test.domain"));
    }

    /// 🚫 An anonymous block inside an import has no key to be addressed by,
    /// and is refused exactly as upstream refuses it.
    #[test]
    fn an_anonymous_import_block_is_refused() {
        let error = crate::compile(
            "(site) {\n\thttp://{args[0]} {\n\t\t{block}\n\t}\n}\n\n\
             import site example.com {\n\t{\n\t\trespond \"x\"\n\t}\n}\n",
        )
        .expect_err("an anonymous block must be refused")
        .to_string();
        assert!(error.contains("anonymous block"), "{error}");
    }

    /// 🚫 A placeholder inside an argument list cannot be spliced by the
    /// directive tree, and is refused rather than silently misread.
    #[test]
    fn a_placeholder_in_an_argument_list_is_refused() {
        let error = crate::compile(
            "(arg) {\n\trespond {block}\n}\nexample.com {\n\timport arg {\n\t\tfoo bar\n\t}\n}\n",
        )
        .expect_err("an argument-position placeholder must be refused")
        .to_string();
        assert!(error.contains("argument list"), "{error}");
    }

    /// 🗂️ Snippet definitions from an imported file are visible to imports
    /// that come later, the way Caddy registers them while parsing — a file
    /// of snippets compiled green and contributed nothing before this was
    /// fixed, because the definitions were scoped to the file's own body.
    #[test]
    fn a_file_import_exposes_its_snippets_to_later_imports() {
        let dir = temp_dir("filesnippets");
        write(&dir, "defs.conf", "(common) {\n\theader X-File yes\n}\n");
        let main = write(
            &dir,
            "main.conf",
            "import ./defs.conf\n\nexample.com {\n\timport common\n}\n",
        );
        let source = std::fs::read_to_string(&main).unwrap();
        let config = crate::compile_named(&source, Some(&main)).expect("must compile");
        assert_eq!(config.servers.len(), 1, "the site must survive the import");
        let rendered = format!("{:?}", config.servers[0]);
        assert!(
            rendered.contains("X-File"),
            "the file snippet must apply: {rendered}"
        );
    }

    /// 🚫 A block supplied to a file-defined snippet reaches the snippet and
    /// is parsed, so an invalid subdirective is refused instead of being
    /// dropped along with the site.
    #[test]
    fn a_block_supplied_to_a_file_defined_snippet_is_not_dropped() {
        let dir = temp_dir("fileblock");
        write(
            &dir,
            "defs.conf",
            "(test) {\n\treverse_proxy {\n\t\t{block}\n\t}\n}\n",
        );
        let main = write(
            &dir,
            "main.conf",
            "import ./defs.conf\n\n:8080 {\n\timport test {\n\t\tthis_is_nonsense\n\t}\n}\n",
        );
        let source = std::fs::read_to_string(&main).unwrap();
        let error = crate::compile_named(&source, Some(&main))
            .expect_err("the nonsense subdirective must be refused")
            .to_string();
        assert!(error.contains("this_is_nonsense"), "{error}");
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
