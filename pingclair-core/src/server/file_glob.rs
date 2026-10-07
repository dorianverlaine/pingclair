// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔍 Expanding a `file` matcher glob against the filesystem, in bytes.
//!
//! On Unix a filename is bytes, not text. The `glob` crate (0.3.4, checked
//! 2026-09-24) matches each directory entry through `OsStr::to_str` and skips
//! any name that is not valid UTF-8 — its own `FIXME (#9639)` in
//! `Paths::next` says so. A `try_files /build/*.js` candidate therefore could
//! not see a file named `caf\xE9.js` even though it was sitting in the
//! directory, and the file server one step later would have served it.
//!
//! This module walks the directories itself and matches entry names as bytes,
//! so every name the filesystem holds is a name a pattern can match. Results
//! stay `PathBuf`s from end to end; nothing is converted to text on the way.
//!
//! # 🧭 Pattern language
//!
//! The same one the `glob` crate accepted, so existing configurations keep
//! their meaning:
//!
//! - `*` matches any run within one component, `?` exactly one character.
//! - `[abc]`, `[a-z]` and `[!abc]` match one character from, or not from, a
//!   set. A `]` right after the opening `[` (or `[!`) is literal, which is how
//!   a placeholder value is escaped: `*` becomes `[*]`, `]` becomes `[]]`.
//! - A component that is exactly `**` matches zero or more directories.
//!
//! "Character" means a UTF-8 character where the name's bytes form one, and a
//! single byte where they do not. `caf?.js` therefore matches both `café.js`
//! (two bytes for the `é`) and `caf\xE9.js` (one Latin-1 byte), which is what
//! an operator writing `?` means either way.
//!
//! # 🛡️ Bounds
//!
//! The root is literal: metacharacters in a configured `root` are not
//! expanded. A `..` component is refused rather than followed. `**` does not
//! descend through symbolic links, so a link pointing at an ancestor cannot
//! turn one request into an endless walk. Expansion stops at `limit` results,
//! and the walk that looks for them may examine at most
//! [`MAX_VISITED_ENTRIES`] directory entries: a result limit alone does not
//! bound the work, because a directory is read in full before the first match
//! can stop anything.

use std::path::{Path, PathBuf};

/// 🛡️ Directory entries one expansion may examine while looking for matches.
///
/// 📌 The result limit stopped the caller from receiving more candidates, not
/// the walk from doing more work: a directory holding a hundred thousand
/// entries was read and sorted in full before the first match could stop
/// anything, and `**` walked a whole tree for a pattern that matched nothing
/// (#240). This budget follows the walk itself and stops it wherever the work
/// happens. It is far above any plausible configuration, so reaching it means
/// the pattern was pointed somewhere it should not have been — the same
/// reading the result limit already has.
const MAX_VISITED_ENTRIES: usize = 16 * 1024;

/// 🔍 Expands `pattern`, a cleaned URI-style path, below `root`.
///
/// Returns every existing path it names, in byte order of each directory's
/// entries, at most `limit` of them. A malformed pattern — an unterminated
/// `[` — or a `..` component names nothing.
pub(super) fn expand(root: &Path, pattern: &str, limit: usize) -> Vec<PathBuf> {
    let components: Vec<&str> = pattern
        .split('/')
        .filter(|component| !component.is_empty() && *component != ".")
        .collect();
    if components.contains(&"..")
        || components
            .iter()
            .any(|component| has_meta(component) && Glob::compile(component).is_none())
    {
        return Vec::new();
    }
    let mut walk = Walk {
        limit,
        visited: 0,
        budget: MAX_VISITED_ENTRIES,
        found: Vec::new(),
    };
    walk_components(root.to_path_buf(), &components, &mut walk);
    walk.found
}

/// 🚶 One expansion's state: what it has found, and what it may still spend.
struct Walk {
    /// 🎯 The result ceiling the caller asked for.
    limit: usize,
    /// 📂 Directory entries examined so far.
    visited: usize,
    /// 🛡️ How many may be examined in total.
    budget: usize,
    /// 🗂️ The matches, in walk order.
    found: Vec<PathBuf>,
}

impl Walk {
    /// 🎯 Whether the caller already has as many matches as it asked for.
    fn full(&self) -> bool {
        self.found.len() >= self.limit
    }

    /// 🛡️ Whether no more directory entries may be read. A name already
    /// collected is still followed: this budget bounds the reading, and the
    /// result limit bounds what following those names can produce.
    fn spent(&self) -> bool {
        self.visited >= self.budget
    }
}

/// 🙈 One glob compiled to match a single path component by its bytes.
///
/// The `file_server` `hide` list matches each component of a resolved path
/// against its patterns, and that path is bytes: the file server serves
/// `secret\xE9.env` from `/secret%E9.env`. Matching through the `glob` crate
/// skipped every such name (`Pattern::matches_path`, glob 0.3.4, returns
/// `false` when `Path::to_str` fails), so `hide *.env` hid `secret.env` and
/// served `secret\xE9.env`. This is the same matcher the `file` matcher's
/// expansion uses, so the two agree on what a pattern names.
///
/// 🏎️ Compiled once, when the configuration loads: every `[…]` set is parsed
/// into its ranges here, so matching a request's path allocates nothing.
#[derive(Debug, Clone)]
pub struct ComponentGlob(Glob);

impl ComponentGlob {
    /// 🧾 Compiles `pattern`, or returns `None` when a `[` set never closes.
    pub fn new(pattern: &str) -> Option<Self> {
        Glob::compile(pattern).map(Self)
    }

    /// 🔍 Reports whether `name`, one path component, matches.
    pub fn matches(&self, name: &std::ffi::OsStr) -> bool {
        crate::percent::path_bytes(Path::new(name)).is_some_and(|name| self.0.matches(name))
    }
}

/// 🚶 Matches `rest` below `base`, depth first, appending hits to the walk.
fn walk_components(base: PathBuf, rest: &[&str], walk: &mut Walk) {
    if walk.full() {
        return;
    }
    let Some((component, after)) = rest.split_first() else {
        // 📏 A literal tail was joined without asking the filesystem, so the
        // existence check happens once, here, for the whole path.
        if base.metadata().is_ok() {
            walk.found.push(base);
        }
        return;
    };
    if *component == "**" {
        walk_recursive(base, after, walk);
        return;
    }
    if !has_meta(component) {
        // 🍃 A literal component costs a join, not a directory read.
        walk_components(base.join(component), after, &mut *walk);
        return;
    }
    // 📌 `expand` refused a malformed component before the walk began.
    let Some(glob) = Glob::compile(component) else {
        return;
    };
    for name in matching_entries(&base, &glob, walk) {
        walk_components(base.join(name), after, &mut *walk);
        if walk.full() {
            return;
        }
    }
}

/// 🌲 `**`: tries the rest of the pattern here, then in every subdirectory.
fn walk_recursive(base: PathBuf, rest: &[&str], walk: &mut Walk) {
    walk_components(base.clone(), rest, walk);
    for name in sorted_entries(
        &base,
        |entry| {
            // 🛡️ `DirEntry::file_type` does not follow symbolic links, so a link
            // back to an ancestor is never descended into.
            entry.file_type().is_ok_and(|kind| kind.is_dir())
        },
        walk,
    ) {
        if walk.full() {
            return;
        }
        walk_recursive(base.join(name), rest, &mut *walk);
    }
}

/// 📂 The names in `dir` that match one pattern component, in byte order.
fn matching_entries(dir: &Path, glob: &Glob, walk: &mut Walk) -> Vec<std::ffi::OsString> {
    sorted_entries(
        dir,
        |entry| {
            crate::percent::path_bytes(Path::new(&entry.file_name()))
                .is_some_and(|name| glob.matches(name))
        },
        walk,
    )
}

/// 📂 The entries of `dir` that `keep` accepts, sorted by name.
///
/// 📌 Sorted because `first_exist` takes the first match, and the order a
/// directory happens to return its entries in is not something a
/// configuration should depend on. The `glob` crate sorted the same way.
///
/// 🛡️ Reading stops at the walk's remaining budget, and the names collected
/// before that are still sorted, so a directory too large to read in full
/// answers in the order its first entries would have anyway (#240).
fn sorted_entries(
    dir: &Path,
    keep: impl Fn(&std::fs::DirEntry) -> bool,
    walk: &mut Walk,
) -> Vec<std::ffi::OsString> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names = Vec::new();
    for entry in entries.flatten() {
        if walk.spent() {
            break;
        }
        walk.visited += 1;
        if keep(&entry) {
            names.push(entry.file_name());
        }
    }
    names.sort_unstable();
    names
}

/// 🔍 Reports whether a component contains a metacharacter.
fn has_meta(component: &str) -> bool {
    component
        .bytes()
        .any(|byte| matches!(byte, b'*' | b'?' | b'['))
}

/// 🧩 One piece of a compiled component pattern.
#[derive(Debug, Clone)]
enum Token {
    /// 🌟 `*`: any run of characters, including none.
    Star,
    /// ❓ `?`: exactly one character.
    One,
    /// 🔤 A character that must appear as written.
    Literal(char),
    /// 🧺 `[…]`: one character inside (or, negated, outside) these inclusive
    /// ranges; a single member is a range of one.
    Set {
        negated: bool,
        ranges: Box<[(char, char)]>,
    },
}

/// 🔍 A component pattern parsed into tokens, so matching a name is a walk
/// over them with no parsing and no allocation.
#[derive(Debug, Clone)]
struct Glob(Box<[Token]>);

impl Glob {
    /// 🧾 Parses `pattern`, or returns `None` when a `[` set never closes.
    fn compile(pattern: &str) -> Option<Self> {
        let bytes = pattern.as_bytes();
        let mut tokens = Vec::new();
        let mut index = 0;
        while index < bytes.len() {
            match bytes[index] {
                b'*' => {
                    tokens.push(Token::Star);
                    index += 1;
                }
                b'?' => {
                    tokens.push(Token::One);
                    index += 1;
                }
                b'[' => {
                    let end = class_end(bytes, index)?;
                    tokens.push(parse_set(&pattern[index + 1..end - 1]));
                    index = end;
                }
                _ => {
                    // 📌 `pattern` is a `str`, so a character starts here.
                    let literal = pattern[index..].chars().next()?;
                    tokens.push(Token::Literal(literal));
                    index += literal.len_utf8();
                }
            }
        }
        Some(Self(tokens.into()))
    }

    /// 🔍 Matches one name, as bytes.
    ///
    /// The classic single-star backtracking scan: remember the last `*` and
    /// how much of the name it had taken, and on a mismatch let it take one
    /// more unit. It never recurses and never allocates, and it is linear in
    /// practice for the short names and patterns a filesystem holds.
    fn matches(&self, name: &[u8]) -> bool {
        let tokens = &self.0;
        let (mut t, mut n) = (0, 0);
        let mut star: Option<(usize, usize)> = None;
        while n < name.len() {
            let (unit, width) = next_unit(&name[n..]);
            let fits = match tokens.get(t) {
                Some(Token::Star) => {
                    star = Some((t, n));
                    t += 1;
                    continue;
                }
                Some(Token::One) => true,
                Some(Token::Literal(literal)) => unit == Some(*literal),
                // 🔤 A byte that is not text is outside every set a pattern
                // can spell, so only a negated set admits it.
                Some(Token::Set { negated, ranges }) => unit.map_or(*negated, |unit| {
                    ranges
                        .iter()
                        .any(|&(low, high)| (low..=high).contains(&unit))
                        != *negated
                }),
                None => false,
            };
            if fits {
                t += 1;
                n += width;
            } else if let Some((star_t, star_n)) = star {
                // 🔁 Let the last `*` swallow one more unit and retry.
                let (_, swallowed) = next_unit(&name[star_n..]);
                star = Some((star_t, star_n + swallowed));
                t = star_t + 1;
                n = star_n + swallowed;
            } else {
                return false;
            }
        }
        tokens[t..].iter().all(|token| matches!(token, Token::Star))
    }
}

/// 📏 The index just past the `]` closing the set that opens at `open`.
fn class_end(pattern: &[u8], open: usize) -> Option<usize> {
    let mut index = open + 1;
    if pattern.get(index) == Some(&b'!') {
        index += 1;
    }
    // 📌 A `]` first in the set is a member, not the end.
    if pattern.get(index) == Some(&b']') {
        index += 1;
    }
    while index < pattern.len() {
        if pattern[index] == b']' {
            return Some(index + 1);
        }
        index += 1;
    }
    None
}

/// 🧺 Parses a set's body (between the brackets) into its ranges.
///
/// `a-c` is a range when a member follows the `-`; any other `-` is itself a
/// member.
fn parse_set(body: &str) -> Token {
    let (negated, body) = match body.strip_prefix('!') {
        Some(rest) => (true, rest),
        None => (false, body),
    };
    let members: Vec<char> = body.chars().collect();
    let mut ranges = Vec::with_capacity(members.len());
    let mut index = 0;
    while index < members.len() {
        if index + 2 < members.len() && members[index + 1] == '-' {
            ranges.push((members[index], members[index + 2]));
            index += 3;
        } else {
            ranges.push((members[index], members[index]));
            index += 1;
        }
    }
    Token::Set {
        negated,
        ranges: ranges.into(),
    }
}

/// 🔤 The character at the front of `bytes` and how many bytes it spans.
///
/// A byte that does not start a valid UTF-8 sequence is its own one-byte
/// unit, reported as `None`: it can match `?`, `*` or a negated set, but
/// never a literal, since a pattern is text and cannot contain that byte.
fn next_unit(bytes: &[u8]) -> (Option<char>, usize) {
    // 🛡️ `first` rather than `[0]`: this runs on names an uploader chose, and
    // with `panic = "abort"` an out-of-range index is the whole process.
    let width = match bytes.first() {
        None => return (None, 1),
        Some(0x00..=0x7f) => 1,
        Some(0xc0..=0xdf) => 2,
        Some(0xe0..=0xef) => 3,
        Some(0xf0..=0xf7) => 4,
        Some(_) => return (None, 1),
    };
    match bytes.get(..width).map(std::str::from_utf8) {
        Some(Ok(text)) => (text.chars().next(), width),
        _ => (None, 1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 🔍 Compiles and matches in one step, for the tables below.
    fn matches(pattern: &str, name: &[u8]) -> bool {
        Glob::compile(pattern).is_some_and(|glob| glob.matches(name))
    }

    /// 🧭 The pattern language the `glob` crate accepted keeps its meaning.
    #[test]
    fn patterns_match_as_before() {
        let cases: [(&str, &[u8], bool); 16] = [
            ("app.*.js", b"app.9f3c.js", true),
            ("app.*.js", b"app.js", false),
            ("*", b".hidden", true),
            ("a*b*c", b"aXXbYYc", true),
            ("a*b*c", b"aXXbYY", false),
            ("?.txt", b"a.txt", true),
            ("?.txt", b"ab.txt", false),
            ("[abc].txt", b"b.txt", true),
            ("[!abc].txt", b"b.txt", false),
            ("[a-c].txt", b"c.txt", true),
            ("[*]", b"*", true),
            ("[*]", b"x", false),
            ("[]]", b"]", true),
            ("[[]x", b"[x", true),
            ("caf?.js", "café.js".as_bytes(), true),
            ("CAF*", b"caf", false),
        ];
        for (pattern, name, expected) in cases {
            assert_eq!(
                matches(pattern, name),
                expected,
                "{pattern} against {}",
                String::from_utf8_lossy(name)
            );
        }
    }

    /// 📁 A name that is not valid UTF-8 is still matchable by bytes: `?` and
    /// `*` take the stray byte, a literal never does.
    #[test]
    fn non_utf8_names_match_by_bytes() {
        assert!(matches("caf*.js", b"caf\xe9.js"));
        assert!(matches("caf?.js", b"caf\xe9.js"));
        assert!(matches("caf[!a].js", b"caf\xe9.js"));
        assert!(!matches("caf[a-z].js", b"caf\xe9.js"));
        assert!(!matches("café.js", b"caf\xe9.js"));
    }

    /// 🧾 An unterminated set is a malformed pattern and names nothing.
    #[test]
    fn a_malformed_set_names_nothing() {
        assert!(Glob::compile("a[bc").is_none());
        assert!(Glob::compile("a[]]").is_some());
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a[bc"), "").unwrap();
        assert!(expand(dir.path(), "/a[bc", 8).is_empty());
    }

    /// 🛡️ The walk stops at its visited budget, not only at the result limit.
    ///
    /// Before this budget existed, one `read_dir` was read and sorted in full
    /// before the result limit could stop anything, and `**` walked whole
    /// trees for patterns that matched nothing (#240). The budget is tiny here
    /// so the test observes the stop without creating 16,384 files.
    #[test]
    fn the_walk_stops_at_its_visited_budget() {
        let dir = tempfile::tempdir().unwrap();
        for index in 0..64 {
            std::fs::write(dir.path().join(format!("f{index:02}.js")), "").unwrap();
        }
        let mut walk = Walk {
            limit: 8,
            visited: 0,
            budget: 4,
            found: Vec::new(),
        };
        walk_components(dir.path().to_path_buf(), &["*.js"], &mut walk);
        assert_eq!(walk.visited, 4, "the walk must stop at its budget");
        assert_eq!(
            walk.found.len(),
            4,
            "every entry examined matched; the budget is what stopped it"
        );
    }

    /// 🌲 `**` reaches nested matches in byte order, never climbs with `..`,
    /// and stops at the limit.
    #[test]
    fn recursive_walks_are_ordered_and_bounded() {
        let dir = tempfile::tempdir().unwrap();
        for path in ["b/deep/x.js", "a/x.js", "x.js"] {
            let full = dir.path().join(path);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, "").unwrap();
        }
        let relative = |paths: Vec<PathBuf>| -> Vec<String> {
            paths
                .iter()
                .map(|path| {
                    path.strip_prefix(dir.path())
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .to_string()
                })
                .collect()
        };
        assert_eq!(
            relative(expand(dir.path(), "/**/x.js", 8)),
            ["x.js", "a/x.js", "b/deep/x.js"]
        );
        assert_eq!(
            relative(expand(dir.path(), "/**/x.js", 2)),
            ["x.js", "a/x.js"]
        );
        assert!(expand(&dir.path().join("a"), "/../*.js", 8).is_empty());
    }
}
