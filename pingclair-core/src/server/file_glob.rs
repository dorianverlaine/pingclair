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
//! turn one request into an endless walk. Expansion stops at `limit` results.

use std::path::{Path, PathBuf};

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
            .any(|component| has_meta(component) && !is_well_formed(component.as_bytes()))
    {
        return Vec::new();
    }
    let mut found = Vec::new();
    walk(root.to_path_buf(), &components, limit, &mut found);
    found
}

/// 🚶 Matches `rest` below `base`, depth first, appending hits to `found`.
fn walk(base: PathBuf, rest: &[&str], limit: usize, found: &mut Vec<PathBuf>) {
    if found.len() >= limit {
        return;
    }
    let Some((component, after)) = rest.split_first() else {
        // 📏 A literal tail was joined without asking the filesystem, so the
        // existence check happens once, here, for the whole path.
        if base.metadata().is_ok() {
            found.push(base);
        }
        return;
    };
    if *component == "**" {
        walk_recursive(base, after, limit, found);
        return;
    }
    if !has_meta(component) {
        // 🍃 A literal component costs a join, not a directory read.
        walk(base.join(component), after, limit, found);
        return;
    }
    for name in matching_entries(&base, component.as_bytes()) {
        walk(base.join(name), after, limit, found);
        if found.len() >= limit {
            return;
        }
    }
}

/// 🌲 `**`: tries the rest of the pattern here, then in every subdirectory.
fn walk_recursive(base: PathBuf, rest: &[&str], limit: usize, found: &mut Vec<PathBuf>) {
    walk(base.clone(), rest, limit, found);
    for name in sorted_entries(&base, |entry| {
        // 🛡️ `DirEntry::file_type` does not follow symbolic links, so a link
        // back to an ancestor is never descended into.
        entry.file_type().is_ok_and(|kind| kind.is_dir())
    }) {
        if found.len() >= limit {
            return;
        }
        walk_recursive(base.join(name), rest, limit, found);
    }
}

/// 📂 The names in `dir` that match one pattern component, in byte order.
fn matching_entries(dir: &Path, pattern: &[u8]) -> Vec<std::ffi::OsString> {
    sorted_entries(dir, |entry| {
        crate::percent::path_bytes(Path::new(&entry.file_name()))
            .is_some_and(|name| matches(pattern, name))
    })
}

/// 📂 The entries of `dir` that `keep` accepts, sorted by name.
///
/// 📌 Sorted because `first_exist` takes the first match, and the order a
/// directory happens to return its entries in is not something a
/// configuration should depend on. The `glob` crate sorted the same way.
fn sorted_entries(
    dir: &Path,
    keep: impl Fn(&std::fs::DirEntry) -> bool,
) -> Vec<std::ffi::OsString> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names: Vec<_> = entries
        .flatten()
        .filter(|entry| keep(entry))
        .map(|entry| entry.file_name())
        .collect();
    names.sort_unstable();
    names
}

/// 🔍 Reports whether a component contains a metacharacter.
fn has_meta(component: &str) -> bool {
    component
        .bytes()
        .any(|byte| matches!(byte, b'*' | b'?' | b'['))
}

/// 🧾 Reports whether every `[` in a component opens a set that closes.
fn is_well_formed(pattern: &[u8]) -> bool {
    let mut index = 0;
    while index < pattern.len() {
        if pattern[index] == b'[' {
            match class_end(pattern, index) {
                Some(end) => index = end,
                None => return false,
            }
        } else {
            index += 1;
        }
    }
    true
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

/// 🔍 Matches one component pattern against one name, both as bytes.
///
/// The classic single-star backtracking scan: remember the last `*` and how
/// much of the name it had taken, and on a mismatch let it take one more
/// unit. It never recurses and never allocates, and it is linear in practice
/// for the short names and patterns a filesystem holds.
fn matches(pattern: &[u8], name: &[u8]) -> bool {
    let (mut p, mut n) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while n < name.len() {
        let (unit, width) = next_unit(&name[n..]);
        let step = match pattern.get(p) {
            Some(b'*') => {
                star = Some((p, n));
                p += 1;
                continue;
            }
            Some(b'?') => Some(p + 1),
            Some(b'[') => {
                class_end(pattern, p).filter(|&end| class_contains(&pattern[p + 1..end - 1], unit))
            }
            Some(_) => {
                let (literal, literal_width) = next_unit(&pattern[p..]);
                (literal.is_some() && literal == unit).then_some(p + literal_width)
            }
            None => None,
        };
        match (step, star) {
            (Some(next), _) => {
                p = next;
                n += width;
            }
            (None, Some((star_p, star_n))) => {
                // 🔁 Let the last `*` swallow one more unit and retry.
                let (_, swallowed) = next_unit(&name[star_n..]);
                star = Some((star_p, star_n + swallowed));
                p = star_p + 1;
                n = star_n + swallowed;
            }
            (None, None) => return false,
        }
    }
    pattern[p..].iter().all(|&byte| byte == b'*')
}

/// 🧺 Reports whether a set's body (between the brackets) admits `unit`.
fn class_contains(body: &[u8], unit: Option<char>) -> bool {
    let (negated, body) = match body.split_first() {
        Some((b'!', rest)) => (true, rest),
        _ => (false, body),
    };
    let Some(unit) = unit else {
        // 🔤 A byte that is not text is outside every set a pattern can spell.
        return negated;
    };
    let Ok(body) = std::str::from_utf8(body) else {
        return false;
    };
    let members: Vec<char> = body.chars().collect();
    let mut index = 0;
    let mut hit = false;
    while index < members.len() {
        if index + 2 < members.len() && members[index + 1] == '-' {
            hit |= (members[index]..=members[index + 2]).contains(&unit);
            index += 3;
        } else {
            hit |= members[index] == unit;
            index += 1;
        }
    }
    hit != negated
}

#[cfg(test)]
mod tests {
    use super::*;

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
                matches(pattern.as_bytes(), name),
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
        assert!(matches(b"caf*.js", b"caf\xe9.js"));
        assert!(matches(b"caf?.js", b"caf\xe9.js"));
        assert!(matches(b"caf[!a].js", b"caf\xe9.js"));
        assert!(!matches(b"caf[a-z].js", b"caf\xe9.js"));
        assert!(!matches("café.js".as_bytes(), b"caf\xe9.js"));
    }

    /// 🧾 An unterminated set is a malformed pattern and names nothing.
    #[test]
    fn a_malformed_set_names_nothing() {
        assert!(!is_well_formed(b"a[bc"));
        assert!(is_well_formed(b"a[]]"));
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a[bc"), "").unwrap();
        assert!(expand(dir.path(), "/a[bc", 8).is_empty());
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
