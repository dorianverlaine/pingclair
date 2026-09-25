// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧩 What a `path` pattern's `*` means, in one place.
//!
//! A pattern is read the way the reference `path` matcher reads it, and the
//! position of its `*` characters decides which of five kinds it is:
//!
//! | Pattern          | Kind       | Matches                                   |
//! | ---------------- | ---------- | ----------------------------------------- |
//! | `/a/b`           | exact      | only `/a/b`                               |
//! | `/a/*`           | prefix     | anything starting with `/a/`              |
//! | `*.php`          | suffix     | anything ending in `.php`, at any depth   |
//! | `*/admin/*`      | substring  | anything containing `/admin/`             |
//! | `/a/*x`, `/*/b*` | glob       | segment by segment; `*` never crosses `/` |
//!
//! Only a pattern with exactly one `*` is a prefix or suffix, and only one
//! with exactly two, at both ends, is a substring. Every other `*` makes a
//! glob, in which a `*` stands for any run of characters **inside one path
//! segment**: `/a/*x` matches `/a/bx` but not `/a/b/cx`, and `/a/*/b*`
//! matches `/a/1/bee` but not `/a/1/b/c`. Comparison ignores ASCII case,
//! because the reference lowercases both the pattern and the path. The same
//! holds for an exact or prefix route path, which the radix pre-filter
//! stores lowercased and looks up through [`with_ascii_lowercase`].
//!
//! 📜 Where this comes from: `MatchPath.MatchWithError` in the reference's
//! `modules/caddyhttp/matchers.go` (v2.x), written from memory of that
//! function on 2026-09-25 and not re-read against its source. The fast cases
//! it tries before falling back to Go's `path.Match` are the ones above, in
//! that order. Three details of the reference are deliberately **not**
//! reproduced, and would be the first thing to check if a measurement ever
//! disagrees:
//!
//! - `path.Match` also gives `?`, `[…]` and `\` a meaning. Here they are
//!   literal characters; only `*` is a wildcard.
//! - A pattern containing `%` is compared against the escaped path there.
//!   Here it is compared against the decoded path like any other pattern.
//! - Lowercasing there is Unicode-aware; here it is ASCII only.
//!
//! 🏎️ [`PathPattern::of`] classifies once; [`PathPattern::matches`] only
//! compares bytes. Neither allocates, so a route can keep a classified
//! pattern from load time and test it on every request.

/// 🧭 One `path` pattern, classified by where its `*` characters are.
///
/// `S` is `&str` for a pattern borrowed from configuration and `Box<str>`
/// for one a route keeps for its lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PathPattern<S> {
    /// `*` alone: every path.
    Any,
    /// No `*`: the whole path, ignoring ASCII case.
    Exact(S),
    /// One trailing `*`, stored without it.
    Prefix(S),
    /// One leading `*`, stored without it.
    Suffix(S),
    /// Exactly two `*`, one at each end, stored without them.
    Substring(S),
    /// Any other placement, stored whole: `*` matches within one segment.
    Glob(S),
}

impl<'a> PathPattern<&'a str> {
    /// 🔎 Classifies a pattern the way the reference picks its fast path.
    pub(super) fn of(pattern: &'a str) -> Self {
        let stars = pattern.bytes().filter(|&byte| byte == b'*').count();
        let leading = pattern.starts_with('*');
        let trailing = pattern.ends_with('*');
        match stars {
            0 => Self::Exact(pattern),
            1 if pattern.len() == 1 => Self::Any,
            1 if leading => Self::Suffix(&pattern[1..]),
            1 if trailing => Self::Prefix(&pattern[..pattern.len() - 1]),
            2 if leading && trailing => Self::Substring(&pattern[1..pattern.len() - 1]),
            _ => Self::Glob(pattern),
        }
    }

    /// 📦 The same classification, owning its text so a route can keep it.
    pub(super) fn to_owned(self) -> PathPattern<Box<str>> {
        match self {
            Self::Any => PathPattern::Any,
            Self::Exact(text) => PathPattern::Exact(text.into()),
            Self::Prefix(text) => PathPattern::Prefix(text.into()),
            Self::Suffix(text) => PathPattern::Suffix(text.into()),
            Self::Substring(text) => PathPattern::Substring(text.into()),
            Self::Glob(text) => PathPattern::Glob(text.into()),
        }
    }
}

impl<S: AsRef<str>> PathPattern<S> {
    /// 🎯 Whether `path` matches, ignoring ASCII case.
    pub(super) fn matches(&self, path: &str) -> bool {
        let path = path.as_bytes();
        match self {
            Self::Any => true,
            Self::Exact(text) => path.eq_ignore_ascii_case(text.as_ref().as_bytes()),
            Self::Prefix(text) => starts_with(path, text.as_ref().as_bytes()),
            Self::Suffix(text) => ends_with(path, text.as_ref().as_bytes()),
            Self::Substring(text) => contains(path, text.as_ref().as_bytes()),
            Self::Glob(text) => glob(text.as_ref().as_bytes(), path),
        }
    }

    /// 🌲 The text every matching path must start with: everything before
    /// the first `*`. The radix pre-filter uses it to leave a pattern off
    /// the nodes it can never match.
    pub(super) fn literal_prefix(&self) -> &str {
        match self {
            Self::Any | Self::Suffix(_) | Self::Substring(_) => "",
            Self::Exact(text) | Self::Prefix(text) => text.as_ref(),
            Self::Glob(text) => {
                let text = text.as_ref();
                text.find('*').map_or(text, |star| &text[..star])
            }
        }
    }
}

/// 🔎 Whether `text` has an ASCII uppercase letter, the question every
/// request asks before its radix lookup (issue #198).
///
/// 🏎️ Eight bytes at a time: a byte-at-a-time scan with an early exit cost
/// about 6 ns on a 19-byte path in the router benchmark, which is a third of
/// a whole route selection. For a byte `b` below 0x80, `b + 0x3F` sets the
/// top bit exactly when `b >= b'A'`, and `b + 0x25` exactly when
/// `b > b'Z'`; neither sum can carry into the next byte. Bytes at or above
/// 0x80 (UTF-8 continuation and lead bytes) are masked out by `!word`.
pub(super) fn has_ascii_uppercase(text: &str) -> bool {
    const ONES: u64 = u64::from_ne_bytes([0x01; 8]);
    const HIGH: u64 = ONES * 0x80;
    let bytes = text.as_bytes();
    let (words, rest) = bytes.as_chunks::<8>();
    for &word in words {
        let word = u64::from_ne_bytes(word);
        let at_least_a = word.wrapping_add(ONES * 0x3F);
        let above_z = word.wrapping_add(ONES * 0x25);
        if at_least_a & !above_z & !word & HIGH != 0 {
            return true;
        }
    }
    rest.iter().any(u8::is_ascii_uppercase)
}

/// 📏 The longest path [`with_ascii_lowercase`] folds on the stack. Real
/// request paths are tens of bytes; one longer than this that also has an
/// uppercase letter pays for one heap copy instead.
const FOLD_ON_STACK: usize = 256;

/// 🔤 Calls `f` with `path` lowercased (ASCII only), without a heap
/// allocation unless the path is unusually long.
///
/// The radix pre-filter compares bytes exactly and its nodes were
/// lowercased at load, so a request path with an uppercase letter must be
/// folded the same way before the lookup (issue #198). The caller checks
/// [`has_ascii_uppercase`] first, so a lowercase path, nearly every
/// request, never gets here and is not copied at all.
///
/// - 📦 A path up to [`FOLD_ON_STACK`] bytes is folded into a buffer on the
///   stack.
/// - 🐢 A longer one is folded into a `String`: one allocation for a request
///   that is already unusual, which keeps the answer correct rather than
///   capping how long a routable path may be.
///
/// Folding only ASCII keeps every other byte in place, so the result is
/// still valid UTF-8 and has the same length as `path`.
pub(super) fn with_ascii_lowercase<R>(path: &str, f: impl FnOnce(&str) -> R) -> R {
    if path.len() <= FOLD_ON_STACK {
        let mut buffer = [0u8; FOLD_ON_STACK];
        let folded = &mut buffer[..path.len()];
        folded.copy_from_slice(path.as_bytes());
        folded.make_ascii_lowercase();
        // 🛡️ Cannot fail, since ASCII folding keeps UTF-8 valid; checking
        // anyway costs a few nanoseconds on an uncommon path and needs no
        // `unsafe`.
        if let Ok(folded) = std::str::from_utf8(folded) {
            return f(folded);
        }
    }
    f(&path.to_ascii_lowercase())
}

/// 🔤 `text` starts with `prefix`, ignoring ASCII case.
pub(super) fn starts_with(text: &[u8], prefix: &[u8]) -> bool {
    text.len() >= prefix.len() && text[..prefix.len()].eq_ignore_ascii_case(prefix)
}

fn ends_with(text: &[u8], suffix: &[u8]) -> bool {
    text.len() >= suffix.len() && text[text.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
}

/// 🔎 A plain window scan: paths and patterns are tens of bytes, where a
/// searcher that has to be built first would cost more than it saves.
fn contains(text: &[u8], needle: &[u8]) -> bool {
    needle.is_empty()
        || text
            .windows(needle.len())
            .any(|window| window.eq_ignore_ascii_case(needle))
}

/// 🧩 Segment-by-segment glob. Because `*` never matches `/`, a pattern and
/// a path can only match with the same number of segments, and then each
/// pattern segment must match the path segment in the same position.
fn glob(pattern: &[u8], path: &[u8]) -> bool {
    let mut patterns = pattern.split(|&byte| byte == b'/');
    let mut segments = path.split(|&byte| byte == b'/');
    loop {
        match (patterns.next(), segments.next()) {
            (Some(pattern), Some(segment)) => {
                if !segment_glob(pattern, segment) {
                    return false;
                }
            }
            (None, None) => return true,
            _ => return false,
        }
    }
}

/// 🔁 Glob within one segment, where `*` matches any run of bytes. On a
/// mismatch it retries from the most recent `*` one byte further along,
/// which is linear in practice and never recurses.
fn segment_glob(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        if p < pattern.len() && pattern[p] == b'*' {
            star = Some((p, t));
            p += 1;
        } else if p < pattern.len() && pattern[p].eq_ignore_ascii_case(&text[t]) {
            p += 1;
            t += 1;
        } else if let Some((star_p, star_t)) = star {
            p = star_p + 1;
            t = star_t + 1;
            star = Some((star_p, star_t + 1));
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|&byte| byte == b'*')
}

// MARK: - Tests

#[cfg(test)]
mod tests {
    use super::PathPattern;

    #[test]
    fn the_position_of_the_star_picks_the_kind() {
        // 🧭 Only one trailing or leading `*` is a prefix or suffix; a
        // second `*` anywhere else turns the whole pattern into a glob.
        let kinds: Vec<PathPattern<&str>> = [
            "*",
            "/a",
            "/a/*",
            "*.php",
            "*/admin/*",
            "/a/*x",
            "/*/b*",
            "*a*b",
            "**",
        ]
        .into_iter()
        .map(PathPattern::of)
        .collect();
        assert_eq!(
            kinds,
            [
                PathPattern::Any,
                PathPattern::Exact("/a"),
                PathPattern::Prefix("/a/"),
                PathPattern::Suffix(".php"),
                PathPattern::Substring("/admin/"),
                PathPattern::Glob("/a/*x"),
                PathPattern::Glob("/*/b*"),
                PathPattern::Glob("*a*b"),
                PathPattern::Substring(""),
            ]
        );
    }

    /// 🎯 Each pattern against the paths it must and must not match.
    #[test]
    fn each_kind_matches_like_the_reference() {
        let cases: &[(&str, &[&str], &[&str])] = &[
            ("/a", &["/a", "/A"], &["/a/", "/ab"]),
            ("/a/*", &["/a/", "/a/b/c", "/A/B"], &["/a", "/b/a/"]),
            (
                "*.php",
                &["/index.php", "/x/y/Z.PHP"],
                &["/index.php/x", "/php"],
            ),
            (
                "*/admin/*",
                &["/x/admin/y", "/admin/"],
                &["/admin", "/xadmin/"],
            ),
            (
                "/a/*x",
                &["/a/bx", "/a/x", "/A/BX"],
                &["/a/b/cx", "/a/bxy", "/b/bx"],
            ),
            ("/*/bx", &["/a/bx", "/z/bx"], &["/a/b/bx", "/bx"]),
            ("/a/*/b*", &["/a/1/b", "/a/1/bee"], &["/a/1/b/c", "/a/b"]),
            ("/a*b*c", &["/abc", "/a-b-c", "/abbbc"], &["/ab/c", "/acb"]),
        ];
        for (pattern, hits, misses) in cases {
            let compiled = PathPattern::of(pattern);
            for path in *hits {
                assert!(compiled.matches(path), "{pattern} should match {path}");
                assert!(
                    compiled.to_owned().matches(path),
                    "owned {pattern} vs {path}"
                );
            }
            for path in *misses {
                assert!(!compiled.matches(path), "{pattern} should not match {path}");
            }
        }
    }

    #[test]
    fn folding_lowercases_ascii_on_every_path_length() {
        // 🔤 Short and long mixed-case paths take different buffers; both
        // must fold only ASCII letters and leave other bytes alone.
        let long = format!("/Ä/{}", "Ab".repeat(200));
        let folded: Vec<String> = ["/already/lower", "/Mixed/Case/ÄB", long.as_str()]
            .into_iter()
            .map(|path| super::with_ascii_lowercase(path, str::to_string))
            .collect();
        assert_eq!(
            folded,
            [
                "/already/lower".to_string(),
                "/mixed/case/Äb".to_string(),
                format!("/Ä/{}", "ab".repeat(200)),
            ]
        );
    }

    #[test]
    fn the_uppercase_scan_sees_a_capital_in_any_byte_position() {
        // 🔎 A capital in each position of a word and in the remainder, the
        // two letters at the edges of the range, the bytes just outside it,
        // and non-ASCII bytes, which must never count.
        let mut seen = Vec::new();
        for position in 0..19 {
            let mut path = vec![b'a'; 19];
            path[position] = b'Q';
            seen.push(super::has_ascii_uppercase(
                std::str::from_utf8(&path).unwrap(),
            ));
        }
        assert_eq!(seen, [true; 19]);
        let edges: Vec<bool> = [
            "/abcdefgA",
            "/abcdefgZ",
            "/abcdefg@",
            "/abcdefg[",
            "/ÄÖÜéàèìò",
            "",
        ]
        .into_iter()
        .map(super::has_ascii_uppercase)
        .collect();
        assert_eq!(edges, [true, true, false, false, false, false]);
    }

    #[test]
    fn the_literal_prefix_stops_at_the_first_star() {
        let prefixes: Vec<String> = ["/a/*x", "*.php", "/a/*", "/a", "*/x/*"]
            .into_iter()
            .map(|pattern| PathPattern::of(pattern).literal_prefix().to_string())
            .collect();
        assert_eq!(prefixes, ["/a/", "", "/a/", "/a", ""]);
    }
}
