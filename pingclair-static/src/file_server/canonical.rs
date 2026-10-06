// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔁 Builds canonical static paths without introducing an authority.

/// 🔁 Selects the canonical trailing slash for the filesystem entry.
pub(super) enum Entry {
    /// 📁 A directory needs a trailing slash for relative links.
    Directory,
    /// 📄 A regular file has no trailing slash.
    File,
}

/// 🛡️ Cleans path segments and quotes browser separators before adding the query.
///
/// 🔁 This runs only after a redirect is needed. Escaped non-dot path bytes and query
/// bytes retain their spelling; literal backslashes must not become URL slashes.
pub(super) fn location(path: &str, query: Option<&str>, entry: Entry) -> String {
    let mut target = String::with_capacity(path.len() + query.map_or(0, |q| q.len() + 1) + 1);
    for segment in path.split('/') {
        // 🧭 Browsers recognize encoded dots before removing parent segments.
        if segment.is_empty() || segment == "." || segment.eq_ignore_ascii_case("%2e") {
            continue;
        }
        if segment == ".."
            || segment.eq_ignore_ascii_case(".%2e")
            || segment.eq_ignore_ascii_case("%2e.")
            || segment.eq_ignore_ascii_case("%2e%2e")
        {
            target.truncate(target.rfind('/').unwrap_or(0));
            continue;
        }
        target.push('/');
        for character in segment.chars() {
            match character {
                '\\' => target.push_str("%5C"),
                '#' => target.push_str("%23"),
                _ => target.push(character),
            }
        }
    }
    if matches!(entry, Entry::Directory) || target.is_empty() {
        target.push('/');
    }
    if let Some(query) = query {
        target.push('?');
        target.push_str(query);
    }
    target
}
