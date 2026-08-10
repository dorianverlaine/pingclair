// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧭 MIME type handling.
//!
//! 📌 No blanket `allow(dead_code)` here. It used to carry one because
//! `build_meta` inlined `guess_mime_type` instead of calling it, so the
//! function looked unused — and the attribute then suppressed dead-code
//! warnings on everything else in the file too. The duplication is gone, so
//! the lint is back on and can do its job.

/// Get MIME type for a file extension
pub fn guess_mime_type(path: &str) -> String {
    with_charset(
        mime_guess::from_path(path)
            .first_raw()
            .unwrap_or("application/octet-stream"),
    )
}

/// 🧭 Caddy appends `; charset=utf-8` to text types; keep the same default
/// so legacy clients do not guess at the encoding.
pub fn with_charset(mime: &str) -> String {
    // 🧭 Caddy sends `text/html; charset=utf-8`; a bare `text/*` leaves
    // legacy clients guessing at the encoding.
    if mime.starts_with("text/") && !mime.contains("charset") {
        format!("{mime}; charset=utf-8")
    } else {
        mime.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mime_types() {
        assert_eq!(guess_mime_type("index.html"), "text/html; charset=utf-8");
        assert_eq!(guess_mime_type("style.css"), "text/css; charset=utf-8");
        assert_eq!(guess_mime_type("app.js"), "text/javascript; charset=utf-8");
    }
}
