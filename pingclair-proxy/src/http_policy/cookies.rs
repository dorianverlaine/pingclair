// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🍪 Folding several `Cookie` field lines into one cookie-string.
//!
//! A request can carry its cookies on more than one line: HTTP/2 and HTTP/3
//! clients split them on purpose so each piece compresses on its own, and an
//! unusual HTTP/1.1 client may simply send two lines. Anything downstream
//! that expects one value — an HTTP/1 upstream, a CGI environment — must be
//! handed the pieces joined with `"; "` (RFC 6265 §4.2.1, RFC 9113 §8.2.3,
//! RFC 9114 §4.2.1).
//!
//! 🚫 The generic list separator `", "` is wrong here. A comma is not even a
//! legal cookie octet, so `a=1, b=2` reads as one cookie `a` whose value is
//! `1, b=2`. Every folding site uses this module so the rule lives once.

use std::borrow::Cow;

/// 🍪 The only separator the cookie-string grammar allows between pairs.
pub(crate) const COOKIE_SEPARATOR: &str = "; ";

/// 🍪 Accumulates `Cookie` field lines in arrival order.
///
/// 🍃 One line is the overwhelmingly common case, and it stays borrowed: the
/// fold allocates only when a second line actually arrives.
#[derive(Debug, Default)]
pub(crate) struct CookieFold<'a> {
    folded: Option<Cow<'a, str>>,
}

impl<'a> CookieFold<'a> {
    /// 🍪 Adds the next field line.
    pub(crate) fn push(&mut self, line: &'a str) {
        match &mut self.folded {
            None => self.folded = Some(Cow::Borrowed(line)),
            Some(folded) => {
                let joined = folded.to_mut();
                joined.reserve(COOKIE_SEPARATOR.len() + line.len());
                joined.push_str(COOKIE_SEPARATOR);
                joined.push_str(line);
            }
        }
    }

    /// 🍪 The single cookie-string, or `None` when no line was pushed.
    pub(crate) fn finish(self) -> Option<Cow<'a, str>> {
        self.folded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 🍪 Two lines fold with `"; "`, one line borrows, none yields nothing.
    #[test]
    fn folds_lines_with_the_cookie_separator() {
        let mut fold = CookieFold::default();
        fold.push("a=1");
        fold.push("b=2");
        fold.push("c=3");
        assert_eq!(fold.finish().as_deref(), Some("a=1; b=2; c=3"));

        let mut single = CookieFold::default();
        single.push("a=1");
        assert!(matches!(single.finish(), Some(Cow::Borrowed("a=1"))));

        assert_eq!(CookieFold::default().finish(), None);
    }
}
