//! 🚫 A block directive's matcher token is `*`, a `/path`, or `@name`.
//!
//! Anything else in that position used to be dropped without a word, so
//! `handle *.php { … }` became a block with no matcher and answered every
//! request on the site — PHP or not.

use crate::compile;

/// 🧾 Compiles one site body and returns the error text, if any.
///
/// The cases are written on one line for a readable table; a Caddyfile block
/// needs its braces on their own lines, so they are expanded here.
fn refusal(body: &str) -> Option<String> {
    let body = body.replace("{ ", "{\n").replace(" }", "\n}");
    compile(&format!(":8080 {{\n{body}\n}}\n"))
        .err()
        .map(|error| error.to_string())
}

/// 🚫 Every block directive, at site level and nested, refuses a token that
/// is not a matcher, and accepts the three spellings that are.
#[test]
fn block_directives_refuse_a_token_that_is_not_a_matcher() {
    let cases = [
        ("handle *.php { respond \"php\" }", false),
        ("route *.php { respond \"php\" }", false),
        ("handle /a /b { respond \"two\" }", false),
        ("route { handle *.php { respond \"php\" } }", false),
        ("handle { route *.php { respond \"php\" } }", false),
        ("handle * { respond \"any\" }", true),
        ("handle /api/* { respond \"api\" }", true),
        ("@php path *.php\nhandle @php { respond \"php\" }", true),
        ("route { handle /x { respond \"x\" } }", true),
    ];
    let outcomes: Vec<_> = cases
        .iter()
        .map(|(body, _)| (*body, refusal(body).is_none()))
        .collect();
    let expected: Vec<_> = cases.iter().map(|(body, ok)| (*body, *ok)).collect();
    assert_eq!(outcomes, expected);
}
