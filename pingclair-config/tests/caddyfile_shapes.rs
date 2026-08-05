// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧱 Structural shapes a Caddyfile is allowed to take, and the ones it is not.
//!
//! These are about the *shape of the file* rather than any one directive: where
//! a site block begins, when braces are required, and which arrangements have to
//! be refused. Every case here was found by running the Caddyfile format's own
//! regression corpus through this crate — 228 configurations written by the
//! people who define the format, which between them use shapes nobody here
//! would have thought to write a test for.
//!
//! 🎯 **Why these live in the repository while the corpus does not.** The corpus
//! is a megabyte of someone else's test data, most of which this crate cannot
//! yet compile, and a directory full of configurations that are *supposed* to
//! fail is a trap for anyone reading it as documentation. So the corpus stays a
//! local measurement tool and the *shapes it revealed* are written out here, in
//! our own words, where CI runs them on every commit.
//!
//! 📌 Two cases are `#[ignore]`d on purpose. They are the acceptance tests for
//! known gaps, written now so that the fix has something to turn green rather
//! than being declared done by inspection. Do not delete them to make the suite
//! quiet; a red test that is honest is worth more than a green suite that is
//! not.

use pingclair_config::compile;

/// Whether the compiler accepts a configuration at all.
fn compiles(source: &str) -> bool {
    compile(source).is_ok()
}

// MARK: - Shapes that must compile

/// 🧭 The single-site shorthand: an address on its own line, then directives,
/// no braces anywhere. This is the shortest configuration the format allows and
/// the corpus leans on it heavily.
#[test]
fn a_single_site_needs_no_braces() {
    assert!(compiles(":80\nrespond \"ok\"\n"));
}

/// 🧭 A global options block is not a site block, so the shorthand above stays
/// legal after one. Getting this wrong makes the two most common openings in
/// real configurations mutually exclusive.
#[test]
fn a_global_block_may_precede_the_shorthand() {
    assert!(compiles("{\n\tauto_https off\n}\n\nlocalhost\n"));
}

#[test]
fn a_global_block_may_precede_a_braced_site() {
    assert!(compiles(
        "{\n\tauto_https off\n}\n\nlocalhost {\n\trespond \"ok\"\n}\n"
    ));
}

#[test]
fn several_braced_sites_may_coexist() {
    assert!(compiles(
        "a.example {\n\trespond \"a\"\n}\nb.example {\n\trespond \"b\"\n}\n"
    ));
}

// MARK: - Shapes that must be refused

/// 🚫 Bare directives and braced sites cannot be mixed, because there is no way
/// to tell which site the bare ones belong to. Refusing is the whole point: the
/// alternative is silently attaching them to whichever site happens to be first.
#[test]
fn bare_directives_may_not_be_mixed_with_braced_sites() {
    assert!(!compiles(
        "example.com\nrespond \"one\"\n\nother.example {\n\trespond \"two\"\n}\n"
    ));
}

// MARK: - Known gaps (acceptance tests for pending work)

/// 🐛 A directive carrying its own block, inside the unbraced single-site
/// shorthand.
///
/// The opening brace of `file_server { … }` is currently mistaken for the start
/// of a second site block, so this is rejected with a complaint about mixing
/// bare directives with braced sites — while the same configuration with a
/// block-less directive compiles. It is the single largest gap the corpus
/// found: 58 of its 228 configurations fail on this one shape and nothing else.
///
/// The fix is structural rather than local — the parser has no way to
/// distinguish a directive's block from a site's block — so this test is the
/// acceptance criterion for that work, not a reminder to patch it here.
#[test]
#[ignore = "known gap: a directive's own block is read as a second site block"]
fn the_shorthand_accepts_a_directive_with_its_own_block() {
    assert!(compiles(":80\nfile_server {\n\thide first.txt\n}\n"));
}

/// 🐛 A known directive name used where a site address belongs.
///
/// `handle` on its own line is accepted as a hostname today. It should be
/// refused, saying that the name is a directive and that directives belong
/// inside a site block — otherwise the operator gets a server listening on a
/// site called `handle` and no hint about why nothing works.
///
/// 🚨 This one fails *open*, which is why it is written down rather than left
/// to be noticed: a configuration that loads and then serves nothing useful
/// gives the operator nothing to search for.
#[test]
#[ignore = "known gap: a directive name is accepted as a site address"]
fn a_directive_name_is_refused_as_a_site_address() {
    assert!(!compiles("handle\n\nrespond \"should not work\"\n"));
}

// MARK: - Heredoc

/// 📜 The whole point: multi-line text without escaping every newline. The
/// indentation of the closing marker is stripped from every line, so a heredoc
/// can sit at whatever depth its block does without that depth reaching the
/// value.
#[test]
fn a_heredoc_strips_the_closing_markers_indentation() {
    let config = compile("example.com {\n\trespond <<EOF\n    a\n      b\n    c\n    EOF\n}\n")
        .expect("must compile");
    let rendered = format!("{:?}", config.servers[0].routes[0].handler);
    assert!(
        rendered.contains(r"a\n  b\nc"),
        "relative indentation must survive, absolute must not: {rendered}"
    );
}

/// 🧭 The body ends at the first *word* that ends with the marker, not the first
/// line — so `EOF 200` closes the body and still leaves `200` to be read as the
/// status code. Treating it as a line would swallow the argument.
#[test]
fn a_heredoc_leaves_the_rest_of_the_closing_line_to_be_parsed() {
    let config =
        compile("example.com {\n\trespond <<EOF\n    hi\n    EOF 418\n}\n").expect("must compile");
    let rendered = format!("{:?}", config.servers[0].routes[0].handler);
    assert!(
        rendered.contains("418"),
        "the status must survive: {rendered}"
    );
}

/// 🚫 A line that does not carry the closing marker's indentation is refused
/// rather than stripped as best it can be. Guessing would silently rewrite the
/// operator's text, and text is the one thing a heredoc exists to preserve.
#[test]
fn mismatched_indentation_is_refused() {
    assert!(!compiles(
        "example.com {\n\trespond <<END\n  short\n        long\n    END\n}\n"
    ));
}

/// 🚫 The marker's spelling is constrained, so a punctuation typo is named
/// rather than becoming a marker that never appears again.
#[test]
fn an_invalid_marker_is_refused() {
    assert!(!compiles(
        "example.com {\n\trespond <<END!\n    hi\n    END!\n}\n"
    ));
    assert!(!compiles("example.com {\n\trespond <<\n    hi\n}\n"));
    assert!(!compiles(
        "example.com {\n\trespond <<<END\n    hi\n    END\n}\n"
    ));
}

/// 🚫 Running to end of file must say which marker was expected. Without the
/// marker in the message the operator has to guess which of several heredocs
/// in the file was left open.
#[test]
fn an_unterminated_heredoc_names_the_marker() {
    let error = compile("example.com {\n\trespond <<NOPE\n    hi\n")
        .expect_err("must not compile")
        .to_string();
    assert!(error.contains("NOPE"), "must name the marker: {error}");
}

/// 📌 `<<` with a space after it is an ordinary token. An operator writing a
/// shell-style redirect is not opening a heredoc, and hijacking it would make
/// the file fail somewhere far from the line they wrote.
#[test]
fn a_space_after_the_angles_is_not_a_heredoc() {
    assert!(compiles("example.com {\n\trespond \"<< notaheredoc\"\n}\n"));
}
