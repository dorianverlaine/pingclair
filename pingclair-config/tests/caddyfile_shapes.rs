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
