// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 📍 An error must say where it is, in terms an operator can act on.
//!
//! Before this existed, a syntax error reported `Location { start: 42, end: 48 }`
//! — byte-ish offsets nobody can see in an editor — and never said which file it
//! came from. Both matter, and the second one matters most for a directory
//! configuration, where one line number belongs to any of several files.

use std::path::Path;

use pingclair_config::{compile, compile_named};

/// The rendered error for a source that must not compile.
fn error_for(source: &str, name: Option<&Path>) -> String {
    match compile_named(source, name) {
        Ok(_) => panic!("this source was expected to fail:\n{source}"),
        Err(error) => error.to_string(),
    }
}

/// 📍 A line and a column, not an offset. The column matters more than it looks:
/// `}}}` on one line has three plausible culprits and only one of them is the
/// one the parser tripped on.
#[test]
fn a_syntax_error_reports_line_and_column() {
    let source = "a.example {\n\trespond \"one\"\n}\n\nb.example {\n\trespond \"two\"\n\t}}}\n}\n";
    let rendered = error_for(source, None);
    assert!(
        rendered.contains("7:3"),
        "expected line 7 column 3, got: {rendered}"
    );
}

/// 🧭 A comment in a non-Latin script must not shift the positions after it.
/// Counting bytes instead of characters would put every later error a few
/// columns off, which is worse than no column at all — it points confidently at
/// the wrong place.
#[test]
fn a_multibyte_comment_does_not_shift_later_positions() {
    let source = "# 這是一行中文註解\na.example {\n\trespond \"one\"\n}\n}\n";
    let rendered = error_for(source, None);
    assert!(
        rendered.contains("5:1"),
        "expected line 5 column 1, got: {rendered}"
    );
}

/// 📄 A named source puts the file in the message.
#[test]
fn a_named_source_reports_its_name() {
    let rendered = error_for("}\n", Some(Path::new("/etc/pingclair/Pingclairfile")));
    assert!(
        rendered.contains("/etc/pingclair/Pingclairfile"),
        "expected the path in the message, got: {rendered}"
    );
}

/// 🧪 An unnamed source carries the position alone rather than inventing a file
/// for itself. Configurations posted to the admin API and built by tests have no
/// filename, and claiming one would send the operator looking for a file that
/// does not exist.
#[test]
fn an_unnamed_source_invents_no_filename() {
    let rendered = error_for("}\n", None);
    assert!(
        !rendered.contains("Pingclairfile"),
        "an unnamed source must not name a file: {rendered}"
    );
}

/// 📌 `compile` keeps its signature and behaves as the unnamed case, so nothing
/// that already called it has to change.
#[test]
fn the_unnamed_entry_point_still_works() {
    assert!(compile(":80\nrespond \"ok\"\n").is_ok());
    assert!(compile("}\n").is_err());
}
