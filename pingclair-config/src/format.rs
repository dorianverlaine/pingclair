// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🖋️ Canonical formatting for the native language.
//!
//! The printer rebuilds the file from the parsed declarations: four-space
//! indentation, one declaration per line, a single blank line at most between
//! siblings, and trailing commas once an argument list or array wraps (more
//! than three entries, one per line). A block with one child that fits on one
//! line stays inline (`Fallback { Proxy(to: "…") }`), which is the style the
//! examples use.
//!
//! Comments are preserved. A comment that trailed code stays on the line it
//! ended; every other comment moves to its own line at the current indent, and
//! its order relative to the declarations is kept.
//!
//! Formatting requires the input to parse; a file that does not is refused
//! with the parser's own diagnostic rather than half-rewritten.

use crate::frontend::Error;
use crate::syntax::{Attribute, Call, Declaration, Position, Value};

const INDENT: &str = "    ";
const WRAP_AFTER: usize = 3;

/// Formats a native configuration; the output is idempotent.
pub fn format(source: &str) -> Result<String, Error> {
    let declarations = crate::syntax::parse(source)?;
    let mut printer = Printer {
        out: String::new(),
        indent: 0,
        comments: comments(source),
        next_comment: 0,
    };
    let mut previous_end = None;
    for declaration in &declarations {
        let start = declaration_start(declaration);
        if let Some(previous) = previous_end
            && start > previous + 1
        {
            printer.blank_line();
        }
        printer.statement(declaration);
        previous_end = Some(declaration_end(declaration));
    }
    printer.flush_comments(usize::MAX);
    Ok(printer.out)
}

fn declaration_start(declaration: &Declaration) -> usize {
    match declaration {
        Declaration::Binding { at, .. } => at.line,
        Declaration::Component { call, .. } => call.at.line,
    }
}

fn declaration_end(declaration: &Declaration) -> usize {
    match declaration {
        Declaration::Binding { end, .. } => end.line,
        Declaration::Component { call, .. } => call.end.line,
    }
}

struct Comment {
    line: usize,
    text: String,
    own_line: bool,
}

/// Collects `//` comments with their line and whether code preceded them.
fn comments(source: &str) -> Vec<Comment> {
    let mut comments = Vec::new();
    let mut line = 1usize;
    let mut own_line = true;
    let mut chars = source.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\n' => {
                line += 1;
                own_line = true;
            }
            '"' => {
                own_line = false;
                let mut escaped = false;
                for next in chars.by_ref() {
                    if next == '\n' {
                        line += 1;
                    }
                    if next == '"' && !escaped {
                        break;
                    }
                    escaped = next == '\\' && !escaped;
                }
            }
            '/' if chars.peek() == Some(&'/') => {
                chars.next();
                let start_line = line;
                let started_own_line = own_line;
                let mut text = String::from("//");
                for next in chars.by_ref() {
                    if next == '\n' {
                        line += 1;
                        own_line = true;
                        break;
                    }
                    text.push(next);
                }
                comments.push(Comment {
                    line: start_line,
                    text: text.trim_end().to_string(),
                    own_line: started_own_line,
                });
            }
            other if other.is_whitespace() => {}
            _ => own_line = false,
        }
    }
    comments
}

struct Printer {
    out: String,
    indent: usize,
    comments: Vec<Comment>,
    next_comment: usize,
}

impl Printer {
    fn text(&mut self, text: &str) {
        self.out.push_str(text);
    }

    fn newline(&mut self) {
        self.out.push('\n');
    }

    fn start_line(&mut self) {
        for _ in 0..self.indent {
            self.out.push_str(INDENT);
        }
    }

    fn blank_line(&mut self) {
        if !self.out.is_empty() && !self.out.ends_with("\n\n") {
            self.out.push('\n');
        }
    }

    fn flush_comments(&mut self, before_line: usize) {
        while self.next_comment < self.comments.len()
            && self.comments[self.next_comment].line < before_line
        {
            let text = self.comments[self.next_comment].text.clone();
            self.start_line();
            self.text(&text);
            self.newline();
            self.next_comment += 1;
        }
    }

    fn attach_trailing(&mut self, end_line: usize) {
        if let Some(comment) = self.comments.get(self.next_comment)
            && !comment.own_line
            && comment.line == end_line
        {
            let text = comment.text.clone();
            self.text(" ");
            self.text(&text);
            self.next_comment += 1;
        }
    }

    fn statement(&mut self, declaration: &Declaration) {
        match declaration {
            Declaration::Binding {
                attributes,
                name,
                value,
                at,
                end,
            } => {
                self.flush_comments(at.line);
                self.attributes(attributes);
                self.start_line();
                self.text("let ");
                self.text(name);
                self.text(" = ");
                self.value(value);
                self.attach_trailing(end.line);
                self.newline();
            }
            Declaration::Component { attributes, call } => {
                self.flush_comments(call.at.line);
                self.attributes(attributes);
                self.start_line();
                self.call(call);
                self.attach_trailing(call.end.line);
                self.newline();
            }
        }
    }

    fn attributes(&mut self, attributes: &[Attribute]) {
        for attribute in attributes {
            self.start_line();
            self.text("@");
            self.text(&attribute.name);
            if !attribute.args.is_empty() {
                self.args(&attribute.args);
            }
            self.newline();
        }
    }

    fn call(&mut self, call: &Call) {
        self.text(&call.name);
        if call.parens {
            self.args(&call.args);
        }
        if let Some(children) = &call.body {
            self.block(children, call.block_end);
        }
        for modifier in &call.modifiers {
            self.newline();
            self.flush_comments(modifier.at.line);
            self.start_line();
            self.text(".");
            self.text(&modifier.name);
            if modifier.parens {
                self.args(&modifier.args);
            }
        }
    }

    fn block(&mut self, children: &[Call], block_end: Option<Position>) {
        if children.is_empty() {
            self.text(" {}");
            return;
        }
        if self.try_inline_block(children) {
            return;
        }
        self.text(" {");
        self.newline();
        self.indent += 1;
        let mut previous_end = None;
        for child in children {
            if let Some(previous) = previous_end
                && child.at.line > previous + 1
            {
                self.blank_line();
            }
            self.flush_comments(child.at.line);
            self.start_line();
            self.call(child);
            self.attach_trailing(child.end.line);
            self.newline();
            previous_end = Some(child.end.line);
        }
        if let Some(end) = block_end {
            self.flush_comments(end.line);
        }
        self.indent -= 1;
        self.start_line();
        self.text("}");
    }

    /// 🖋️ Keeps a one-child block on one line when that child renders inline.
    fn try_inline_block(&mut self, children: &[Call]) -> bool {
        if children.len() != 1 {
            return false;
        }
        let child = &children[0];
        if child.body.is_some() || !child.modifiers.is_empty() {
            return false;
        }
        let checkpoint = self.out.len();
        self.text(" { ");
        self.call(child);
        if self.out[checkpoint..].contains('\n') {
            self.out.truncate(checkpoint);
            return false;
        }
        self.text(" }");
        true
    }

    fn args(&mut self, args: &[(Option<String>, Value)]) {
        self.text("(");
        if args.is_empty() {
            self.text(")");
            return;
        }
        if args.len() <= WRAP_AFTER {
            for (index, (label, value)) in args.iter().enumerate() {
                if index > 0 {
                    self.text(", ");
                }
                self.label(label);
                self.value(value);
            }
            self.text(")");
            return;
        }
        self.newline();
        self.indent += 1;
        for (label, value) in args {
            self.start_line();
            self.label(label);
            self.value(value);
            self.text(",");
            self.newline();
        }
        self.indent -= 1;
        self.start_line();
        self.text(")");
    }

    fn label(&mut self, label: &Option<String>) {
        if let Some(label) = label {
            self.text(label);
            self.text(": ");
        }
    }

    fn value(&mut self, value: &Value) {
        match value {
            Value::String(text) => {
                let rendered =
                    serde_json::to_string(text).expect("a string always serializes as JSON");
                self.text(&rendered);
            }
            Value::Number(number) => self.text(&number.to_string()),
            Value::Decimal(number) => self.text(number),
            Value::Bool(flag) => self.text(if *flag { "true" } else { "false" }),
            Value::Reference { name, .. } => self.text(name),
            // 🔐 Synthetic, so a formatter never meets one; printing the
            // value it carries keeps the two spellings in step if it ever does.
            Value::Secret { value, .. } => self.value(value),
            Value::Typed(call) => {
                self.text(".");
                self.call(call);
            }
            Value::Component(call) => self.call(call),
            Value::Array(items) => {
                self.text("[");
                if items.is_empty() {
                    self.text("]");
                    return;
                }
                if items.len() <= WRAP_AFTER {
                    for (index, item) in items.iter().enumerate() {
                        if index > 0 {
                            self.text(", ");
                        }
                        self.value(item);
                    }
                    self.text("]");
                    return;
                }
                self.newline();
                self.indent += 1;
                for item in items {
                    self.start_line();
                    self.value(item);
                    self.text(",");
                    self.newline();
                }
                self.indent -= 1;
                self.start_line();
                self.text("]");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_layout_and_idempotence() {
        let source = "TCPListener(on: \"127.0.0.1:9443\") {\n\
                      Route(when: .tls(sni: [\"a.test\"])) { Proxy(to: \"127.0.0.1:10001\") }\n\
                      Fallback { Proxy(to: \"127.0.0.1:10002\") }\n\
                      }.limits(connections: 128)\n";
        let expected = "TCPListener(on: \"127.0.0.1:9443\") {\n\
                        \x20   Route(when: .tls(sni: [\"a.test\"])) { Proxy(to: \"127.0.0.1:10001\") }\n\
                        \x20   Fallback { Proxy(to: \"127.0.0.1:10002\") }\n\
                        }\n\
                        .limits(connections: 128)\n";
        let formatted = format(source).unwrap();
        assert_eq!(formatted, expected);
        assert_eq!(format(&formatted).unwrap(), formatted);
    }

    /// 🧮 The decimal literal is data, not arithmetic: it round-trips exactly
    /// as written, and every integer reader still refuses it.
    #[test]
    fn a_decimal_literal_round_trips_and_stays_out_of_integer_readers() {
        let formatted = format("let ratio = 0.10\n").expect("the binding formats");
        assert!(formatted.contains("0.10"), "{formatted}");
        assert_eq!(format(&formatted).unwrap(), formatted);

        let error = crate::compile("Shutdown(grace: .seconds(1.5))")
            .expect_err("a decimal is not a duration");
        assert!(error.to_string().contains("unsigned integer"), "{error}");
    }

    #[test]
    fn comments_and_blank_lines_survive() {
        let source = "// top\n\n@Matcher\nlet secure = .tls(sni: [\"a.test\"]) // trailing\n\nTCPListener(on: \"127.0.0.1:9443\") {\n  Route(when: secure) { Proxy(to: \"127.0.0.1:10001\") }\n}\n";
        let formatted = format(source).unwrap();
        assert!(formatted.starts_with("// top\n"), "{formatted}");
        assert!(
            formatted.contains("let secure = .tls(sni: [\"a.test\"]) // trailing"),
            "{formatted}"
        );
        assert!(formatted.contains("\n\nTCPListener("), "{formatted}");
        assert_eq!(format(&formatted).unwrap(), formatted);
    }

    #[test]
    fn long_arrays_wrap_with_trailing_commas() {
        let source = "TCPListener(on: \"127.0.0.1:9443\") {\n    Route(when: .tls(sni: [\"a.test\", \"b.test\", \"c.test\", \"d.test\"])) { Proxy(to: \"127.0.0.1:10001\") }\n}\n";
        let formatted = format(source).unwrap();
        assert!(formatted.contains("\n        \"a.test\",\n"), "{formatted}");
        assert!(formatted.contains("\n        \"d.test\",\n"), "{formatted}");
        assert!(formatted.contains("\n    ]))"), "{formatted}");
        assert_eq!(format(&formatted).unwrap(), formatted);
    }

    #[test]
    fn comment_like_text_inside_strings_is_not_a_comment() {
        let source = "TCPListener(on: \"127.0.0.1:9443\") {\n    Fallback { Proxy(to: \"http://example.test:80\") }\n}\n";
        let formatted = format(source).unwrap();
        assert!(
            formatted.contains("\"http://example.test:80\""),
            "{formatted}"
        );
        assert_eq!(formatted.matches("//").count(), 1, "{formatted}");
    }

    #[test]
    fn argument_lists_wrap_past_three_entries() {
        let position = Position { line: 1, column: 1 };
        let call = Call {
            name: "Example".to_string(),
            args: (0..4)
                .map(|index| (Some(format!("arg{index}")), Value::Number(index)))
                .collect(),
            body: None,
            modifiers: Vec::new(),
            parens: true,
            block_end: None,
            end: position,
            at: position,
        };
        let declaration = Declaration::Component {
            attributes: Vec::new(),
            call,
        };
        let mut printer = Printer {
            out: String::new(),
            indent: 0,
            comments: Vec::new(),
            next_comment: 0,
        };
        printer.statement(&declaration);
        assert!(printer.out.contains("(\n    arg0: 0,\n"), "{}", printer.out);
        assert!(printer.out.ends_with(")\n"), "{}", printer.out);
    }

    #[test]
    fn invalid_sources_are_refused() {
        assert!(format("TCPListener(on: [").is_err());
        assert!(format("let = 1").is_err());
    }
}
