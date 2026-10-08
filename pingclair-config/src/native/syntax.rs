// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧩 Bounded syntax for labeled declarations and literal values.

#[derive(Clone, Copy, Debug)]
pub(super) struct Position {
    pub line: usize,
    pub column: usize,
}
impl Position {
    pub fn error(self, message: impl Into<String>) -> super::Error {
        super::Error {
            line: self.line,
            column: self.column,
            message: message.into(),
        }
    }
}

#[derive(Clone)]
pub(super) struct Call {
    pub name: String,
    pub args: Vec<(Option<String>, Value)>,
    pub body: Option<Vec<Call>>,
    pub modifiers: Vec<Call>,
    pub at: Position,
}

/// 🧩 A top-level declaration is either a component or an immutable binding.
pub(super) enum Declaration {
    Component(Call),
    Binding {
        name: String,
        value: Value,
        at: Position,
    },
}

#[derive(Clone)]
pub(super) enum Value {
    String(String),
    Number(u64),
    Bool(bool),
    Array(Vec<Value>),
    Typed(Call),
    Component(Call),
    Reference { name: String, at: Position },
}
#[derive(PartialEq)]
enum Token {
    Word(String),
    String(String),
    Number(u64),
    Mark(char),
    End,
}
struct Item {
    token: Token,
    at: Position,
}

/// 🛡️ Limits apply before allocating tokens or descending through recursive values.
pub(super) fn parse(source: &str) -> Result<Vec<Declaration>, super::Error> {
    let start = Position { line: 1, column: 1 };
    if source.len() > 1024 * 1024 {
        return Err(start.error("configuration exceeds 1 MiB"));
    }
    let mut items = Vec::new();
    let mut chars = source.char_indices().peekable();
    let mut at = start;
    while let Some((offset, ch)) = chars.next() {
        let here = at;
        at.column += 1;
        if ch == '\n' {
            at.line += 1;
            at.column = 1;
            continue;
        }
        if ch.is_whitespace() {
            continue;
        }
        if ch == '/' && chars.peek().is_some_and(|(_, c)| *c == '/') {
            for (_, c) in chars.by_ref() {
                if c == '\n' {
                    at.line += 1;
                    at.column = 1;
                    break;
                }
                at.column += 1;
            }
            continue;
        }
        let token =
            if ch == '"' {
                let mut escaped = false;
                let mut end = None;
                for (index, c) in chars.by_ref() {
                    at.column += 1;
                    if c == '\n' || c == '\r' {
                        return Err(here.error("string must stay on one line"));
                    }
                    if c == '"' && !escaped {
                        end = Some(index + 1);
                        break;
                    }
                    escaped = c == '\\' && !escaped;
                }
                let end = end.ok_or_else(|| here.error("unterminated string"))?;
                Token::String(serde_json::from_str(&source[offset..end]).map_err(|_| {
                    here.error("invalid string escape; interpolation is not supported")
                })?)
            } else if ch.is_ascii_alphabetic() || ch == '_' {
                let mut word = ch.to_string();
                while chars
                    .peek()
                    .is_some_and(|(_, c)| c.is_ascii_alphanumeric() || *c == '_')
                {
                    word.push(chars.next().unwrap().1);
                    at.column += 1;
                }
                Token::Word(word)
            } else if ch.is_ascii_digit() {
                let mut word = ch.to_string();
                while chars
                    .peek()
                    .is_some_and(|(_, c)| c.is_ascii_digit() || *c == '_')
                {
                    word.push(chars.next().unwrap().1);
                    at.column += 1;
                }
                if word.ends_with('_') || word.contains("__") {
                    return Err(here.error("invalid integer separator"));
                }
                Token::Number(
                    word.replace('_', "")
                        .parse()
                        .map_err(|_| here.error("integer exceeds supported range"))?,
                )
            } else if "(){}[],:.=".contains(ch) {
                Token::Mark(ch)
            } else {
                return Err(here.error("unexpected character"));
            };
        if items.len() == 65_536 {
            return Err(here.error("configuration exceeds token limit"));
        }
        items.push(Item { token, at: here });
    }
    items.push(Item {
        token: Token::End,
        at,
    });
    let mut parser = Parser {
        items: items.into_iter().peekable(),
    };
    let mut declarations = Vec::new();
    while parser.peek() != &Token::End {
        if parser.peek_word() == Some("let") {
            declarations.push(parser.binding(0)?);
        } else {
            declarations.push(Declaration::Component(parser.call(0, true)?));
        }
    }
    Ok(declarations)
}
struct Parser {
    items: std::iter::Peekable<std::vec::IntoIter<Item>>,
}
impl Parser {
    fn peek(&mut self) -> &Token {
        &self.items.peek().unwrap().token
    }
    fn peek_word(&mut self) -> Option<&str> {
        match self.peek() {
            Token::Word(word) => Some(word),
            _ => None,
        }
    }
    fn error(&mut self, message: &str) -> super::Error {
        self.items.peek().unwrap().at.error(message)
    }
    fn take(&mut self, mark: char) -> bool {
        if self.peek() == &Token::Mark(mark) {
            self.items.next();
            true
        } else {
            false
        }
    }
    fn expect(&mut self, mark: char) -> Result<(), super::Error> {
        if self.take(mark) {
            Ok(())
        } else {
            Err(self.error(&format!("expected '{mark}'")))
        }
    }
    /// 🧩 Parses `let <name> = <value|component>`; bindings live at the top level only.
    fn binding(&mut self, depth: usize) -> Result<Declaration, super::Error> {
        if depth >= 16 {
            return Err(self.error("configuration nesting exceeds 16 levels"));
        }
        let at = self.items.peek().unwrap().at;
        self.items.next();
        let identifier = self.items.next().unwrap();
        let Token::Word(name) = identifier.token else {
            return Err(identifier.at.error("expected binding name"));
        };
        self.expect('=')?;
        let value = if matches!(self.peek(), Token::Word(_)) {
            let item = self.items.next().unwrap();
            let Token::Word(word) = item.token else {
                unreachable!()
            };
            if word == "true" || word == "false" {
                Value::Bool(word == "true")
            } else if self.peek() == &Token::Mark('(') || self.peek() == &Token::Mark('{') {
                Value::Component(self.call_with_open(word, item.at, depth + 1, true)?)
            } else {
                Value::Reference {
                    name: word,
                    at: item.at,
                }
            }
        } else {
            self.value(depth + 1)?
        };
        Ok(Declaration::Binding { name, value, at })
    }
    fn call(&mut self, depth: usize, block: bool) -> Result<Call, super::Error> {
        let item = self.items.next().unwrap();
        let Token::Word(name) = item.token else {
            return Err(item.at.error("expected declaration name"));
        };
        if name == "let" {
            return Err(item.at.error("let bindings must be top-level declarations"));
        }
        self.call_with_open(name, item.at, depth, block)
    }
    fn call_with_open(
        &mut self,
        name: String,
        at: Position,
        depth: usize,
        block: bool,
    ) -> Result<Call, super::Error> {
        if depth >= 16 {
            return Err(self.error("configuration nesting exceeds 16 levels"));
        }
        let mut args = Vec::new();
        if self.take('(') {
            while !self.take(')') {
                if self.peek() == &Token::End {
                    return Err(self.error("unterminated argument list"));
                }
                let label = if let Token::Word(word) = self.peek() {
                    if word != "true" && word != "false" {
                        let Item {
                            token: Token::Word(label),
                            ..
                        } = self.items.next().unwrap()
                        else {
                            unreachable!()
                        };
                        self.expect(':')?;
                        Some(label)
                    } else {
                        None
                    }
                } else {
                    None
                };
                if label.is_some() && args.iter().any(|(old, _)| old == &label) {
                    return Err(at.error("duplicate argument label"));
                }
                args.push((label, self.value(depth + 1)?));
                if self.take(')') {
                    break;
                }
                self.expect(',')?;
            }
        }
        let body = if block && self.take('{') {
            let mut children = Vec::new();
            while !self.take('}') {
                if self.peek() == &Token::End {
                    return Err(self.error("unterminated configuration block"));
                }
                children.push(self.call(depth + 1, true)?);
            }
            Some(children)
        } else {
            None
        };
        let mut modifiers = Vec::new();
        if block {
            while self.take('.') {
                modifiers.push(self.call(depth + 1, false)?);
            }
        }
        Ok(Call {
            name,
            args,
            body,
            modifiers,
            at,
        })
    }
    fn value(&mut self, depth: usize) -> Result<Value, super::Error> {
        if depth >= 16 {
            return Err(self.error("configuration nesting exceeds 16 levels"));
        }
        if self.take('.') {
            return Ok(Value::Typed(self.call(depth + 1, false)?));
        }
        if self.take('[') {
            let mut values = Vec::new();
            while !self.take(']') {
                values.push(self.value(depth + 1)?);
                if self.take(']') {
                    break;
                }
                self.expect(',')?;
            }
            return Ok(Value::Array(values));
        }
        let item = self.items.next().unwrap();
        match item.token {
            Token::String(value) => Ok(Value::String(value)),
            Token::Number(value) => Ok(Value::Number(value)),
            Token::Word(value) if value == "true" || value == "false" => {
                Ok(Value::Bool(value == "true"))
            }
            Token::Word(name) => Ok(Value::Reference { name, at: item.at }),
            _ => Err(item
                .at
                .error("expected a literal, array, typed value, or binding")),
        }
    }
}
