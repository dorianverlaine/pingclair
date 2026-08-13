// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔁 Turns one `lb_retry_match` expression into a predicate the runtime knows.
//!
//! **This is not a CEL implementation and must not grow into one.** It reads
//! the shapes `lb_retry_match` actually uses — a boolean combination of
//! response tests and request matchers — and refuses everything else at load.
//!
//! The reason for refusing rather than storing is the whole point of the
//! module. Before this existed, an expression was kept as text, scanned for a
//! few substrings, and logged at startup as "accepted but not evaluated". An
//! operator writing `lb_retry_match` to stop retrying non-idempotent POSTs got
//! a server that retried them anyway, and the only warning was one line in a
//! log nobody reads twice. A retry rule that silently does nothing is worse
//! than one that fails to load, because the failure mode is duplicate writes.
//!
//! ```text
//! expression := or
//! or         := and ( "||" and )*
//! and        := primary ( "&&" primary )*
//! primary    := "(" expression ")" | test
//! test       := "{rp.status_code}" ( "==" int | ">=" int | "in" "[" int,* "]" )
//!             | "{rp.is_transport_error}"
//!             | "{rp.header." name "}" "==" string
//!             | func "(" args ")"
//! ```

use pingclair_core::config::RetryPredicate;

/// 🚫 Why one expression could not become a predicate.
///
/// Carries the offending text rather than an offset: an operator reads the
/// expression they wrote, not a column number into a string the Caddyfile
/// parser already unquoted for them.
#[derive(Debug)]
pub(super) struct RetryExprError {
    pub(super) message: String,
}

impl RetryExprError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// 🔁 Parses one expression into a predicate, or explains why it cannot.
pub(super) fn parse(expression: &str) -> Result<RetryPredicate, RetryExprError> {
    let text = expression.trim().trim_matches('`').trim();
    if text.is_empty() {
        return Err(RetryExprError::new("the expression is empty"));
    }
    let mut parser = Parser {
        input: text,
        position: 0,
        depth: 0,
    };
    let predicate = parser.parse_or()?;
    parser.skip_space();
    if parser.position < parser.input.len() {
        return Err(RetryExprError::new(format!(
            "unexpected `{}` after a complete condition",
            &parser.input[parser.position..]
        )));
    }
    Ok(predicate)
}

/// 🧱 Nesting ceiling while parsing, one below the config-level limit.
///
/// Refusing here as well as in `validate_config` is not redundancy for its own
/// sake: the parser recurses, so a limit applied only after parsing finishes
/// would be checked by a stack that had already grown.
const MAX_PARSE_DEPTH: usize = pingclair_core::config::MAX_RETRY_PREDICATE_DEPTH;

struct Parser<'a> {
    input: &'a str,
    position: usize,
    depth: usize,
}

impl<'a> Parser<'a> {
    fn skip_space(&mut self) {
        while self.input[self.position..].starts_with(|c: char| c.is_whitespace()) {
            self.position += 1;
        }
    }

    fn eat(&mut self, token: &str) -> bool {
        self.skip_space();
        if self.input[self.position..].starts_with(token) {
            self.position += token.len();
            true
        } else {
            false
        }
    }

    fn parse_or(&mut self) -> Result<RetryPredicate, RetryExprError> {
        let mut branches = vec![self.parse_and()?];
        while self.eat("||") {
            branches.push(self.parse_and()?);
        }
        Ok(if branches.len() == 1 {
            branches.pop().expect("just checked the length")
        } else {
            RetryPredicate::Any { of: branches }
        })
    }

    fn parse_and(&mut self) -> Result<RetryPredicate, RetryExprError> {
        let mut branches = vec![self.parse_primary()?];
        while self.eat("&&") {
            branches.push(self.parse_primary()?);
        }
        Ok(if branches.len() == 1 {
            branches.pop().expect("just checked the length")
        } else {
            RetryPredicate::All { of: branches }
        })
    }

    fn parse_primary(&mut self) -> Result<RetryPredicate, RetryExprError> {
        self.depth += 1;
        if self.depth > MAX_PARSE_DEPTH {
            return Err(RetryExprError::new(format!(
                "nested more than {MAX_PARSE_DEPTH} levels deep"
            )));
        }
        let result = self.parse_primary_inner();
        self.depth -= 1;
        result
    }

    fn parse_primary_inner(&mut self) -> Result<RetryPredicate, RetryExprError> {
        if self.eat("(") {
            let inner = self.parse_or()?;
            if !self.eat(")") {
                return Err(RetryExprError::new("a `(` is never closed"));
            }
            return Ok(inner);
        }
        self.skip_space();
        if self.input[self.position..].starts_with('{') {
            return self.parse_placeholder_test();
        }
        self.parse_function()
    }

    /// 🧭 `{rp.…}` and its long spelling `{http.reverse_proxy.…}`.
    fn parse_placeholder_test(&mut self) -> Result<RetryPredicate, RetryExprError> {
        let rest = &self.input[self.position..];
        let Some(end) = rest.find('}') else {
            return Err(RetryExprError::new("a `{` is never closed"));
        };
        let name = &rest[1..end];
        self.position += end + 1;

        // 🧭 Both spellings mean the same thing; the short one is what an
        // operator writes and the long one is what an exported JSON config
        // contains, so a round trip through either has to keep working.
        let field = name
            .strip_prefix("rp.")
            .or_else(|| name.strip_prefix("http.reverse_proxy."))
            .ok_or_else(|| {
                RetryExprError::new(format!(
                    "`{{{name}}}` is not a retry placeholder; only `{{rp.…}}` is available here"
                ))
            })?;

        if field == "is_transport_error" {
            return Ok(RetryPredicate::TransportError);
        }
        if let Some(header) = field.strip_prefix("header.") {
            if !self.eat("==") {
                return Err(RetryExprError::new(format!(
                    "`{{rp.header.{header}}}` needs `== \"value\"`"
                )));
            }
            let value = self.parse_string()?;
            return Ok(RetryPredicate::ResponseHeader {
                name: header.to_string(),
                value,
            });
        }
        if field != "status_code" {
            return Err(RetryExprError::new(format!(
                "`{{rp.{field}}}` is not a retry placeholder; expected `status_code`, \
                 `is_transport_error` or `header.<name>`"
            )));
        }

        if self.eat("==") {
            return Ok(RetryPredicate::Status {
                any_of: vec![self.parse_status()?],
            });
        }
        if self.eat(">=") {
            return Ok(RetryPredicate::StatusAtLeast {
                code: self.parse_status()?,
            });
        }
        if self.eat("in") {
            if !self.eat("[") {
                return Err(RetryExprError::new(
                    "`in` needs a list, as in `in [502, 503]`",
                ));
            }
            let mut any_of = Vec::new();
            loop {
                any_of.push(self.parse_status()?);
                if self.eat(",") {
                    continue;
                }
                if self.eat("]") {
                    break;
                }
                return Err(RetryExprError::new("a status list is never closed"));
            }
            return Ok(RetryPredicate::Status { any_of });
        }
        Err(RetryExprError::new(
            "`{rp.status_code}` needs `==`, `>=` or `in [ … ]`",
        ))
    }

    fn parse_status(&mut self) -> Result<u16, RetryExprError> {
        self.skip_space();
        let rest = &self.input[self.position..];
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        if digits.is_empty() {
            return Err(RetryExprError::new("expected a status code"));
        }
        self.position += digits.len();
        let code: u16 = digits
            .parse()
            .map_err(|_| RetryExprError::new(format!("`{digits}` is not a status code")))?;
        if !(100..=599).contains(&code) {
            return Err(RetryExprError::new(format!(
                "`{code}` is not a status code between 100 and 599"
            )));
        }
        Ok(code)
    }

    /// 🔤 A single- or double-quoted literal. No escapes: the shapes this
    /// grammar accepts are header names, methods, paths and globs, and an
    /// escape in one of those is far more likely a mistake than an intention.
    fn parse_string(&mut self) -> Result<String, RetryExprError> {
        self.skip_space();
        let rest = &self.input[self.position..];
        let quote = rest
            .chars()
            .next()
            .filter(|c| *c == '\'' || *c == '"')
            .ok_or_else(|| RetryExprError::new("expected a quoted value"))?;
        let body = &rest[1..];
        let end = body
            .find(quote)
            .ok_or_else(|| RetryExprError::new("a quoted value is never closed"))?;
        self.position += 1 + end + 1;
        Ok(body[..end].to_string())
    }

    fn parse_function(&mut self) -> Result<RetryPredicate, RetryExprError> {
        self.skip_space();
        let rest = &self.input[self.position..];
        let name_length = rest
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .unwrap_or(rest.len());
        if name_length == 0 {
            return Err(RetryExprError::new(format!(
                "expected a condition, found `{}`",
                rest.chars().take(24).collect::<String>()
            )));
        }
        let name = rest[..name_length].to_string();
        self.position += name_length;
        if !self.eat("(") {
            return Err(RetryExprError::new(format!("`{name}` needs its arguments")));
        }

        let predicate = match name.as_str() {
            "method" => RetryPredicate::Method {
                any_of: self
                    .parse_string_list()?
                    .into_iter()
                    .map(|value| value.to_ascii_uppercase())
                    .collect(),
            },
            "path" => RetryPredicate::Path {
                any_of: self.parse_string_list()?,
            },
            "host" => RetryPredicate::Host {
                any_of: self.parse_string_list()?,
            },
            "path_regexp" => RetryPredicate::PathRegexp {
                pattern: self.parse_string()?,
            },
            "protocol" => RetryPredicate::Protocol {
                name: self.parse_string()?.to_ascii_lowercase(),
            },
            "header_regexp" => {
                let header = self.parse_string()?;
                if !self.eat(",") {
                    return Err(RetryExprError::new(
                        "`header_regexp` needs a header name and a pattern",
                    ));
                }
                RetryPredicate::HeaderRegexp {
                    name: header,
                    pattern: self.parse_string()?,
                }
            }
            "header" => {
                let (key, any_of) = self.parse_map_entry("header")?;
                RetryPredicate::RequestHeader { name: key, any_of }
            }
            "query" => {
                let (key, any_of) = self.parse_map_entry("query")?;
                RetryPredicate::Query { key, any_of }
            }
            other => {
                return Err(RetryExprError::new(format!(
                    "`{other}()` is not a retry condition; available are `method`, `path`, \
                     `host`, `protocol`, `path_regexp`, `header`, `header_regexp` and `query`"
                )));
            }
        };

        if !self.eat(")") {
            return Err(RetryExprError::new(format!("`{name}(` is never closed")));
        }
        Ok(predicate)
    }

    /// 🔤 `'a'` or `'a', 'b'` — a function's positional values.
    fn parse_string_list(&mut self) -> Result<Vec<String>, RetryExprError> {
        let mut values = vec![self.parse_string()?];
        while self.eat(",") {
            values.push(self.parse_string()?);
        }
        Ok(values)
    }

    /// 🗺️ `{'Name': 'value'}` — the single-entry map form `header()` and
    /// `query()` take.
    ///
    /// ⚠️ Only one entry. Upstream's map accepts several, but several entries
    /// mean "all of them must match" and reading that wrong is a silent
    /// widening of when a retry happens. Refusing beats guessing; a second
    /// condition can be written with `&&`, which is unambiguous.
    fn parse_map_entry(&mut self, function: &str) -> Result<(String, Vec<String>), RetryExprError> {
        if !self.eat("{") {
            return Err(RetryExprError::new(format!(
                "`{function}` takes a map, as in `{function}({{'Name': 'value'}})`"
            )));
        }
        let key = self.parse_string()?;
        if !self.eat(":") {
            return Err(RetryExprError::new(format!(
                "`{function}` needs a value for `{key}`"
            )));
        }
        // 🧭 One value, then the map must close. Reading a comma-separated list
        // here would be ambiguous with a second field — `{'a': 'b', 'c': 'd'}`
        // and `{'a': 'b', 'c'}` differ by one character and mean opposite
        // things — so the comma is refused instead of guessed at.
        let value = self.parse_string()?;
        if self.eat(",") {
            return Err(RetryExprError::new(format!(
                "`{function}` accepts one field here; write the second condition with `&&` so \
                 it is clear both must match"
            )));
        }
        if !self.eat("}") {
            return Err(RetryExprError::new(format!(
                "`{function}(` is never closed"
            )));
        }
        Ok((key, vec![value]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(expression: &str) -> RetryPredicate {
        parse(expression).unwrap_or_else(|e| panic!("`{expression}` should parse: {}", e.message))
    }

    fn refused(expression: &str) -> String {
        parse(expression)
            .err()
            .unwrap_or_else(|| panic!("`{expression}` should be refused"))
            .message
    }

    /// 🔁 Every expression in upstream's own `retry_match` fixtures.
    ///
    /// Written against the fixture rather than invented, because the point of
    /// the module is coverage of shapes real configurations use — and the
    /// shapes nobody thinks to test are exactly the ones the old substring
    /// matcher got wrong.
    #[test]
    fn every_expression_in_the_upstream_fixtures_parses() {
        for expression in [
            "{rp.status_code} in [502, 503, 504]",
            "{rp.header.X-Retry} == \"true\"",
            "method('POST') && {rp.status_code} >= 500",
            "path('/api*') && {rp.status_code} in [502, 503]",
            "host('example.com') && {rp.status_code} == 503",
            "query({'retry': 'true'}) && {rp.status_code} >= 500",
            "header({'X-Idempotency-Key': '*'}) && {rp.status_code} in [502, 503]",
            "protocol('https') && {rp.status_code} == 502",
            "path_regexp('^/api/v[0-9]+/') && {rp.status_code} >= 500",
            "header_regexp('Content-Type', '^application/json') && {rp.status_code} == 502",
            "{rp.is_transport_error} || {rp.status_code} in [502, 503]",
            "{rp.is_transport_error} && method('POST')",
            "{rp.status_code} == 504",
            "{rp.is_transport_error} && method('PUT')",
            "{http.reverse_proxy.status_code} == 502",
        ] {
            parsed(expression);
        }
    }

    /// 🧭 `&&` binds tighter than `||`, so one misread of precedence does not
    /// turn "retry these two together" into "retry either".
    #[test]
    fn and_binds_tighter_than_or() {
        let predicate =
            parsed("{rp.is_transport_error} || method('POST') && {rp.status_code} == 503");
        let RetryPredicate::Any { of } = &predicate else {
            panic!("the top level must be the `||`: {predicate:?}");
        };
        assert_eq!(of.len(), 2);
        assert!(matches!(of[0], RetryPredicate::TransportError));
        assert!(
            matches!(&of[1], RetryPredicate::All { of } if of.len() == 2),
            "the `&&` must be one branch of the `||`, not a sibling"
        );

        // 🧭 And parentheses override it, which is the only way to say the
        // other thing.
        let predicate =
            parsed("({rp.is_transport_error} || method('POST')) && {rp.status_code} == 503");
        assert!(matches!(predicate, RetryPredicate::All { .. }));
    }

    /// 🚫 An expression nobody taught this parser is refused at load, with a
    /// message naming what is available.
    ///
    /// This is the behaviour the whole module exists for: the old code kept
    /// such an expression as text and retried anyway.
    #[test]
    fn an_unknown_condition_is_refused_by_name() {
        assert!(refused("remote_ip('10.0.0.0/8')").contains("remote_ip"));
        assert!(refused("{rp.latency} > 5").contains("latency"));
        assert!(refused("{rp.status_code}").contains("`==`"));
        assert!(refused("method('POST') &&").contains("expected a condition"));
        assert!(refused("(method('POST')").contains("never closed"));
        assert!(refused("{rp.status_code} == 42").contains("between 100 and 599"));
        assert!(
            refused("header({'A': 'b', 'C': 'd'})").contains("&&"),
            "a multi-field map must point at the unambiguous spelling"
        );
    }

    /// 🧱 The depth limit is enforced while parsing, not after — the parser
    /// recurses, so a check that ran afterwards would run on a stack that had
    /// already grown.
    #[test]
    fn a_deeply_nested_expression_is_refused_rather_than_recursed() {
        let deep = format!(
            "{}{}{}",
            "(".repeat(500),
            "{rp.is_transport_error}",
            ")".repeat(500)
        );
        assert!(refused(&deep).contains("deep"));
    }
}
