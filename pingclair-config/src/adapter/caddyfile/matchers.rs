// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

use super::AdapterError;
use crate::parser::ast::*;
use crate::parser::caddy_ast::{Block, Directive, TokenRun};

// MARK: - Matchers

pub(super) fn parse_matcher_and_block(
    d: &Directive,
) -> Result<(Option<Matcher>, Option<&Block>), AdapterError> {
    Ok((matcher_token(d), d.block.as_ref()))
}

/// 🎯 Reads the optional matcher token in a directive's first argument.
///
/// There is one rule, and it applies to every directive:
///
/// | first argument | meaning |
/// | --- | --- |
/// | `*` | every request, which is the same as no matcher |
/// | starts with `/` | a path matcher |
/// | starts with `@` | a matcher defined elsewhere by that name |
/// | anything else | not a matcher; it is this directive's own data |
///
/// **No wildcard is required and no argument count is involved.** Both of those
/// were invented here, and both were wrong: until 2026-08-05 a leading slash
/// only counted as a matcher when it also carried a `*`, and only for the four
/// directives someone had remembered to list. The other four measured that day
/// each failed differently — `respond /first "x"` answered every request with
/// the text `/first`, `header /exact X-Test y` compiled a header named `/exact`,
/// and `encode` and `basic_auth` refused to load. One rule, so a directive
/// nobody thought about behaves like the rest.
///
/// 🧭 The single exception is named in [`takes_path_as_data`], with its reason.
pub(super) fn matcher_token(d: &Directive) -> Option<Matcher> {
    let arg = d.args.first()?;
    if first_argument_is_data(d) {
        return None;
    }
    match arg.chars().next()? {
        // 🌐 `*` exists only to say "this argument is not a matcher" for
        // directives whose data could otherwise be mistaken for one.
        '*' if arg.len() == 1 => None,
        '@' => Some(Matcher::Named(arg.clone())),
        '/' => Some(Matcher::Path(PathMatcher {
            patterns: vec![arg.clone()],
        })),
        _ => None,
    }
}

/// 🧭 Whether a directive's first argument is its own data despite looking like
/// a matcher.
///
/// A handful of directives take a path as their first *argument*, so for those
/// the argument count decides — which is how the format itself disambiguates,
/// inside each directive rather than in one global table.
///
/// 📌 What this is **not**: the old allowlist inverted for convenience. That one
/// had to name every directive wanting *normal* behaviour, so forgetting one
/// produced a silent misparse — `respond /first "x"` answering every request
/// with the text `/first`. This names the few that want *abnormal* behaviour, so
/// forgetting an entry produces ordinary matcher behaviour: the safe direction.
pub(super) fn first_argument_is_data(d: &Directive) -> bool {
    let Some(first) = d.args.first() else {
        return false;
    };
    match d.name.as_str() {
        // 🎯 `redir <target>` and `redir <target> <status>` put the target
        // first; `redir <matcher> <target>` puts a matcher there. The second
        // argument tells them apart: a redirect target is a path or carries a
        // scheme, and is never a status code.
        "redir" | "redirect" => {
            let target_follows = d.args.get(1).is_some_and(|next| {
                (next.starts_with('/') || next.contains("://")) && next.parse::<u16>().is_err()
            });
            !target_follows
        }
        // 📂 `root <path>` with one argument is the document root. The optional
        // `*` form (`root * /srv`) is how an operator says so explicitly.
        "root" => d.args.len() == 1,
        // 🚧 A conflict rather than a rule. `file_server /var/www` setting the
        // document root is an extension of ours, while the format it extends
        // reads that argument as a path matcher. Both cannot be true.
        //
        // Narrowed to the non-glob form, because `file_server /downloads/*` has
        // always been a matcher here and still is — so only the shape that is
        // genuinely ambiguous stays on the extension's side. Until the conflict
        // is decided, this is the place that records it.
        "file_server" => !first.contains('*'),
        _ => false,
    }
}

/// Parse the matcher for a `route`/`handle` directive.
///
/// Unlike the generic [`parse_matcher_and_block`], the first argument of a
/// `route`/`handle` block is *positionally* a matcher and accepts both
/// spellings Caddy allows:
///   - `@name`      → a named matcher defined elsewhere in the block
///   - `/some/path` → an inline path matcher (`handle /api/*`)
///
/// Historically only `@name` was recognised here, so `handle /api/*` (and
/// the equivalent `route "/api/*"`) silently dropped its path and collapsed
/// into the server's catch-all handler — every request matched it
/// regardless of URL. This dedicated helper keeps that leading-`/`
/// detection out of the generic branch, where a leading `/` is a real
/// argument (e.g. `file_server /var/www/html`), not a matcher.
pub(super) fn parse_route_matcher_and_block(
    d: &Directive,
) -> Result<(Option<Matcher>, Option<&Block>), AdapterError> {
    let block = d.block.as_ref();
    let matcher = match d.args.first() {
        Some(arg) if arg.starts_with('@') => Some(Matcher::Named(arg.clone())),
        Some(arg) if arg.starts_with('/') => Some(Matcher::Path(PathMatcher {
            patterns: vec![arg.clone()],
        })),
        _ => None,
    };
    Ok((matcher, block))
}

/// 🎯 Reads a directive's matcher token and resolves a named reference
/// against the scope the surrounding `route`/`handle` block can see.
pub(super) fn resolve_matcher_token(
    d: &Directive,
    matchers: &std::collections::HashMap<String, Matcher>,
) -> Result<Option<Matcher>, AdapterError> {
    let Some(matcher) = matcher_token(d) else {
        return Ok(None);
    };
    Ok(Some(match matcher {
        Matcher::Named(name) => matchers.get(&name).cloned().ok_or_else(|| {
            AdapterError::InvalidArgument(
                d.name.clone(),
                format!(
                    "matcher `{}` is not defined in this scope; define it in the site \
                     block or in this route/handle block",
                    name.strip_prefix('@').unwrap_or(&name)
                ),
            )
        })?,
        other => other,
    }))
}

pub(super) fn parse_matcher_definition(d: &Directive) -> Result<Matcher, AdapterError> {
    if let Some(block) = &d.block {
        let mut matchers = Vec::new();
        for sub in &block.directives {
            matchers.push(parse_single_matcher(sub)?);
        }

        if matchers.is_empty() {
            return Err(AdapterError::InvalidArgument(
                d.name.clone(),
                "Empty matcher block".into(),
            ));
        }

        Ok(merge_matcher_set(matchers))
    } else {
        // Inline matcher: @api path /v1/*
        if d.args.is_empty() {
            return Err(AdapterError::ArgumentCount(d.name.clone(), 1, 0));
        }
        let sub_directive = Directive {
            name: d.args[0].clone(),
            args: d.args[1..].to_vec(),
            block: None,
            // 🧪 Re-dispatching one matcher's arguments as another directive.
            // There is no such directive in the file, so there are no tokens.
            tokens: TokenRun::synthetic(),
        };
        parse_single_matcher(&sub_directive)
    }
}

/// 🧩 Merges a named matcher set the way Caddy does: matchers of the same
/// kind are OR'ed (path values, method verbs, host names, header fields of
/// the same name, query keys of the same name, remote-IP ranges) while
/// different kinds are AND'ed. The old code AND'ed everything, which made
/// `@foo { header Foo bar; header Foo baz }` impossible to satisfy.
pub(super) fn merge_matcher_set(matchers: Vec<Matcher>) -> Matcher {
    use std::collections::HashMap;

    let mut header_groups: HashMap<String, Vec<HeaderMatcher>> = HashMap::new();
    let mut query_groups: HashMap<String, Vec<QueryMatcher>> = HashMap::new();
    let mut paths: Vec<String> = Vec::new();
    let mut methods: Vec<HttpMethod> = Vec::new();
    let mut hosts: Vec<String> = Vec::new();
    let mut remote_ips: Vec<String> = Vec::new();
    let mut others: Vec<Matcher> = Vec::new();

    for matcher in matchers {
        match matcher {
            Matcher::Header(header) => {
                header_groups
                    .entry(header.name.clone())
                    .or_default()
                    .push(header);
            }
            Matcher::Query(query) => {
                query_groups
                    .entry(query.name.clone())
                    .or_default()
                    .push(query);
            }
            Matcher::Path(path) => paths.extend(path.patterns),
            Matcher::Method(m) => methods.extend(m),
            Matcher::Host(h) => hosts.extend(h),
            Matcher::RemoteIp(ips) => remote_ips.extend(ips),
            other => others.push(other),
        }
    }

    let mut parts: Vec<Matcher> = Vec::new();
    for headers in header_groups.into_values() {
        let group = headers
            .into_iter()
            .map(Matcher::Header)
            .reduce(|left, right| Matcher::Or(Box::new(left), Box::new(right)))
            .expect("a header group is never empty");
        parts.push(group);
    }
    for queries in query_groups.into_values() {
        let group = queries
            .into_iter()
            .map(Matcher::Query)
            .reduce(|left, right| Matcher::Or(Box::new(left), Box::new(right)))
            .expect("a query group is never empty");
        parts.push(group);
    }
    if !paths.is_empty() {
        parts.push(Matcher::Path(PathMatcher { patterns: paths }));
    }
    if !methods.is_empty() {
        parts.push(Matcher::Method(methods));
    }
    if !hosts.is_empty() {
        parts.push(Matcher::Host(hosts));
    }
    if !remote_ips.is_empty() {
        parts.push(Matcher::RemoteIp(remote_ips));
    }
    parts.extend(others);

    let mut combined = parts.remove(0);
    for part in parts {
        combined = Matcher::And(Box::new(combined), Box::new(part));
    }
    combined
}

/// 🕳️ Maximum matcher nesting accepted from a Pingclairfile.
///
/// Blocks are capped at 100 in the parser; matchers are a separate recursion
/// and were never capped, so `not not not …` deep enough exhausted the stack
/// and aborted the process. Nothing legitimate nests more than a few deep.
const MAX_MATCHER_NESTING: usize = 32;

pub(super) fn parse_single_matcher(d: &Directive) -> Result<Matcher, AdapterError> {
    parse_single_matcher_at(d, 0)
}

pub(super) fn parse_single_matcher_at(
    d: &Directive,
    depth: usize,
) -> Result<Matcher, AdapterError> {
    if depth > MAX_MATCHER_NESTING {
        return Err(AdapterError::InvalidArgument(
            d.name.clone(),
            format!("matcher nesting exceeds the maximum depth of {MAX_MATCHER_NESTING}"),
        ));
    }
    match d.name.as_str() {
        "path" => Ok(Matcher::Path(PathMatcher {
            patterns: d.args.clone(),
        })),
        "not" => {
            let inner = if let Some(block) = &d.block {
                let mut matchers = block
                    .directives
                    .iter()
                    .map(|inner| parse_single_matcher_at(inner, depth + 1))
                    .collect::<Result<Vec<_>, _>>()?;
                if matchers.is_empty() {
                    return Err(AdapterError::InvalidArgument(
                        "not".into(),
                        "empty matcher block".into(),
                    ));
                }
                let mut combined = matchers.remove(0);
                for matcher in matchers {
                    combined = Matcher::And(Box::new(combined), Box::new(matcher));
                }
                combined
            } else {
                let Some(name) = d.args.first() else {
                    return Err(AdapterError::ArgumentCount("not".into(), 1, 0));
                };
                let nested = Directive {
                    name: name.clone(),
                    args: d.args[1..].to_vec(),
                    block: None,
                    tokens: TokenRun::synthetic(),
                };
                parse_single_matcher_at(&nested, depth + 1)?
            };
            Ok(Matcher::Not(Box::new(inner)))
        }
        "method" => {
            // 🚫 Unknown verbs used to be filtered out silently, so
            // `method HEAD` produced a matcher that could never match while
            // `method GET FOO` quietly matched only GET. Every standard verb
            // is supported and anything else is a config error.
            let mut methods = Vec::with_capacity(d.args.len());
            for m in &d.args {
                let method = match m.to_uppercase().as_str() {
                    "GET" => HttpMethod::Get,
                    "POST" => HttpMethod::Post,
                    "PUT" => HttpMethod::Put,
                    "DELETE" => HttpMethod::Delete,
                    "PATCH" => HttpMethod::Patch,
                    "HEAD" => HttpMethod::Head,
                    "OPTIONS" => HttpMethod::Options,
                    other => {
                        return Err(AdapterError::InvalidArgument(
                            "method".into(),
                            format!("unknown HTTP method `{other}`"),
                        ));
                    }
                };
                methods.push(method);
            }
            Ok(Matcher::Method(methods))
        }
        "host" => {
            if d.args.is_empty() {
                return Err(AdapterError::ArgumentCount("host".into(), 1, 0));
            }
            Ok(Matcher::Host(d.args.clone()))
        }
        "query" => {
            // 🧭 `query q=1` / `query q=*`; several lines for the same key are
            // OR'ed by the set merge, different keys are AND'ed. The bare
            // `query ""` (no query string at all) is deferred to v0.3.
            let Some(spec) = d.args.first() else {
                return Err(AdapterError::ArgumentCount("query".into(), 1, 0));
            };
            if d.args.len() != 1 {
                return Err(AdapterError::ArgumentCount("query".into(), 1, d.args.len()));
            }
            if spec.is_empty() {
                // TODO(v0.3): support `query ""` (requests with no query
                // string) via a dedicated condition.
                return Err(AdapterError::UnsupportedFeature(
                    "query".into(),
                    "the empty-query matcher (`query \"\"`) is not implemented yet".into(),
                ));
            }
            let Some((name, value)) = spec.split_once('=') else {
                return Err(AdapterError::InvalidArgument(
                    "query".into(),
                    format!("expected `key=value`, got `{spec}`"),
                ));
            };
            let condition = if value == "*" {
                HeaderCondition::Exists
            } else {
                HeaderCondition::Equals(value.to_string())
            };
            Ok(Matcher::Query(QueryMatcher {
                name: name.to_string(),
                condition,
            }))
        }
        "protocol" => {
            if d.args.is_empty() {
                return Err(AdapterError::ArgumentCount("protocol".into(), 1, 0));
            }
            // 🚫 Versioned forms like `http/2+` need range comparison that the
            // runtime does not implement yet; refuse them instead of treating
            // them as an exact protocol string.
            if d.args.iter().any(|p| p.contains('/')) {
                // TODO(v0.3): implement versioned protocol matchers.
                return Err(AdapterError::UnsupportedFeature(
                    "protocol".into(),
                    "versioned protocol matchers (http/2+, grpc) are not implemented yet".into(),
                ));
            }
            Ok(Matcher::Protocol(d.args.clone()))
        }
        "remote_ip" | "client_ip" => {
            if d.args.is_empty() {
                return Err(AdapterError::ArgumentCount(d.name.clone(), 1, 0));
            }
            // 🧭 `client_ip` matches the verified client address; Pingclair
            // resolves that before routing, so both spellings share the same
            // remote-address evaluation for now.
            Ok(Matcher::RemoteIp(d.args.clone()))
        }
        "header" => {
            if d.args.is_empty() {
                return Err(AdapterError::ArgumentCount(
                    "header".into(),
                    1,
                    d.args.len(),
                ));
            }
            // 🚫 A third argument used to be silently dropped, so
            // `header Foo bar baz` matched only `bar`. Caddy matches one
            // field with one value per matcher line; write a second line for
            // an OR'ed value.
            if d.args.len() > 2 {
                return Err(AdapterError::ArgumentCount(
                    "header".into(),
                    2,
                    d.args.len(),
                ));
            }

            // 🚫 A `!` prefix means the field must NOT exist (`header !Foo`).
            let raw_name = &d.args[0];
            let negated = raw_name.starts_with('!');
            let name = raw_name.strip_prefix('!').unwrap_or(raw_name);

            let condition = if d.args.len() >= 2 {
                let val = &d.args[1];
                if val == "*" {
                    HeaderCondition::Exists
                } else if val.starts_with('*') && val.ends_with('*') && val.len() >= 2 {
                    HeaderCondition::Contains(val[1..val.len() - 1].to_string())
                } else if val.starts_with('*') {
                    // `*suffix` matches values ending with the rest.
                    HeaderCondition::EndsWith(val.strip_prefix('*').unwrap_or(val).to_string())
                } else if val.ends_with('*') {
                    // `prefix*` matches values starting with the rest.
                    HeaderCondition::StartsWith(val.strip_suffix('*').unwrap_or(val).to_string())
                } else {
                    HeaderCondition::Equals(val.clone())
                }
            } else {
                // Single arg: header exists
                HeaderCondition::Exists
            };

            let header = Matcher::Header(HeaderMatcher {
                name: name.to_string(),
                condition,
            });
            Ok(if negated {
                Matcher::Not(Box::new(header))
            } else {
                header
            })
        }
        // 🔤 `header_regexp <field> <pattern>` matches a header against a
        // regular expression. Everything below this line already existed —
        // the condition, its compilation, and the router's compiled-regex
        // cache — so this arm is the only thing that was missing.
        "header_regexp" => {
            let (field, pattern) = match d.args.as_slice() {
                [field, pattern] => (field, pattern),
                // 🔍 The three-argument form names the capture groups so
                // they can be read back as `{re.<name>.N}` placeholders.
                [name, field, pattern] => {
                    return Ok(Matcher::HeaderRegexp {
                        name: Some(name.clone()),
                        field: field.clone(),
                        pattern: pattern.clone(),
                    });
                }
                other => {
                    return Err(AdapterError::ArgumentCount(
                        "header_regexp".into(),
                        2,
                        other.len(),
                    ));
                }
            };

            // 🚫 An unparseable pattern would compile green and then match
            // nothing, for the lifetime of the server. Refuse it here, where
            // the operator is still looking at the line they wrote.
            if let Err(error) = regex::Regex::new(pattern) {
                return Err(AdapterError::InvalidArgument(
                    "header_regexp".into(),
                    format!("`{pattern}` is not a valid regular expression: {error}"),
                ));
            }

            Ok(Matcher::HeaderRegexp {
                name: None,
                field: field.clone(),
                pattern: pattern.clone(),
            })
        }
        // 🔤 `path_regexp [<name>] <pattern>` matches the request path
        // against a regular expression; the optional name makes capture
        // groups readable as `{re.<name>.N}` placeholders.
        "path_regexp" => {
            if d.block.is_some() {
                return Err(AdapterError::BlockNotAllowed("path_regexp".into()));
            }
            let (name, pattern) = match d.args.as_slice() {
                [pattern] => (None, pattern.clone()),
                [name, pattern] => (Some(name.clone()), pattern.clone()),
                other => {
                    return Err(AdapterError::ArgumentCount(
                        "path_regexp".into(),
                        2,
                        other.len(),
                    ));
                }
            };
            // 🚫 An unparseable pattern would compile green and then match
            // nothing, for the lifetime of the server.
            if let Err(error) = regex::Regex::new(&pattern) {
                return Err(AdapterError::InvalidArgument(
                    "path_regexp".into(),
                    format!("`{pattern}` is not a valid regular expression: {error}"),
                ));
            }
            Ok(Matcher::PathRegexp { name, pattern })
        }
        "vars" => {
            // 🧰 The `vars` matcher reads one request-scoped variable and
            // matches when its value equals any listed value.
            let [name, values @ ..] = d.args.as_slice() else {
                return Err(AdapterError::InvalidArgument(
                    "vars".into(),
                    "malformed vars matcher: expected a field name".into(),
                ));
            };
            if values.is_empty() {
                return Err(AdapterError::InvalidArgument(
                    "vars".into(),
                    "malformed vars matcher: expected at least one value".into(),
                ));
            }
            // 🚫 A `{placeholder}` key resolves against the request's
            // placeholder engine, which this matcher cannot reach from the
            // router; refusing is honest, and a literal-brace comparison
            // would be a matcher that silently never matches.
            if name.starts_with('{') && name.ends_with('}') {
                return Err(AdapterError::UnsupportedFeature(
                    "vars matcher".into(),
                    "placeholder keys are not implemented yet; use a variable name".into(),
                ));
            }
            Ok(Matcher::Vars {
                name: name.clone(),
                values: values.to_vec(),
            })
        }
        // 🚫 Matchers the format defines and this crate does not implement.
        // Each needs a capability we do not have rather than an arm here:
        // `expression` an expression language, `vars_regexp` regex against
        // the variable subsystem, `url_pattern` the URLPattern syntax, and
        // `tls` access to the handshake from a matcher.
        name if is_known_matcher(name) => Err(AdapterError::UnsupportedFeature(
            format!("{name} matcher"),
            "Pingclair does not implement this matcher yet".into(),
        )),
        _ => Err(AdapterError::UnknownDirective(format!(
            "matcher: {}",
            d.name
        ))),
    }
}

/// 🧾 Matcher names the format defines, whether or not we implement them.
///
/// The point is the same as everywhere else in this adapter: an operator who
/// wrote `path_regexp` spelled it correctly, and telling them the word is
/// unknown sends them looking for a spelling rather than a workaround.
fn is_known_matcher(name: &str) -> bool {
    matches!(name, "expression" | "url_pattern" | "vars_regexp" | "tls")
}
