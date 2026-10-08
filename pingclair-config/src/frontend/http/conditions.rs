// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🎛️ The conditions a route matches on.

use super::*;

use super::handlers::method_name;

/// 🎛️ Whether a typed value names an HTTP condition.
///
/// 📌 The one list both readers consult: `http_condition` below is what turns a
/// name into a matcher, and a `@Matcher` binding is accepted on the strength of
/// this predicate before anything uses it. Two lists would let a condition bind
/// and then fail on the line that uses it, or refuse to bind at all — which is
/// what happened to every HTTP condition until the corpus wrote one down.
pub(crate) fn is_http_condition(name: &str) -> bool {
    matches!(
        name,
        "path"
            | "host"
            | "method"
            | "header"
            | "query"
            | "protocol"
            | "clientIP"
            | "remoteIP"
            | "variable"
            | "file"
            | "all"
            | "any"
            | "not"
    )
}

/// 🎛️ A typed HTTP condition, lowered onto the shared matcher model.
pub(super) fn http_condition(
    value: &Value,
    at: Position,
) -> Result<(Matcher, Option<String>), Error> {
    let Value::Typed(call) = value else {
        return Err(at.error("a condition is a typed value such as .path(exact: \"/x\")"));
    };
    match call.name.as_str() {
        "path" => path_condition(call),
        "host" => {
            let [(None, Value::Array(items))] = call.args.as_slice() else {
                return Err(call.at.error("host takes one array of names"));
            };
            let mut hosts = Vec::new();
            for item in items {
                let Value::String(host) = item else {
                    return Err(call.at.error("host takes an array of names"));
                };
                hosts.push(host.clone());
            }
            if hosts.is_empty() {
                return Err(call.at.error("host needs at least one name"));
            }
            Ok((Matcher::Host(hosts), None))
        }
        "method" => {
            if call.args.is_empty() {
                return Err(call
                    .at
                    .error("method needs at least one .get/.post/... value"));
            }
            let mut methods = Vec::new();
            for (label, item) in call.args.as_slice() {
                if label.is_some() {
                    return Err(call
                        .at
                        .error("method takes unlabeled .get/.post/... values"));
                }
                let Value::Typed(value) = item else {
                    return Err(call
                        .at
                        .error("method takes unlabeled .get/.post/... values"));
                };
                methods.push(method_name(value)?.to_string());
            }
            Ok((Matcher::Method { methods }, None))
        }
        "all" | "any" => conjunction_or_disjunction(call),
        "not" => {
            let [(None, item)] = call.args.as_slice() else {
                return Err(call.at.error("not takes one condition"));
            };
            let (matcher, _) = http_condition(item, call.at)?;
            Ok((Matcher::Not(Box::new(matcher)), None))
        }
        "header" => header_or_query_condition(call, true),
        "query" => header_or_query_condition(call, false),
        "protocol" => protocol_condition(call),
        "clientIP" => address_condition(call, true),
        "remoteIP" => address_condition(call, false),
        "variable" => variable_condition(call),
        "file" => file_condition(call).map(|matcher| (matcher, None)),
        other => Err(call.at.error(format!(
            "unknown condition '.{other}'; expected .path, .host, .method, .header, .query, .protocol, .clientIP, .remoteIP, .variable, .file, .all, .any or .not"
        ))),
    }
}

/// 📁 The `.path(...)` variants: exact, segment prefix, glob and regex.
fn path_condition(call: &Call) -> Result<(Matcher, Option<String>), Error> {
    if let [(None, Value::Typed(regex))] = call.args.as_slice() {
        if regex.name != "regex" {
            return Err(regex.at.error(format!(
                "unknown path condition '.{}'; expected .regex",
                regex.name
            )));
        }
        let [(None, Value::String(pattern))] = regex.args.as_slice() else {
            return Err(regex.at.error("regex takes one pattern string"));
        };
        return Ok((
            Matcher::PathRegexp {
                name: None,
                pattern: pattern.clone(),
            },
            None,
        ));
    }
    call.leaf(&["exact", "prefix", "glob"])?;
    let mut chosen = Vec::new();
    for label in ["exact", "prefix", "glob"] {
        if call.get(label).is_some() {
            chosen.push(label);
        }
    }
    let [label] = chosen.as_slice() else {
        return Err(call
            .at
            .error("path requires exactly one of exact:, prefix:, glob: or .regex(...)"));
    };
    let text = call.string(label)?;
    if text.is_empty() {
        return Err(call.at.error(format!("{label} path must not be empty")));
    }
    if *label != "glob" && text.contains('*') {
        return Err(call.at.error(format!(
            "a {label} path cannot contain '*'; use glob: for wildcard patterns"
        )));
    }
    let (patterns, primary) = if *label == "prefix" {
        if text != "/" && text.ends_with('/') {
            return Err(call
                .at
                .error("a prefix must not end with '/'; write the parent path instead"));
        }
        let patterns = if text == "/" {
            vec!["/".to_string(), "/*".to_string()]
        } else {
            vec![text.clone(), format!("{text}/*")]
        };
        // 🧭 The route index needs a pattern that covers the whole subtree;
        // the matcher above still decides the exact semantics.
        let primary = if text == "/" {
            "/*".to_string()
        } else {
            format!("{text}*")
        };
        (patterns, Some(primary))
    } else {
        (vec![text.clone()], Some(text.clone()))
    };
    Ok((Matcher::Path { patterns }, primary))
}

/// 🔗 `.all([...])` and `.any([...])`, folded into an `And`/`Or` tree.
fn conjunction_or_disjunction(call: &Call) -> Result<(Matcher, Option<String>), Error> {
    let [(None, Value::Array(items))] = call.args.as_slice() else {
        return Err(call
            .at
            .error(format!("{} takes one array of conditions", call.name)));
    };
    if items.is_empty() {
        return Err(call
            .at
            .error(format!("{} needs at least one condition", call.name)));
    }
    let and = call.name == "all";
    let mut folded = None;
    let mut primary = None;
    for item in items {
        let (matcher, item_primary) = http_condition(item, call.at)?;
        if primary.is_none() {
            primary = item_primary;
        }
        folded = Some(match folded {
            None => matcher,
            Some(left) if and => Matcher::And(Box::new(left), Box::new(matcher)),
            Some(left) => Matcher::Or(Box::new(left), Box::new(matcher)),
        });
    }
    let folded = folded.expect("the array is non-empty");
    Ok((folded, if and { primary } else { None }))
}

/// 🏷️ `.header(...)` and `.query(...)`: one name and one typed predicate.
fn header_or_query_condition(
    call: &Call,
    is_header: bool,
) -> Result<(Matcher, Option<String>), Error> {
    let noun = if is_header { "header" } else { "query" };
    if is_header && let [(None, Value::Typed(regex))] = call.args.as_slice() {
        if regex.name != "regex" {
            return Err(regex.at.error(format!(
                "unknown header condition '.{}'; expected .regex",
                regex.name
            )));
        }
        regex.leaf(&["name", "pattern"])?;
        return Ok((
            Matcher::HeaderRegexp {
                name: None,
                field: regex.string("name")?,
                pattern: regex.string("pattern")?,
            },
            None,
        ));
    }
    call.leaf(&[
        "name",
        "value",
        "exists",
        "startsWith",
        "endsWith",
        "contains",
    ])?;
    let name = call.string("name")?;
    let mut predicates = Vec::new();
    for label in ["value", "exists", "startsWith", "endsWith", "contains"] {
        if call.get(label).is_some() {
            predicates.push(label);
        }
    }
    let [predicate] = predicates.as_slice() else {
        return Err(call.at.error(format!(
            "{noun} needs exactly one predicate: value:, exists:, startsWith:, endsWith: or contains:"
        )));
    };
    let condition = match *predicate {
        "value" => MatcherCondition::Equals(call.string("value")?),
        "exists" => {
            if !call.boolean("exists")? {
                return Err(call.at.error(format!(
                    "exists: false needs .not(...); write .not(.{noun}(name: \"…\", exists: true))"
                )));
            }
            MatcherCondition::Exists
        }
        "startsWith" => MatcherCondition::StartsWith(call.string("startsWith")?),
        "endsWith" => MatcherCondition::EndsWith(call.string("endsWith")?),
        "contains" => MatcherCondition::Contains(call.string("contains")?),
        _ => unreachable!(),
    };
    let matcher = if is_header {
        Matcher::Header { name, condition }
    } else {
        Matcher::Query { name, condition }
    };
    Ok((matcher, None))
}

/// 🌐 `.protocol(.http1, .http2, .http3)`: which protocols the route accepts.
fn protocol_condition(call: &Call) -> Result<(Matcher, Option<String>), Error> {
    if call.args.is_empty() {
        return Err(call
            .at
            .error("protocol needs at least one of .http1, .http2 or .http3"));
    }
    let mut names: Vec<String> = Vec::new();
    for (label, item) in call.args.as_slice() {
        if label.is_some() {
            return Err(call
                .at
                .error("protocol takes unlabeled .http1/.http2/.http3 values"));
        }
        let Value::Typed(value) = item else {
            return Err(call
                .at
                .error("protocol takes unlabeled .http1/.http2/.http3 values"));
        };
        if !value.args.is_empty() {
            return Err(value.at.error("a protocol value takes no arguments"));
        }
        let name = match value.name.as_str() {
            "http1" | "http2" | "http3" => value.name.clone(),
            other => {
                return Err(value.at.error(format!(
                    "unknown protocol '.{other}'; expected .http1, .http2 or .http3"
                )));
            }
        };
        if names.contains(&name) {
            return Err(value.at.error("duplicate protocol entry"));
        }
        names.push(name);
    }
    Ok((Matcher::Protocol(names), None))
}

/// 🔌 `.clientIP([...])` and `.remoteIP([...])`, with `.privateRanges`.
fn address_condition(call: &Call, client: bool) -> Result<(Matcher, Option<String>), Error> {
    let noun = if client { "clientIP" } else { "remoteIP" };
    let [(None, Value::Array(items))] = call.args.as_slice() else {
        return Err(call.at.error(format!(
            "{noun} takes one array of CIDRs, optionally including .privateRanges"
        )));
    };
    if items.is_empty() {
        return Err(call.at.error(format!("{noun} needs at least one range")));
    }
    let mut ranges = Vec::new();
    for item in items {
        match item {
            Value::String(range) => ranges.push(range.clone()),
            Value::Typed(value) if value.name == "privateRanges" && value.args.is_empty() => {
                ranges.extend(PRIVATE_RANGES.iter().map(|range| (*range).to_string()));
            }
            _ => {
                return Err(call
                    .at
                    .error(format!("{noun} takes CIDR strings or .privateRanges")));
            }
        }
    }
    let ranges = IpRanges::parse(ranges).map_err(|error| call.at.error(error.to_string()))?;
    let matcher = if client {
        Matcher::ClientIp(ranges)
    } else {
        Matcher::RemoteIp(ranges)
    };
    Ok((matcher, None))
}

/// 📦 `.variable(name:, values:)`: a request-scoped variable match.
fn variable_condition(call: &Call) -> Result<(Matcher, Option<String>), Error> {
    call.leaf(&["name", "values"])?;
    let name = call.string("name")?;
    let values = call.strings("values")?;
    if values.is_empty() {
        return Err(call.at.error("variable needs at least one value"));
    }
    Ok((Matcher::Vars { name, values }, None))
}

/// 📂 `.file(candidates:, root:, policy:)`: whether a candidate exists on disk.
///
/// 📌 The same candidate vocabulary as `TryFiles` below, and for the same
/// reason: one reader for one concept. A condition on file existence is what
/// the `try_files` shorthand is built out of.
pub(super) fn file_condition(call: &Call) -> Result<Matcher, Error> {
    let files = file_candidates(call)?;
    let root = if call.get("root").is_some() {
        Some(call.string("root")?)
    } else {
        None
    };
    let try_policy = file_policy(call)?;
    Ok(Matcher::File {
        try_files: files,
        root,
        try_policy,
        // 🐘 The `.php` split belongs to the FastCGI expansion, which knows
        // what it is splitting; a hand-written condition says what it means
        // by naming its candidates.
        split_path: Vec::new(),
    })
}

/// 📂 `candidates:` — literal paths and the request path itself.
///
/// 🚫 Two things are refused by name rather than passed through: `{…}` because
/// the language has typed sources instead of interpolation, and `*` because
/// glob candidates are unimplemented in this build (#21) and would have to be
/// silently treated as a literal `*` in a filename.
/// 🏷️ The argument labels `try_files` accepts, named once for the parser and `describe`.
pub(crate) const TRY_FILES_LABELS: &[&str] = &["candidates", "root", "policy"];

pub(super) fn file_candidates(call: &Call) -> Result<Vec<String>, Error> {
    call.leaf(TRY_FILES_LABELS)?;
    let Some(Value::Array(items)) = call.get("candidates") else {
        return Err(call
            .at
            .error("candidates takes an array such as [.requestPath, \"/index.html\"]"));
    };
    if items.is_empty() {
        return Err(call.at.error("candidates needs at least one entry"));
    }
    let mut files = Vec::new();
    for item in items {
        files.push(file_candidate(item, call.at)?);
    }
    Ok(files)
}

/// 📂 One candidate, as the matcher spells it.
pub(super) fn file_candidate(value: &Value, at: Position) -> Result<String, Error> {
    match value {
        // 🔤 A literal path. No interpolation: `{path}` spelled by hand is the
        // engine's own vocabulary, and `.requestPath` is the typed spelling of
        // exactly that idea.
        Value::String(path) => Ok(with_kept_query(candidate_path(path, at)?, false)),
        Value::Typed(source) => {
            match source.name.as_str() {
                // 🌐 The request path itself.
                "requestPath" => {
                    source.leaf(&["appending", "keepQuery"])?;
                    let appending = if source.get("appending").is_some() {
                        source.string("appending")?
                    } else {
                        String::new()
                    };
                    let keep_query = if source.get("keepQuery").is_some() {
                        source.boolean("keepQuery")?
                    } else {
                        false
                    };
                    // 🌐 Only the part the author wrote is checked: the `{path}`
                    // head is the typed source's own lowering.
                    let suffix = if appending.is_empty() {
                        String::new()
                    } else {
                        candidate_path(&appending, source.at)?
                    };
                    Ok(with_kept_query(format!("{{path}}{suffix}"), keep_query))
                }
                // 🔤 A fixed path. Typed rather than a plain string because it
                // can carry `keepQuery:`; a string cannot say that.
                "path" => {
                    let (path, keep_query) = match source.args.as_slice() {
                        [(None, Value::String(path))] => (path.clone(), false),
                        [
                            (None, Value::String(path)),
                            (Some(label), Value::Bool(keep)),
                        ] if label == "keepQuery" => (path.clone(), *keep),
                        _ => {
                            return Err(source.at.error(
                                ".path takes a quoted path, and optionally keepQuery: true",
                            ));
                        }
                    };
                    source.no_modifiers()?;
                    if source.body.is_some() {
                        return Err(source.at.error(".path does not take a block"));
                    }
                    Ok(with_kept_query(
                        candidate_path(&path, source.at)?,
                        keep_query,
                    ))
                }
                other => Err(source.at.error(format!(
                    "unknown candidate '.{other}'; expected .requestPath, \
                         .requestPath(appending: \"…\") or .path(\"…\", keepQuery: true)"
                ))),
            }
        }
        _ => Err(at.error(
            "a candidate is a quoted path, .requestPath(appending: \"…\") or \
             .path(\"…\", keepQuery: true)",
        )),
    }
}

/// 📂 One literal candidate path, checked for the spellings this build refuses.
pub(super) fn candidate_path(path: &str, at: Position) -> Result<String, Error> {
    if path.is_empty() {
        return Err(at.error("a candidate must not be empty"));
    }
    if path.contains('{') || path.contains('}') {
        return Err(at.error(
            "candidates do not interpolate; write .requestPath for the request path, or \
             .requestPath(appending: \"…\") for it plus a suffix",
        ));
    }
    if path.contains('*') {
        return Err(at.error(
            "glob candidates are not implemented in this build, and a literal `*` in a path \
             is not what this would mean; write the paths out",
        ));
    }
    if path.contains('?') {
        return Err(at.error(
            "a candidate is a path; `keepQuery: true` on a typed candidate is how the request's \
             query string is carried into the rewrite",
        ));
    }
    Ok(path.to_string())
}

/// 📌 The query flag travels as the matcher's own `?` marker — the same thing
/// the Caddyfile spelling compiles to.
pub(super) fn with_kept_query(path: String, keep_query: bool) -> String {
    if keep_query {
        format!("{path}?{{query}}")
    } else {
        path
    }
}

/// 🗂️ `policy:` — how several existing candidates are ranked.
pub(super) fn file_policy(call: &Call) -> Result<Option<String>, Error> {
    let Some(value) = call.get("policy") else {
        return Ok(None);
    };
    let Value::Typed(policy) = value else {
        return Err(call
            .at
            .error("policy takes a typed value such as .mostRecentlyModified"));
    };
    policy.leaf(&[])?;
    Ok(Some(
        match policy.name.as_str() {
            "firstExist" => "first_exist",
            "firstExistFallback" => "first_exist_fallback",
            "largestSize" => "largest_size",
            "smallestSize" => "smallest_size",
            "mostRecentlyModified" => "most_recently_modified",
            other => {
                return Err(policy.at.error(format!(
                    "unknown file policy '.{other}'; expected .firstExist, .firstExistFallback, \
                     .largestSize, .smallestSize or .mostRecentlyModified"
                )));
            }
        }
        .to_string(),
    ))
}
