// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

use super::AdapterError;
use super::args::{
    expect_no_arguments, expect_one_argument, parse_duration_ms, parse_positive_u64,
    parse_positive_usize, parse_required_duration,
};
use super::matchers::{
    parse_matcher_definition, parse_route_matcher_and_block, resolve_matcher_token,
};
use super::order::DirectiveOrder;
use super::reverse_proxy::adapt_reverse_proxy;
use crate::parser::ast::*;
use crate::parser::caddy_ast::{Block, Directive};
use pingclair_core::config::BasicAuthAlgorithm;
use std::collections::HashMap;

// MARK: - Handler Adaptation

pub(super) fn adapt_handler(
    d: Directive,
    matchers: &HashMap<String, Matcher>,
    order: &DirectiveOrder,
) -> Result<Handler, AdapterError> {
    match d.name.as_str() {
        "reverse_proxy" => adapt_reverse_proxy(d),
        "respond" => adapt_respond(d),
        "redir" | "redirect" => adapt_redirect(d),
        "file_server" => {
            let mut root = ".".to_string();
            let mut browse = false;
            if let Some(arg) = d.args.first() {
                if arg == "browse" {
                    // 🧭 Caddy's `file_server browse` enables directory
                    // listings without opening a block.
                    browse = true;
                } else if !arg.starts_with('@') {
                    root = arg.clone();
                }
            }

            let mut config = FileServerConfig {
                root,
                index: vec!["index.html".into()],
                browse,
                compress: true,
            };

            if let Some(block) = d.block {
                for sub in block.directives {
                    match sub.name.as_str() {
                        "root" => {
                            if let Some(arg) = sub.args.first() {
                                config.root = arg.clone();
                            }
                        }
                        "index" => config.index = sub.args.clone(),
                        "browse" => {
                            config.browse =
                                browse || sub.args.first().map(|s| s == "true").unwrap_or(true)
                        }
                        // 🚩 Subdirectives the format defines and this file
                        // server does not implement. They used to compile into
                        // a file server that quietly served without any of the
                        // behaviour asked for; rejecting them is the only
                        // honest option until they exist.
                        //
                        // 📌 They are named here rather than falling through to
                        // "unknown" on purpose: an operator who wrote `hide`
                        // spelled it correctly, and "unknown directive" sends
                        // them hunting for a typo instead of telling them the
                        // feature is missing. That distinction is the whole
                        // difference between a wrong file and a missing
                        // feature.
                        "precompressed"
                        | "fs"
                        | "hide"
                        | "status"
                        | "pass_thru"
                        | "disable_canonical_uris"
                        | "etag_file_extensions" => {
                            // TODO(v0.3): implement precompressed sidecar
                            // lookup, custom file-system modules, hidden-path
                            // filtering, and the response-shaping options.
                            return Err(AdapterError::UnsupportedFeature(
                                format!("file_server {}", sub.name),
                                "Pingclair does not implement this subdirective yet".into(),
                            ));
                        }
                        other => {
                            return Err(AdapterError::UnknownDirective(format!(
                                "file_server: {other}"
                            )));
                        }
                    }
                }
            }
            Ok(Handler::FileServer(config))
        }
        "templates" => Ok(Handler::Templates),
        "header" => adapt_header_directive(&d),
        "log_skip" => Ok(Handler::LogSkip),
        "route" => adapt_subroute_block(&d, matchers, order, false),
        "handle" => adapt_subroute_block(&d, matchers, order, true),
        "handle_path" => adapt_handle_path(&d, matchers, order).map(|(_, handler)| handler),
        "basic_auth" | "basicauth" => adapt_basic_auth(d),
        "rate_limit" => adapt_rate_limit(d),
        "error" => adapt_error_directive(&d),
        "rewrite" => adapt_rewrite(d),
        "uri" => adapt_uri(d),
        "try_files" => adapt_try_files(d),
        "cors" => adapt_cors(d),
        "access_control" => adapt_access_control(d),
        // 🚫 A directive that exists in Caddy's standard set but has no
        // implementation here gets a message that says so, instead of being
        // indistinguishable from a typo.
        // 🚫 A name the registry knows gets a message saying the feature is
        // missing; anything else is a typo. One table decides, so the two can
        // never disagree about the same word.
        //
        // 🧭 The registry also separates "we do not have this" from "we have
        // this, but not here" — `root` is a site-level directive and lands in
        // this arm only when it was written inside a `route` or `handle` block.
        // Telling an operator to go implement a directive that already exists
        // would send them looking in the wrong place entirely.
        other => Err(match super::registry::directive(other) {
            Some(spec) if spec.support == super::registry::Support::Implemented => {
                AdapterError::UnsupportedFeature(
                    other.to_string(),
                    "this directive is not supported inside a route or handle block yet".into(),
                )
            }
            Some(_) => AdapterError::UnsupportedFeature(
                other.to_string(),
                "this directive is not implemented yet".into(),
            ),
            None => AdapterError::UnknownDirective(other.to_string()),
        }),
    }
}

/// 🛣️ Builds a `route` or `handle` block's elements.
///
/// `sorted` is the whole difference between the two directives: Caddy keeps
/// `route` contents in file order (`buildSubroute(..., false)`) and sorts
/// `handle` contents (`buildSubroute(..., true)`).
pub(super) fn adapt_subroute_block(
    d: &Directive,
    parent_matchers: &HashMap<String, Matcher>,
    order: &DirectiveOrder,
    sorted: bool,
) -> Result<Handler, AdapterError> {
    let elements = match &d.block {
        Some(block) => collect_subroute_elements(block, parent_matchers, order, sorted)?,
        None => Vec::new(),
    };
    Ok(if sorted {
        Handler::Handle(elements)
    } else {
        Handler::Pipeline(elements)
    })
}

/// 🛣️ Builds a `handle_path` block, returning its matcher and handler so the
/// caller can attach the matcher to the surrounding route or element.
pub(super) fn adapt_handle_path(
    d: &Directive,
    parent_matchers: &HashMap<String, Matcher>,
    order: &DirectiveOrder,
) -> Result<(Option<Matcher>, Handler), AdapterError> {
    let (matcher, inner_block) = parse_route_matcher_and_block(d)?;
    let Some(Matcher::Path(path)) = matcher.clone() else {
        return Err(AdapterError::InvalidArgument(
            "handle_path".into(),
            "expected a path to match and strip, e.g. `handle_path /api/* { … }`".into(),
        ));
    };
    // 🧭 The prefix is the pattern without its glob: matching `/api/*`
    // strips `/api`. Stripping the `*` as well would leave a prefix nothing
    // starts with.
    let prefix = path
        .patterns
        .first()
        .map(|pattern| pattern.trim_end_matches('*').trim_end_matches('/'))
        .unwrap_or_default()
        .to_string();
    if prefix.is_empty() {
        return Err(AdapterError::InvalidArgument(
            "handle_path".into(),
            "the path to strip cannot be empty; use `handle` instead".into(),
        ));
    }
    let elements = match inner_block {
        Some(block) => collect_subroute_elements(block, parent_matchers, order, true)?,
        None => Vec::new(),
    };
    Ok((
        matcher,
        Handler::HandlePath {
            prefix,
            handlers: elements,
        },
    ))
}

/// 🧭 Turns one block's directives into matcher-guarded elements.
///
/// Caddy's three scope rules live here: named matcher definitions are copied
/// from the parent scope, additions stay local to this block, and nothing is
/// written back to the parent.
fn collect_subroute_elements(
    block: &Block,
    parent_matchers: &HashMap<String, Matcher>,
    order: &DirectiveOrder,
    sorted: bool,
) -> Result<Vec<HandlerElement>, AdapterError> {
    let mut local = parent_matchers.clone();
    let mut elements = Vec::new();
    for inner_d in &block.directives {
        // 🏷️ A named matcher definition belongs to this block's scope.
        if inner_d.name.starts_with('@') {
            let matcher = parse_matcher_definition(inner_d)?;
            local.insert(inner_d.name.clone(), matcher);
            continue;
        }
        // 🛣️ `handle_path` owns its leading path: it is both the element's
        // matcher and the prefix to strip, so it must not go through the
        // generic matcher-token stripping.
        if inner_d.name == "handle_path" {
            let (matcher, handler) = adapt_handle_path(inner_d, &local, order)?;
            elements.push(HandlerElement { matcher, handler });
            continue;
        }
        let matcher = resolve_matcher_token(inner_d, &local)?;
        let mut stripped = inner_d.clone();
        if matcher.is_some() {
            stripped.drop_first_arg();
        }
        let handler = adapt_handler(stripped, &local, order)?;
        elements.push(HandlerElement { matcher, handler });
    }
    if sorted {
        sort_handle_elements(&mut elements, order);
    }
    Ok(elements)
}

/// 🔢 Sorts `handle` elements the way Caddy's `sortRoutes` does: directive
/// order first, then path-matcher specificity (exact before glob, longer
/// before shorter). `route` never calls this.
fn sort_handle_elements(elements: &mut [HandlerElement], order: &DirectiveOrder) {
    elements.sort_by(|a, b| {
        let rank =
            |element: &HandlerElement| super::sites::caddy_handler_rank(order, &element.handler);
        rank(a).cmp(&rank(b)).then_with(|| {
            let (a_exact, a_len) = super::sites::route_specificity(&a.matcher);
            let (b_exact, b_len) = super::sites::route_specificity(&b.matcher);
            a_exact.cmp(&b_exact).then_with(|| b_len.cmp(&a_len))
        })
    });
}

/// 🚦 Adapts an exact local rate-limit policy and rejects ambiguous options.
pub(super) fn adapt_rate_limit(directive: Directive) -> Result<Handler, AdapterError> {
    let [requests, window] = directive.args.as_slice() else {
        return Err(AdapterError::InvalidArgument(
            directive.name,
            "expected <requests> <window> followed by an optional block".into(),
        ));
    };
    let requests = requests
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| AdapterError::InvalidArgument("rate_limit".into(), requests.clone()))?;
    let window_ms = parse_duration_ms(window)
        .filter(|value| *value >= 1_000 && value % 1_000 == 0)
        .ok_or_else(|| AdapterError::InvalidArgument("rate_limit".into(), window.clone()))?;
    let mut config = RateLimitConfig {
        requests,
        window_ms,
        burst: 0,
        key: RateLimitKey::Ip,
        dry_run: false,
    };

    if let Some(block) = directive.block {
        for option in block.directives {
            match option.name.as_str() {
                "burst" => {
                    let value = expect_one_argument(&option)?;
                    config.burst = value.parse::<u64>().map_err(|_| {
                        AdapterError::InvalidArgument(option.name.clone(), value.to_string())
                    })?;
                }
                "dry_run" => {
                    expect_no_arguments(&option)?;
                    config.dry_run = true;
                }
                "key" => {
                    config.key = match option.args.as_slice() {
                        [kind] if kind == "ip" => RateLimitKey::Ip,
                        [kind] if kind == "global" => RateLimitKey::Global,
                        [kind] if kind == "route" => RateLimitKey::Route,
                        [kind] if kind == "api_key" => RateLimitKey::ApiKey,
                        [kind] if kind == "tenant" => RateLimitKey::Tenant("X-Tenant-ID".into()),
                        [kind, name] if kind == "header" => RateLimitKey::Header(name.clone()),
                        [kind, name] if kind == "tenant" => RateLimitKey::Tenant(name.clone()),
                        _ => {
                            return Err(AdapterError::InvalidArgument(
                                option.name,
                                "expected ip, global, route, api_key, header <name>, or tenant [name]"
                                    .into(),
                            ));
                        }
                    };
                }
                _ => return Err(AdapterError::UnknownDirective(option.name)),
            }
        }
    }

    Ok(Handler::RateLimit(config))
}

pub(super) fn adapt_redirect(d: Directive) -> Result<Handler, AdapterError> {
    if d.block.is_some() {
        return Err(AdapterError::BlockNotAllowed(d.name));
    }

    let (to, code) = match d.args.as_slice() {
        [to] => (to.clone(), 302),
        [to, code] => {
            let code = match code.as_str() {
                "temporary" => 302,
                "permanent" => 301,
                value => value.parse::<u16>().map_err(|_| {
                    AdapterError::InvalidArgument(d.name.clone(), value.to_string())
                })?,
            };
            (to.clone(), code)
        }
        _ => {
            return Err(AdapterError::InvalidArgument(
                d.name,
                "expected <location> [3xx|temporary|permanent]".into(),
            ));
        }
    };

    if !(300..=399).contains(&code) {
        return Err(AdapterError::InvalidArgument(
            d.name,
            format!("status {code} is not a redirect code"),
        ));
    }

    Ok(Handler::Redirect(RedirectConfig { to, code }))
}

/// Adapt `rewrite <replacement>` or `rewrite <regex> <replacement>`.
///
/// The two-argument form is deliberately explicit: it keeps a plain
/// replacement from accidentally treating punctuation as a regex and maps
/// capture groups directly to Rust-regex's `$1` replacement syntax.
pub(super) fn adapt_rewrite(d: Directive) -> Result<Handler, AdapterError> {
    if d.block.is_some() {
        return Err(AdapterError::BlockNotAllowed("rewrite".into()));
    }
    match d.args.as_slice() {
        [replace] => Ok(Handler::Rewrite(RewriteConfig {
            replace: Some(replace.clone()),
            ..Default::default()
        })),
        [regex, replacement] => Ok(Handler::Rewrite(RewriteConfig {
            regex: Some(regex.clone()),
            regex_replace: Some(replacement.clone()),
            ..Default::default()
        })),
        _ => Err(AdapterError::InvalidArgument(
            "rewrite".into(),
            "expected <replacement> or <regex> <replacement>".into(),
        )),
    }
}

/// 🪚 Adapts `uri <operation> <args...>`, the path-surgery half of rewriting.
///
/// Three of the format's operations map onto the rewrite this crate already
/// performs. Two do not, and are refused by name rather than approximated:
///
/// - `replace` means *substring* replacement upstream, while this crate's
///   `replace` swaps the whole path. Accepting it would compile, run, and
///   quietly produce a different URL than the operator asked for — the one
///   outcome worse than an error, because nothing announces it.
/// - `query` edits the query string, which no handler here touches at all.
///
/// 📌 They are named in the message because an operator who wrote `uri replace`
/// spelled it correctly; sending them to hunt for a typo would be a second
/// wrong answer on top of the missing feature.
pub(super) fn adapt_uri(d: Directive) -> Result<Handler, AdapterError> {
    if d.block.is_some() {
        return Err(AdapterError::BlockNotAllowed("uri".into()));
    }
    let operation = d.args.first().map(String::as_str).ok_or_else(|| {
        AdapterError::InvalidArgument(
            "uri".into(),
            "expected strip_prefix, strip_suffix, or path_regexp".into(),
        )
    })?;
    let operands = &d.args[1..];

    match (operation, operands) {
        ("strip_prefix", [prefix]) => Ok(Handler::Rewrite(RewriteConfig {
            strip_prefix: Some(prefix.clone()),
            directive: "uri",
            ..Default::default()
        })),
        ("strip_suffix", [suffix]) => Ok(Handler::Rewrite(RewriteConfig {
            strip_suffix: Some(suffix.clone()),
            directive: "uri",
            ..Default::default()
        })),
        // 🧭 Both operands are required, matching the documented form. Making
        // the replacement optional here would accept a configuration the
        // format refuses, which is the direction of mistake that gets found
        // in production rather than at adapt time.
        ("path_regexp", [pattern, replacement]) => Ok(Handler::Rewrite(RewriteConfig {
            regex: Some(pattern.clone()),
            regex_replace: Some(replacement.clone()),
            directive: "uri",
            ..Default::default()
        })),
        ("strip_prefix" | "strip_suffix", operands) => Err(AdapterError::ArgumentCount(
            format!("uri {operation}"),
            1,
            operands.len(),
        )),
        ("path_regexp", operands) => Err(AdapterError::ArgumentCount(
            "uri path_regexp".into(),
            2,
            operands.len(),
        )),
        ("replace", _) => Err(AdapterError::UnsupportedFeature(
            "uri replace".into(),
            "`uri replace` substitutes a substring of the path, while Pingclair's rewrite \
             replaces the whole path; rather than silently produce a different URL, this is \
             refused until substring replacement exists"
                .into(),
        )),
        ("query", _) => Err(AdapterError::UnsupportedFeature(
            "uri query".into(),
            "Pingclair does not rewrite query strings yet".into(),
        )),
        (other, _) => Err(AdapterError::InvalidArgument(
            "uri".into(),
            format!(
                "unknown operation `{other}` (expected strip_prefix, strip_suffix, or path_regexp)"
            ),
        )),
    }
}

/// 🗂️ Adapts `try_files <candidate...>`.
///
/// Each candidate is a URI path resolved under the site root, and the first one
/// that exists becomes the request's new path. The directive serves nothing on
/// its own — the single-page-application pattern is `try_files` followed by
/// `file_server`, and that second line is what answers.
fn adapt_try_files(d: Directive) -> Result<Handler, AdapterError> {
    if d.block.is_some() {
        return Err(AdapterError::BlockNotAllowed("try_files".into()));
    }
    if d.args.is_empty() {
        return Err(AdapterError::InvalidArgument(
            "try_files".into(),
            "expected at least one candidate path".into(),
        ));
    }
    // 🚫 A candidate carrying a query string is the `php_fastcgi` shape
    // (`try_files {path} /index.php?{query}`), and nothing here would do
    // anything with the query. Refusing it keeps a configuration written for
    // that pattern from looking like it works.
    if let Some(candidate) = d.args.iter().find(|candidate| candidate.contains('?')) {
        return Err(AdapterError::UnsupportedFeature(
            format!("try_files {candidate}"),
            "a candidate with a query string is not supported; Pingclair rewrites the path \
             only and would drop the query without saying so"
                .into(),
        ));
    }
    Ok(Handler::TryFiles(d.args))
}

/// Adapt the CORS directive. Inline arguments are allowed origins; block
/// subdirectives are `origins`, `methods`, `headers`, `expose_headers`,
/// `allow_credentials`, and `max_age`.
pub(super) fn adapt_cors(d: Directive) -> Result<Handler, AdapterError> {
    let mut config = CorsConfig {
        allowed_origins: d.args,
        ..Default::default()
    };
    if let Some(block) = d.block {
        for sub in block.directives {
            match sub.name.as_str() {
                "origins" => config.allowed_origins = sub.args,
                "methods" => config.allowed_methods = sub.args,
                "headers" => config.allowed_headers = sub.args,
                "expose_headers" => config.exposed_headers = sub.args,
                "allow_credentials" => {
                    config.allow_credentials = sub
                        .args
                        .first()
                        .map(|value| value == "true" || value == "on")
                        .unwrap_or(true);
                }
                "max_age" => {
                    let value = sub
                        .args
                        .first()
                        .ok_or_else(|| AdapterError::ArgumentCount("cors max_age".into(), 1, 0))?;
                    config.max_age = Some(value.parse().map_err(|_| {
                        AdapterError::InvalidArgument("cors max_age".into(), value.clone())
                    })?);
                }
                _ => {
                    return Err(AdapterError::UnknownDirective(format!(
                        "cors: {}",
                        sub.name
                    )));
                }
            }
        }
    }
    Ok(Handler::Cors(config))
}

/// Adapt route access control. Each subdirective accepts one or more values:
/// `allow_ip`, `deny_ip`, `allow_referer`, `deny_referer`, `allow_user_agent`,
/// and `deny_user_agent`.
pub(super) fn adapt_access_control(d: Directive) -> Result<Handler, AdapterError> {
    if !d.args.is_empty() || d.block.is_none() {
        return Err(AdapterError::InvalidArgument(
            "access_control".into(),
            "expected a block of allow_/deny_ rules".into(),
        ));
    }
    let mut config = AccessControlConfig::default();
    for sub in d.block.unwrap().directives {
        if sub.args.is_empty() {
            return Err(AdapterError::ArgumentCount(sub.name, 1, 0));
        }
        match sub.name.as_str() {
            "allow_ip" => config.allowed_ips.extend(sub.args),
            "deny_ip" => config.denied_ips.extend(sub.args),
            "allow_referer" => config.allowed_referers.extend(sub.args),
            "deny_referer" => config.denied_referers.extend(sub.args),
            "allow_user_agent" => config.allowed_user_agents.extend(sub.args),
            "deny_user_agent" => config.denied_user_agents.extend(sub.args),
            _ => {
                return Err(AdapterError::UnknownDirective(format!(
                    "access_control: {}",
                    sub.name
                )));
            }
        }
    }
    Ok(Handler::AccessControl(config))
}

// MARK: - basic_auth Directive Adapter

/// 🔐 Adapts the `basic_auth` directive.
///
/// The grammar is the format's own, read from `caddyauth/caddyfile.go` at
/// `ff6da121`:
///
/// ```text
/// basic_auth [<matcher>] [<hash_algorithm> [<realm>]] {
///     <username> <hashed_password>
///     ...
/// }
/// ```
///
/// The realm is the **second argument**, not a subdirective, and the block
/// holds nothing but accounts. With no arguments the algorithm is bcrypt.
///
/// 🤡 This crate used to read the arguments as inline `<user> <password>`
/// pairs and take `realm` as a subdirective — two spellings the format does
/// not have, both of which *collide* with the one it does. `basic_auth bcrypt
/// "Admin Area" { … }`, straight out of the documentation, was refused with
/// "cannot mix inline credentials with a block", so an authenticated site
/// failed on the first paste. The collision is why the old spellings could not
/// simply be kept alongside: under the real grammar, a block line reading
/// `realm "Admin Area"` is an *account* named `realm`.
pub(super) fn adapt_basic_auth(d: Directive) -> Result<Handler, AdapterError> {
    // 🔑 `[<hash_algorithm> [<realm>]]`, and nothing else, may precede the block.
    let (algorithm, realm) = match d.args.as_slice() {
        [] => ("bcrypt", None),
        [algorithm] => (algorithm.as_str(), None),
        [algorithm, realm] => (algorithm.as_str(), Some(realm.clone())),
        args => {
            return Err(AdapterError::InvalidArgument(
                "basic_auth".into(),
                format!(
                    "expected at most <hash_algorithm> <realm>, got {} arguments; credentials                      belong in the block, one `<username> <hashed_password>` per line",
                    args.len()
                ),
            ));
        }
    };

    // 🔑 The declared algorithm is stored, not guessed: a credential is only
    // ever verified against the algorithm this line names, so an `$argon2id$`
    // hash under `basic_auth argon2id` can never fall through to a literal
    // comparison again.
    let algorithm = match algorithm {
        "bcrypt" => BasicAuthAlgorithm::Bcrypt,
        "argon2id" => BasicAuthAlgorithm::Argon2id,
        other => {
            return Err(AdapterError::InvalidArgument(
                "basic_auth".into(),
                format!("unrecognized hash algorithm `{other}` (expected bcrypt or argon2id)"),
            ));
        }
    };

    let mut config = BasicAuthConfig {
        realm,
        algorithm,
        credentials: Vec::new(),
    };

    let Some(block) = &d.block else {
        return Err(AdapterError::InvalidArgument(
            "basic_auth".into(),
            "expected a block of `<username> <hashed_password>` lines".into(),
        ));
    };

    for account in &block.directives {
        // 🛡️ `realm` as the first word of a block line used to configure the
        // realm here and now names an account. Silently accepting it would
        // turn a line that configured nothing into a *working credential* —
        // username `realm`, password whatever the realm string was — which is
        // an account the operator never meant to create. The format would
        // allow a user genuinely called `realm`; refusing that is the price of
        // not creating one by accident, and it is the cheaper mistake.
        if account.name == "realm" {
            return Err(AdapterError::InvalidArgument(
                "basic_auth".into(),
                "`realm` is the second argument, not a block line: write                  `basic_auth bcrypt \"Your Realm\" { … }`. A block line named `realm` would                  otherwise define an account called `realm`"
                    .into(),
            ));
        }
        let [password] = account.args.as_slice() else {
            return Err(AdapterError::InvalidArgument(
                "basic_auth".into(),
                format!(
                    "account `{}` needs exactly one hashed password, got {}",
                    account.name,
                    account.args.len()
                ),
            ));
        };
        if account.name.is_empty() || password.is_empty() {
            return Err(AdapterError::InvalidArgument(
                "basic_auth".into(),
                "username and password cannot be empty".into(),
            ));
        }
        config
            .credentials
            .push((account.name.clone(), password.clone()));
    }

    if config.credentials.is_empty() {
        return Err(AdapterError::InvalidArgument(
            "basic_auth".into(),
            "at least one credential pair is required".into(),
        ));
    }

    Ok(Handler::BasicAuth(config))
}

// MARK: - respond Full Parsing

/// Adapt `respond` directive: `respond ["body"] [status_code]`
///
/// Caddy allows multiple forms:
///   respond "body" 403
///   respond 404
///   respond "body"
pub(super) fn adapt_respond(d: Directive) -> Result<Handler, AdapterError> {
    let mut status: u16 = 200;
    let mut body: Option<Expr> = None;

    match d.args.len() {
        // 🚫 Nothing left to respond with. By the time this runs any matcher
        // token has been stripped, so this covers a bare `respond` and the
        // matcher-only forms `respond /health` and `respond @api` alike.
        //
        // It used to mean "200 with an empty body", which is a guess wearing a
        // default's clothes. `respond /health` has two readings — match
        // `/health` and answer empty, or answer with the text `/health` — and
        // this project has now shipped both of them. Refusing is the third
        // answer and the only honest one: an operator who wants an empty 200
        // says so with `respond 200`, and one who meant to type a body finds
        // out at load instead of in production.
        0 => {
            return Err(AdapterError::InvalidArgument(
                d.name.clone(),
                "needs a status code, a body, or both (`respond 200`, \
                 `respond \"ok\"`, `respond \"nope\" 403`)"
                    .into(),
            ));
        }
        1 => {
            let arg = &d.args[0];
            if let Ok(code) = arg.parse::<u16>() {
                status = code;
            } else {
                body = Some(Expr::String(arg.clone()));
            }
        }
        2 => {
            // respond "body" 403  OR  respond 403 "body"
            if let Ok(code) = d.args[1].parse::<u16>() {
                body = Some(Expr::String(d.args[0].clone()));
                status = code;
            } else if let Ok(code) = d.args[0].parse::<u16>() {
                status = code;
                body = Some(Expr::String(d.args[1].clone()));
            } else {
                body = Some(Expr::String(d.args[0].clone()));
            }
        }
        _ => {
            // First arg is body, last arg might be status
            body = Some(Expr::String(d.args[0].clone()));
            if let Some(last) = d.args.last()
                && let Ok(code) = last.parse::<u16>()
            {
                status = code;
            }
        }
    }

    Ok(Handler::Respond(ResponseConfig {
        status,
        body,
        headers: Default::default(),
    }))
}

// MARK: - error Directive Adapter

/// Adapt Caddy `error` directive: `error [<status> [<message>]]`.
///
/// The grammar is the one upstream parses: a lone three-digit number is the
/// status, a lone word is the message with status 500, and two arguments are
/// message then status. A block may add `message <text…>` when no positional
/// message was given.
pub(super) fn adapt_error_directive(d: &Directive) -> Result<Handler, AdapterError> {
    let mut status: u16 = 500;
    let mut message: Option<String> = None;

    match d.args.as_slice() {
        [] => {}
        [arg] => {
            if arg.len() == 3
                && let Ok(code) = arg.parse::<u16>()
                && (100..=599).contains(&code)
            {
                status = code;
            } else {
                message = Some(arg.clone());
            }
        }
        [message_arg, status_arg] => {
            let Ok(code) = status_arg.parse::<u16>() else {
                return Err(AdapterError::InvalidArgument(
                    "error".into(),
                    format!("`{status_arg}` is not a numeric status code"),
                ));
            };
            if !(100..=599).contains(&code) {
                return Err(AdapterError::InvalidArgument(
                    "error".into(),
                    format!("status code {code} is outside 100..=599"),
                ));
            }
            message = Some(message_arg.clone());
            status = code;
        }
        _ => {
            return Err(AdapterError::ArgumentCount("error".into(), 2, d.args.len()));
        }
    }

    if let Some(block) = &d.block {
        for sub in &block.directives {
            match sub.name.as_str() {
                "message" => {
                    if message.is_some() {
                        return Err(AdapterError::InvalidArgument(
                            "error".into(),
                            "message already specified".into(),
                        ));
                    }
                    if sub.args.is_empty() {
                        return Err(AdapterError::ArgumentCount("error message".into(), 1, 0));
                    }
                    message = Some(sub.args.join(" "));
                }
                other => {
                    return Err(AdapterError::UnknownDirective(format!("error: {other}")));
                }
            }
        }
    }

    Ok(Handler::Error(ErrorConfig { status, message }))
}

// MARK: - header Directive Adapter

/// Adapt Caddy `header` directive which can be:
/// - `header @matcher Key "Value"` (set a header conditionally)
/// - `header { -Server; Key "Value" }` (block form with set/remove)
/// - `header -Server` (inline remove, prefix `-`)
pub(super) fn adapt_header_directive(d: &Directive) -> Result<Handler, AdapterError> {
    let mut config = HeadersConfig::default();

    if let Some(block) = &d.block {
        for sub in &block.directives {
            if sub.name.starts_with('-') {
                // `-Header` → remove
                config.remove.push(sub.name[1..].to_string());
            } else if sub.name.starts_with('+') {
                // `+Header Value` → add
                if let Some(val) = sub.args.first() {
                    config.add.insert(sub.name[1..].to_string(), val.clone());
                }
            } else {
                // `Header Value` → set
                if let Some(val) = sub.args.first() {
                    config.set.insert(sub.name.clone(), val.clone());
                }
            }
        }
    } else {
        // Inline form: `header @matcher Key "Value"` or `header -Server`
        // Skip @matcher argument
        let args: Vec<&String> = d.args.iter().filter(|a| !a.starts_with('@')).collect();

        if let Some(key) = args.first() {
            if let Some(stripped) = key.strip_prefix('-') {
                config.remove.push(stripped.to_string());
            } else if let Some(val) = args.get(1) {
                config.set.insert((*key).clone(), (*val).clone());
            } else {
                // 🚩 `header X-Only` used to compile into an empty header
                // operation: no set, no remove, no add. A header key without
                // a value is either a typo or a request to remove — make the
                // author say which.
                return Err(AdapterError::ArgumentCount("header".into(), 2, args.len()));
            }
        }
    }

    Ok(Handler::Headers(config))
}

/// 🧱 Adapts one fail-closed downstream resource-limit block.
pub(super) fn adapt_resource_limits(
    directive: &Directive,
) -> Result<ResourceLimitsConfig, AdapterError> {
    if !directive.args.is_empty() {
        return Err(AdapterError::ArgumentCount(
            "limits".into(),
            0,
            directive.args.len(),
        ));
    }
    let block = directive
        .block
        .as_ref()
        .ok_or_else(|| AdapterError::InvalidArgument("limits".into(), "block required".into()))?;
    let mut limits = ResourceLimitsConfig::default();
    for sub in &block.directives {
        match sub.name.as_str() {
            "header_timeout" => {
                limits.header_timeout_ms = Some(parse_required_duration(sub)?);
            }
            "body_timeout" => {
                limits.body_timeout_ms = Some(parse_required_duration(sub)?);
            }
            "idle_timeout" => {
                limits.idle_timeout_ms = Some(parse_required_duration(sub)?);
            }
            "request_timeout" => {
                limits.request_timeout_ms = Some(parse_required_duration(sub)?);
            }
            "max_headers" => {
                limits.max_header_count = Some(parse_positive_usize(sub)?);
            }
            "max_header_bytes" => {
                limits.max_header_bytes = Some(parse_positive_usize(sub)?);
            }
            "max_connections" => {
                limits.max_connections = Some(parse_positive_usize(sub)?);
            }
            "upload_bytes_per_sec" => {
                limits.upload_bytes_per_sec = Some(parse_positive_u64(sub)?);
            }
            "download_bytes_per_sec" => {
                limits.download_bytes_per_sec = Some(parse_positive_u64(sub)?);
            }
            "long_connections" => {
                limits.long_connections = adapt_long_connection_limits(sub)?;
            }
            _ => {
                return Err(AdapterError::UnknownDirective(format!(
                    "limits: {}",
                    sub.name
                )));
            }
        }
    }
    Ok(limits)
}

/// 🌊 Adapts long-connection overrides, where `off` deliberately removes a deadline.
pub(super) fn adapt_long_connection_limits(
    directive: &Directive,
) -> Result<LongConnectionLimits, AdapterError> {
    if !directive.args.is_empty() {
        return Err(AdapterError::ArgumentCount(
            "long_connections".into(),
            0,
            directive.args.len(),
        ));
    }
    let block = directive.block.as_ref().ok_or_else(|| {
        AdapterError::InvalidArgument("long_connections".into(), "block required".into())
    })?;
    let mut limits = LongConnectionLimits::default();
    for sub in &block.directives {
        let value = sub
            .args
            .first()
            .ok_or_else(|| AdapterError::ArgumentCount(sub.name.clone(), 1, sub.args.len()))?;
        if sub.args.len() != 1 {
            return Err(AdapterError::ArgumentCount(
                sub.name.clone(),
                1,
                sub.args.len(),
            ));
        }
        let millis = if matches!(value.as_str(), "off" | "none") {
            0
        } else {
            parse_duration_ms(value)
                .filter(|millis| *millis > 0 && *millis <= 31_536_000_000)
                .ok_or_else(|| AdapterError::InvalidArgument(sub.name.clone(), value.clone()))?
        };
        match sub.name.as_str() {
            "idle_timeout" => limits.idle_timeout_ms = Some(millis),
            "request_timeout" => limits.request_timeout_ms = Some(millis),
            _ => {
                return Err(AdapterError::UnknownDirective(format!(
                    "long_connections: {}",
                    sub.name
                )));
            }
        }
    }
    Ok(limits)
}
