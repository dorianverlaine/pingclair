// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

use super::AdapterError;
use super::args::{
    expect_no_arguments, expect_one_argument, parse_duration_ms, parse_positive_u64,
    parse_positive_usize, parse_required_duration,
};
use super::reverse_proxy::adapt_reverse_proxy;
use crate::parser::ast::*;
use crate::parser::caddy_ast::Directive;

// MARK: - Handler Adaptation

pub(super) fn adapt_handler(d: Directive) -> Result<Handler, AdapterError> {
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
        "handle" => {
            // `handle { ... }` inside another handle — nested exclusive routing
            let mut handlers = Vec::new();
            if let Some(block) = d.block {
                for inner_d in block.directives {
                    if inner_d.name.starts_with('@') {
                        // TODO(v0.3): support matcher tokens on directives
                        // inside route/handle blocks (needs per-handler
                        // conditional execution in the runtime chain).
                        return Err(AdapterError::UnsupportedFeature(
                            "route/handle matcher token".into(),
                            "matcher tokens inside route/handle blocks are not \
                             implemented yet"
                                .into(),
                        ));
                    }
                    handlers.push(adapt_handler(inner_d)?);
                }
            }
            Ok(Handler::Handle(handlers))
        }
        "basic_auth" | "basicauth" => adapt_basic_auth(d),
        "rate_limit" => adapt_rate_limit(d),
        "rewrite" => adapt_rewrite(d),
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
            regex: None,
            regex_replace: None,
        })),
        [regex, replacement] => Ok(Handler::Rewrite(RewriteConfig {
            replace: None,
            regex: Some(regex.clone()),
            regex_replace: Some(replacement.clone()),
        })),
        _ => Err(AdapterError::InvalidArgument(
            "rewrite".into(),
            "expected <replacement> or <regex> <replacement>".into(),
        )),
    }
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
/// Supported forms are:
///   basic_auth <user> <password> [<user2> <password2>...]
///   basic_auth {
///       realm "Restricted Area"
///       <user> <password>
///   }
///
/// Password values beginning with a bcrypt marker are validated by the
/// compiler and emitted as hashed credentials.
pub(super) fn adapt_basic_auth(d: Directive) -> Result<Handler, AdapterError> {
    let mut config = BasicAuthConfig {
        realm: None,
        credentials: Vec::new(),
    };

    let mut pairs_from = |args: &[String]| -> Result<(), AdapterError> {
        if !args.len().is_multiple_of(2) {
            return Err(AdapterError::InvalidArgument(
                "basic_auth".into(),
                "credentials must be <user> <password> pairs".into(),
            ));
        }
        for pair in args.chunks(2) {
            config.credentials.push((pair[0].clone(), pair[1].clone()));
        }
        Ok(())
    };

    if let Some(block) = &d.block {
        if !d.args.is_empty() {
            return Err(AdapterError::InvalidArgument(
                "basic_auth".into(),
                "cannot mix inline credentials with a block".into(),
            ));
        }
        for sub in &block.directives {
            if sub.name == "realm" {
                config.realm = sub.args.first().cloned();
            } else {
                pairs_from(
                    &std::iter::once(sub.name.clone())
                        .chain(sub.args.iter().cloned())
                        .collect::<Vec<_>>(),
                )?;
            }
        }
    } else {
        pairs_from(&d.args)?;
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
