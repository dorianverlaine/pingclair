// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧰 The HTTP components: what a route runs.

use super::*;

use super::conditions::{file_candidate, file_candidates, file_policy};

/// 🗂️ `TryFiles(candidates:, root:, policy:)`: rewrite to the first candidate
/// that exists, then stand down so the next component serves it.
///
/// 📌 Lowered exactly the way the Caddyfile's `try_files` is — a first-match
/// group of `file` matcher plus a rewrite to the file the matcher picked. One
/// implementation, so the two spellings cannot drift (that drift is what #21
/// was, and the fix was to delete the second lookup rather than maintain it).
fn try_files(call: &Call) -> Result<HandlerConfig, Error> {
    let files = file_candidates(call)?;
    let root = if call.get("root").is_some() {
        Some(call.string("root")?)
    } else {
        None
    };
    let try_policy = file_policy(call)?;
    // 🧭 A candidate carrying the query gets its own group, because the rewrite
    // target differs; the plain candidates share one. The groups are mutually
    // exclusive, so only the first matching rewrite runs.
    let group = |candidates: Vec<String>, query: &str| HandlerElement {
        matcher: Some(Matcher::File {
            try_files: candidates,
            root: root.clone(),
            try_policy: try_policy.clone(),
            split_path: Vec::new(),
        }),
        handler: HandlerConfig::Rewrite {
            strip_prefix: None,
            strip_suffix: None,
            replace: Some(format!("{{http.matchers.file.relative}}{query}")),
            regex: None,
            regex_replace: None,
            method: None,
        },
    };
    let mut elements = Vec::new();
    let mut plain: Vec<String> = Vec::new();
    for candidate in files {
        match candidate.split_once('?') {
            Some((file, query)) => {
                if !plain.is_empty() {
                    elements.push(group(std::mem::take(&mut plain), ""));
                }
                elements.push(group(vec![file.to_string()], &format!("?{query}")));
            }
            None => plain.push(candidate),
        }
    }
    if !plain.is_empty() {
        elements.push(group(plain, ""));
    }
    Ok(HandlerConfig::FirstMatch { handlers: elements })
}

/// 🔤 The HTTP method one typed `.get`/`.post`/… value names.
pub(super) fn method_name(value: &Call) -> Result<&'static str, Error> {
    if !value.args.is_empty() {
        return Err(value.at.error("a method value takes no arguments"));
    }
    Ok(match value.name.as_str() {
        "get" => "GET",
        "post" => "POST",
        "put" => "PUT",
        "delete" => "DELETE",
        "patch" => "PATCH",
        "head" => "HEAD",
        "options" => "OPTIONS",
        other => {
            return Err(value.at.error(format!(
                "unknown method '.{other}'; expected .get, .post, .put, .delete, .patch, .head or .options"
            )));
        }
    })
}

/// 🔖 One labeled quoted argument, refused when it is missing or mistyped.
fn labeled_string(call: &Call, key: &str) -> Result<String, Error> {
    match call.get(key) {
        Some(Value::String(value)) => Ok(value.clone()),
        _ => Err(call.at.error(format!("{key} requires a quoted string"))),
    }
}

/// 🧰 The HTTP components: terminals that answer, middleware that changes.
pub(super) fn http_handler(call: &Call) -> Result<HandlerConfig, Error> {
    match call.name.as_str() {
        "Respond" => {
            call.leaf(RESPOND_LABELS)?;
            let status = match call.get("status") {
                Some(_) => u16::try_from(call.integer("status")?)
                    .map_err(|_| call.at.error("status must fit in 0..=65535"))?,
                None => 200,
            };
            Ok(HandlerConfig::Respond {
                status,
                body: Some(pingclair_core::config::ConfigText::literal(
                    call.string("body")?,
                )),
                headers: std::collections::BTreeMap::new(),
            })
        }
        "ServeFiles" => serve_files(call),
        "Proxy" => proxy(call),
        "Redirect" => redirect(call),
        "Fail" => fail(call),
        "ServeMetrics" => serve_metrics(call),
        "RequestHeader" => request_headers(call),
        "ResponseHeader" => response_headers(call),
        "Rewrite" => rewrite(call),
        "BasicAuth" => basic_auth(call),
        "TryFiles" => try_files(call),
        "PHPFastCGI" => php_fastcgi(call),
        "Intercept" => intercept(call),
        "RateLimit" => rate_limit(call),
        "AccessControl" => access_control(call),
        "CORS" => cors(call),
        "SetVariable" => set_variable(call),
        "LimitRequestBody" => limit_request_body(call),
        "SkipLog" => skip_log(call),
        "Templates" => templates(call),
        "ForwardAuth" => forward_auth(call),
        "ACMEServer" => acme_server(call),
        _ => Err(call.at.error(
            "unknown HTTP component; expected a terminal (Respond, ServeFiles, Proxy, Redirect, \
             Fail, ServeMetrics, ACMEServer) or middleware (RequestHeader, ResponseHeader, \
             Rewrite, BasicAuth, RateLimit, AccessControl, CORS, SetVariable, LimitRequestBody, \
             SkipLog, Templates, ForwardAuth, TryFiles, Intercept, PHPFastCGI)",
        )),
    }
}

/// 🧭 `Intercept { … }`: response handlers for whatever the later components
/// answer with.
///
/// 📌 The entries are an ordered list, and each one is an ordinary component
/// name with a response matcher: `when:` here asks about the *response*, which
/// is why it takes `.status(...)` and `.header(...)` rather than the request
/// conditions a `Route(when:)` takes.
fn intercept(call: &Call) -> Result<HandlerConfig, Error> {
    call.labels(&[])?;
    call.no_modifiers()?;
    let body = call.block()?;
    if body.is_empty() {
        return Err(call
            .at
            .error("Intercept needs at least one response handler"));
    }
    let mut handlers = Vec::new();
    for (index, child) in body.iter().enumerate() {
        let entry = response_handler(child)?;
        // 🚫 An entry with no `when:` matches every response, so anything
        // written after it can never run. The Caddyfile sorts such entries
        // last; this language refuses the order instead of repairing it.
        if entry.matcher.is_none() && index + 1 != body.len() {
            return Err(child.at.error(
                "an entry with no when: matches every response, so the entries after it can \
                 never run; move it to the end",
            ));
        }
        handlers.push(entry);
    }
    Ok(HandlerConfig::Intercept { handlers })
}

/// 🧭 One entry of an `Intercept` block: a response shape and what to do with
/// it.
///
/// 📌 The handlers live in a group because an entry is not always one handler.
/// `CopyResponseHeaders` is the case that forced it: it only says which of the
/// upstream's headers ride along onto a *replacement* response, so on its own
/// it changes nothing a client can see. Writing it beside the handler that
/// replaces the response is the only way it means something.
fn response_handler(call: &Call) -> Result<ResponseHandlerConfig, Error> {
    if call.name != "Response" {
        return Err(call.at.error(format!(
            "unknown Intercept entry '{}'; expected a Response(when: …) block",
            call.name
        )));
    }
    if call
        .args
        .iter()
        .any(|(label, _)| label.as_deref() != Some("when"))
    {
        return Err(call
            .at
            .error("Response takes only when:; its handlers go in the block"));
    }
    call.no_modifiers()?;
    let matcher = response_matcher(call)?;
    let body = call.block()?;
    if body.is_empty() {
        return Err(call
            .at
            .error("Response needs at least one handler, such as Respond or ReplaceStatus"));
    }
    let mut status_code = None;
    let mut handlers = Vec::new();
    for child in body {
        match child.name.as_str() {
            // 🔢 Answer with a different status, keeping the body.
            "ReplaceStatus" => {
                if status_code.is_some() || !handlers.is_empty() {
                    return Err(child.at.error(
                        "ReplaceStatus is the whole entry: it answers with another status and \
                         nothing else runs",
                    ));
                }
                child.leaf(&["status"])?;
                let status = u16::try_from(child.integer("status")?)
                    .map_err(|_| child.at.error("status must fit in 0..=65535"))?;
                status_code = Some(status.to_string());
            }
            // 💬 Answer with a body this configuration wrote.
            "Respond" => {
                child.leaf(&["body", "status"])?;
                let status = match child.get("status") {
                    Some(_) => u16::try_from(child.integer("status")?)
                        .map_err(|_| child.at.error("status must fit in 0..=65535"))?,
                    None => 200,
                };
                handlers.push(HandlerConfig::Respond {
                    status,
                    // 📌 Optional here, unlike a route's `Respond`: a response
                    // handler that only changes the status is ordinary.
                    body: if child.get("body").is_some() {
                        Some(pingclair_core::config::ConfigText::literal(
                            child.string("body")?,
                        ))
                    } else {
                        None
                    },
                    headers: std::collections::BTreeMap::new(),
                });
            }
            // 📨 Pass the response through, optionally with another status.
            "CopyResponse" => {
                child.leaf(&["status"])?;
                let status_code = if child.get("status").is_some() {
                    Some(
                        u16::try_from(child.integer("status")?)
                            .map_err(|_| child.at.error("status must fit in 0..=65535"))?,
                    )
                } else {
                    None
                };
                handlers.push(HandlerConfig::CopyResponse { status_code });
            }
            // 🏷️ The same `ResponseHeader` component the routes use. It is
            // what edits a response that passes through: `CopyResponse`
            // forwards the upstream's headers untouched, so removing one is a
            // header operation, not a copy policy.
            "ResponseHeader" => handlers.push(response_headers(child)?),
            // 🏷️ Say which of the upstream's headers a *replacement* keeps.
            "CopyResponseHeaders" => {
                child.leaf(&["include", "exclude"])?;
                let include = child.strings("include")?;
                let exclude = child.strings("exclude")?;
                // 🚫 "include wins when both are present" is a rule the reader
                // would have to know; the two lists answer different questions.
                if !include.is_empty() && !exclude.is_empty() {
                    return Err(child
                        .at
                        .error("include: and exclude: are alternatives; pick one"));
                }
                if include.is_empty() && exclude.is_empty() {
                    return Err(child
                        .at
                        .error("CopyResponseHeaders needs include: or exclude:"));
                }
                handlers.push(HandlerConfig::CopyResponseHeaders { include, exclude });
            }
            other => {
                return Err(child.at.error(format!(
                    "unknown response handler '{other}'; expected Respond, ResponseHeader, \
                     ReplaceStatus, CopyResponse or CopyResponseHeaders"
                )));
            }
        }
    }
    Ok(ResponseHandlerConfig {
        matcher,
        status_code,
        handlers,
    })
}

/// 🧭 `when:` inside an `Intercept` block: a matcher over the response.
fn response_matcher(call: &Call) -> Result<Option<ResponseMatcher>, Error> {
    let Some(value) = call.get("when") else {
        return Ok(None);
    };
    let Value::Typed(value) = value else {
        return Err(call
            .at
            .error("when: takes a typed response condition such as .status(.serverError)"));
    };
    let mut matcher = ResponseMatcher::default();
    match value.name.as_str() {
        // 🚦 Codes and classes in one list, exactly the two things the model
        // stores: a three-digit code, or a one-digit class.
        "status" => {
            if value.args.is_empty() {
                return Err(value.at.error("status needs at least one code or class"));
            }
            for (label, item) in &value.args {
                if label.is_some() {
                    return Err(value.at.error("status takes unlabeled codes and classes"));
                }
                let code = match item {
                    Value::Number(code) => {
                        let code = u16::try_from(*code)
                            .map_err(|_| value.at.error("status must fit in 0..=65535"))?;
                        if !(100..=599).contains(&code) {
                            return Err(value
                                .at
                                .error("a status code is 100..=599; write .serverError for 5xx"));
                        }
                        code
                    }
                    Value::Typed(class) => match class.name.as_str() {
                        "informational" => 1,
                        "success" => 2,
                        "redirect" => 3,
                        "clientError" => 4,
                        "serverError" => 5,
                        other => {
                            return Err(class.at.error(format!(
                                "unknown status class '.{other}'; expected .informational, \
                                 .success, .redirect, .clientError or .serverError"
                            )));
                        }
                    },
                    _ => {
                        return Err(value.at.error("status takes codes and class values"));
                    }
                };
                if !matcher.status_codes.contains(&code) {
                    matcher.status_codes.push(code);
                }
            }
        }
        // 🏷️ A header the response carries. `exists: true` is the model's `*`
        // pattern; a value may use `*` as the model's own wildcard.
        "header" => {
            value.leaf(&["name", "value", "exists"])?;
            let name = value.string("name")?;
            let pattern = if value.get("exists").is_some() {
                if !value.boolean("exists")? {
                    return Err(value.at.error(
                        "a response matcher cannot say a header is absent; match the responses \
                         you want instead",
                    ));
                }
                "*".to_string()
            } else {
                value.string("value")?
            };
            matcher.headers.entry(name).or_default().push(pattern);
        }
        other => {
            return Err(value.at.error(format!(
                "unknown response condition '.{other}'; expected .status(...) or .header(...)"
            )));
        }
    }
    Ok(Some(matcher))
}

/// 🏷️ The argument labels `templates` accepts, named once for the parser and `describe`.
pub(crate) const TEMPLATES_LABELS: &[&str] = &["root"];

/// 🧩 `Templates(root:)`: renders the files later components serve.
fn templates(call: &Call) -> Result<HandlerConfig, Error> {
    call.leaf(TEMPLATES_LABELS)?;
    let root = if call.get("root").is_some() {
        Some(call.string("root")?)
    } else {
        None
    };
    Ok(HandlerConfig::Templates { root })
}

/// 🏷️ The argument labels `forward_auth` accepts, named once for the parser and `describe`.
pub(crate) const FORWARD_AUTH_LABELS: &[&str] = &["to", "uri", "copyHeaders"];

/// 🔐 `ForwardAuth(to:, uri:, copyHeaders:)`: one auth round trip up front.
fn forward_auth(call: &Call) -> Result<HandlerConfig, Error> {
    call.leaf(FORWARD_AUTH_LABELS)?;
    let upstream = call.string("to")?;
    let uri = call.string("uri")?;
    let mut copy_headers: Vec<ForwardAuthHeaderMap> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let copied: &[Value] = match call.get("copyHeaders") {
        None => &[],
        Some(Value::Array(items)) => {
            if items.is_empty() {
                return Err(call
                    .at
                    .error("copyHeaders must not be empty; leave it out instead"));
            }
            items
        }
        Some(_) => {
            return Err(call.at.error(
                "copyHeaders takes an array of field names and .rename(\"From\", to: \"To\") values",
            ));
        }
    };
    for item in copied {
        let (from, to) = match item {
            Value::String(field) => (field.clone(), None),
            Value::Typed(rename) if rename.name == "rename" => {
                let [(None, Value::String(from)), rest @ ..] = rename.args.as_slice() else {
                    return Err(rename.at.error(".rename takes a field name and to: \"…\""));
                };
                if rest.len() != 1 {
                    return Err(rename.at.error(".rename takes a field name and to: \"…\""));
                }
                (from.clone(), Some(labeled_string(rename, "to")?))
            }
            _ => {
                return Err(call.at.error(
                    "copyHeaders takes field names and .rename(\"From\", to: \"To\") values",
                ));
            }
        };
        if !seen.insert(from.clone()) {
            return Err(call.at.error(format!("'{from}' is copied twice")));
        }
        copy_headers.push(ForwardAuthHeaderMap { from, to });
    }
    let config = ForwardAuthConfig {
        upstream,
        uri,
        copy_headers,
        upstream_tls: None,
    };
    Ok(HandlerConfig::ReverseProxy(Box::new(
        config.as_reverse_proxy_subrequest(),
    )))
}

/// 🏛️ `ACMEServer(ca:, lifetime:, signWithRoot:, challenges:, allow:, deny:)`.
///
/// 📌 Written for parity with the Caddyfile spelling: the runtime refuses to
/// start a site that carries one, so this parses, validates and serialises, and
/// 🏷️ The argument labels `acme_server` accepts, named once for the parser and `describe`.
pub(crate) const ACME_SERVER_LABELS: &[&str] = &[
    "ca",
    "lifetime",
    "signWithRoot",
    "challenges",
    "allow",
    "deny",
];

/// the refusal to run stays where it always was.
fn acme_server(call: &Call) -> Result<HandlerConfig, Error> {
    call.leaf(ACME_SERVER_LABELS)?;
    let ca = if call.get("ca").is_some() {
        Some(call.string("ca")?)
    } else {
        None
    };
    let lifetime_secs = if call.get("lifetime").is_some() {
        let millis = call.measure("lifetime", false)?;
        if millis == 0 || millis % 1000 != 0 {
            return Err(call.at.error("lifetime is at least one whole second"));
        }
        Some(millis / 1000)
    } else {
        None
    };
    let sign_with_root = if call.get("signWithRoot").is_some() {
        call.boolean("signWithRoot")?
    } else {
        false
    };
    let challenges = match call.get("challenges") {
        None => None,
        Some(_) => Some(call.strings("challenges")?),
    };
    Ok(HandlerConfig::AcmeServer(Box::new(AcmeServerConfig {
        ca,
        lifetime_secs,
        sign_with_root,
        challenges,
        allow: acme_policy(call, "allow")?,
        deny: acme_policy(call, "deny")?,
    })))
}

/// 🧭 One `allow:`/`deny:` policy: the names and networks a server issues for.
fn acme_policy(call: &Call, key: &str) -> Result<Option<AcmeServerPolicy>, Error> {
    let Some(value) = call.get(key) else {
        return Ok(None);
    };
    let Value::Typed(policy) = value else {
        return Err(call
            .at
            .error(format!("{key} takes .policy(domains:, ipRanges:)")));
    };
    if policy.name != "policy" {
        return Err(policy.at.error(format!(
            "unknown {key} policy '.{}'; expected .policy(domains:, ipRanges:)",
            policy.name
        )));
    }
    policy.leaf(&["domains", "ipRanges"])?;
    let domains = policy.strings("domains")?;
    let ip_ranges = policy.strings("ipRanges")?;
    if domains.is_empty() && ip_ranges.is_empty() {
        return Err(policy
            .at
            .error("a policy needs at least one domain or IP range"));
    }
    Ok(Some(AcmeServerPolicy { domains, ip_ranges }))
}

/// 🏷️ The argument labels `basic_auth` accepts, named once for the parser and `describe`.
pub(crate) const BASIC_AUTH_LABELS: &[&str] = &["users", "algorithm", "realm"];

/// 🔐 `BasicAuth(users:, algorithm:, realm:)`: one guard, many credentials.
fn basic_auth(call: &Call) -> Result<HandlerConfig, Error> {
    call.leaf(BASIC_AUTH_LABELS)?;
    let algorithm = match call.get("algorithm") {
        None => BasicAuthAlgorithm::Bcrypt,
        Some(Value::Typed(value)) => {
            if !value.args.is_empty() {
                return Err(value.at.error("an algorithm takes no arguments"));
            }
            match value.name.as_str() {
                "bcrypt" => BasicAuthAlgorithm::Bcrypt,
                "argon2id" => BasicAuthAlgorithm::Argon2id,
                other => {
                    return Err(value.at.error(format!(
                        "unknown algorithm '.{other}'; expected .bcrypt or .argon2id"
                    )));
                }
            }
        }
        Some(_) => return Err(call.at.error("algorithm takes .bcrypt or .argon2id")),
    };
    let realm = if call.get("realm").is_some() {
        call.string("realm")?
    } else {
        pingclair_core::config::default_auth_realm()
    };
    let Some(Value::Array(users)) = call.get("users") else {
        return Err(call
            .at
            .error("users takes an array of .user(\"name\", hash: \"…\") values"));
    };
    if users.is_empty() {
        return Err(call.at.error("users needs at least one entry"));
    }
    let mut seen = std::collections::HashSet::new();
    let mut credentials = Vec::new();
    for user in users {
        let Value::Typed(user) = user else {
            return Err(call
                .at
                .error("users takes .user(\"name\", hash: \"…\") values"));
        };
        if user.name != "user" {
            return Err(user
                .at
                .error("users takes .user(\"name\", hash: \"…\") values"));
        }
        let [(None, Value::String(name)), rest @ ..] = user.args.as_slice() else {
            return Err(user.at.error(".user takes a name and hash: \"…\""));
        };
        if rest.len() != 1 {
            return Err(user.at.error(".user takes a name and hash: \"…\""));
        }
        if !seen.insert(name.clone()) {
            return Err(user.at.error(format!("'{name}' appears twice in users")));
        }
        // 🔑 The hash is checked against the declared algorithm here, exactly
        // as the Caddyfile path does: a plaintext password must fail at load,
        // never at the first login attempt.
        let credential = crate::compiler::compile_basic_auth_credential(
            name,
            &labeled_string(user, "hash")?,
            algorithm,
        )
        .map_err(|error| user.at.error(error.to_string()))?;
        credentials.push(credential);
    }
    Ok(HandlerConfig::BasicAuth { realm, credentials })
}

/// 🏷️ The argument labels `rate_limit` accepts, named once for the parser and `describe`.
pub(crate) const RATE_LIMIT_LABELS: &[&str] = &["requests", "per", "key", "burst", "dryRun"];

/// ⏱️ `RateLimit(requests:, per:, key:, burst:, dryRun:)`.
fn rate_limit(call: &Call) -> Result<HandlerConfig, Error> {
    call.leaf(RATE_LIMIT_LABELS)?;
    let Some(_) = call.get("requests") else {
        return Err(call.at.error("RateLimit requires requests:"));
    };
    let requests = call.integer("requests")?;
    if requests == 0 {
        return Err(call.at.error("requests must be at least 1"));
    }
    let Some(_) = call.get("per") else {
        return Err(call
            .at
            .error("RateLimit requires per:, such as per: .minutes(1)"));
    };
    let window_ms = call.measure("per", false)?;
    if window_ms % 1000 != 0 {
        return Err(call.at.error("a rate limit window is whole seconds"));
    }
    let window_secs = window_ms / 1000;
    if window_secs == 0 {
        return Err(call.at.error("a rate limit window is at least one second"));
    }
    let key = match call.get("key") {
        None => RateLimitKey::Ip,
        Some(Value::Typed(value)) => {
            let argument = |value: &Call| -> Result<String, Error> {
                let [(None, Value::String(name))] = value.args.as_slice() else {
                    return Err(value
                        .at
                        .error(format!(".{} takes one quoted header name", value.name)));
                };
                Ok(name.clone())
            };
            match value.name.as_str() {
                kind @ ("ip" | "global" | "route" | "apiKey") => {
                    value.leaf(&[])?;
                    match kind {
                        "ip" => RateLimitKey::Ip,
                        "global" => RateLimitKey::Global,
                        "route" => RateLimitKey::Route,
                        _ => RateLimitKey::ApiKey,
                    }
                }
                "header" => RateLimitKey::Header(argument(value)?),
                "tenant" => RateLimitKey::Tenant(argument(value)?),
                other => {
                    return Err(value.at.error(format!(
                        "unknown rate limit key '.{other}'; expected .ip, .global, .route, \
                         .apiKey, .header(\"X-Name\") or .tenant(\"X-Name\")"
                    )));
                }
            }
        }
        Some(_) => {
            return Err(call
                .at
                .error("key takes a typed value such as .ip or .header(\"X-Tenant-ID\")"));
        }
    };
    let burst = if call.get("burst").is_some() {
        call.integer("burst")?
    } else {
        0
    };
    let dry_run = if call.get("dryRun").is_some() {
        call.boolean("dryRun")?
    } else {
        false
    };
    Ok(HandlerConfig::RateLimit {
        requests,
        window_secs,
        // 🔑 Kept for documents written before the key was a field; the key
        // itself is what the runtime reads.
        by_ip: matches!(key, RateLimitKey::Ip),
        burst,
        key: Some(key),
        dry_run,
    })
}

/// 🏷️ The argument labels `access_control` accepts, named once for the parser and `describe`.
pub(crate) const ACCESS_CONTROL_LABELS: &[&str] = &[
    "allowedIPs",
    "deniedIPs",
    "allowedReferers",
    "deniedReferers",
    "allowedUserAgents",
    "deniedUserAgents",
];

/// 🛡️ `AccessControl(...)`: allow and deny rules ahead of the terminal.
fn access_control(call: &Call) -> Result<HandlerConfig, Error> {
    call.leaf(ACCESS_CONTROL_LABELS)?;
    if call.args.is_empty() {
        return Err(call
            .at
            .error("AccessControl needs at least one rule; a rule-less guard guards nothing"));
    }
    Ok(HandlerConfig::AccessControl(AccessControlConfig {
        allowed_ips: call.strings("allowedIPs")?,
        denied_ips: call.strings("deniedIPs")?,
        allowed_referers: call.strings("allowedReferers")?,
        denied_referers: call.strings("deniedReferers")?,
        allowed_user_agents: call.strings("allowedUserAgents")?,
        denied_user_agents: call.strings("deniedUserAgents")?,
    }))
}

/// 🏷️ The argument labels `cors` accepts, named once for the parser and `describe`.
pub(crate) const CORS_LABELS: &[&str] = &[
    "origins",
    "methods",
    "headers",
    "exposedHeaders",
    "allowCredentials",
    "maxAge",
];

/// 🌐 `CORS(origins:, methods:, headers:, exposedHeaders:, allowCredentials:, maxAge:)`.
fn cors(call: &Call) -> Result<HandlerConfig, Error> {
    call.leaf(CORS_LABELS)?;
    let Some(Value::Array(origins)) = call.get("origins") else {
        return Err(call.at.error("CORS requires origins: [...]"));
    };
    let mut allowed_origins = Vec::new();
    for origin in origins {
        let Value::String(origin) = origin else {
            return Err(call.at.error("origins takes quoted origins"));
        };
        allowed_origins.push(origin.clone());
    }
    if allowed_origins.is_empty() {
        return Err(call.at.error("origins needs at least one origin"));
    }
    let allowed_methods = match call.get("methods") {
        None => pingclair_core::config::default_cors_methods(),
        Some(Value::Array(methods)) => {
            if methods.is_empty() {
                return Err(call.at.error("methods must not be empty"));
            }
            let mut names = Vec::new();
            for method in methods {
                let Value::Typed(value) = method else {
                    return Err(call
                        .at
                        .error("methods takes unlabeled .get/.post/... values"));
                };
                names.push(method_name(value)?.to_string());
            }
            names
        }
        Some(_) => {
            return Err(call
                .at
                .error("methods takes an array of .get/.post/... values"));
        }
    };
    let allowed_headers = match call.get("headers") {
        None => pingclair_core::config::default_cors_headers(),
        Some(_) => call.strings("headers")?,
    };
    let exposed_headers = call.strings("exposedHeaders")?;
    let allow_credentials = if call.get("allowCredentials").is_some() {
        call.boolean("allowCredentials")?
    } else {
        false
    };
    let max_age = if call.get("maxAge").is_some() {
        let max_age_ms = call.measure("maxAge", false)?;
        if max_age_ms % 1000 != 0 {
            return Err(call.at.error("maxAge is whole seconds"));
        }
        max_age_ms / 1000
    } else {
        pingclair_core::config::default_cors_max_age()
    };
    Ok(HandlerConfig::Cors {
        allowed_origins,
        allowed_methods,
        allowed_headers,
        exposed_headers,
        allow_credentials,
        max_age,
    })
}

/// 🏷️ The argument labels `set_variable` accepts, named once for the parser and `describe`.
pub(crate) const SET_VARIABLE_LABELS: &[&str] = &["name", "value"];

/// 🧰 `SetVariable(name:, value:)`: one request-scoped variable.
fn set_variable(call: &Call) -> Result<HandlerConfig, Error> {
    call.leaf(SET_VARIABLE_LABELS)?;
    let name = call.string("name")?;
    // 📌 An empty value is a value: it clears a variable a site-level rule
    // set, which is a thing an operator really does write.
    let value = call.string("value")?;
    let mut values = std::collections::BTreeMap::new();
    values.insert(name, value);
    Ok(HandlerConfig::Vars { values })
}

/// 🏷️ The argument labels `limit_request_body` accepts, named once for the parser and `describe`.
pub(crate) const LIMIT_BODY_LABELS: &[&str] = &["max", "readTimeout", "writeTimeout", "set"];

/// 📥 `LimitRequestBody(max:, readTimeout:, writeTimeout:, set:)`.
fn limit_request_body(call: &Call) -> Result<HandlerConfig, Error> {
    call.leaf(LIMIT_BODY_LABELS)?;
    if call.args.is_empty() {
        return Err(call.at.error(
            "LimitRequestBody needs at least one of max:, readTimeout:, writeTimeout: or set:",
        ));
    }
    let max_size = if call.get("max").is_some() {
        Some(call.measure("max", true)?)
    } else {
        None
    };
    let read_timeout_ms = if call.get("readTimeout").is_some() {
        Some(call.measure("readTimeout", false)?)
    } else {
        None
    };
    let write_timeout_ms = if call.get("writeTimeout").is_some() {
        Some(call.measure("writeTimeout", false)?)
    } else {
        None
    };
    let set = match call.get("set") {
        None => None,
        Some(Value::String(body)) if body.is_empty() => {
            return Err(call
                .at
                .error("set: \"\" would replace the body with nothing; leave set: out instead"));
        }
        Some(Value::String(body)) => Some(body.clone()),
        Some(_) => return Err(call.at.error("set requires a quoted string")),
    };
    Ok(HandlerConfig::RequestBody {
        max_size,
        read_timeout_ms,
        write_timeout_ms,
        set,
    })
}

/// 🙈 `SkipLog()`: this request is left out of the access log.
fn skip_log(call: &Call) -> Result<HandlerConfig, Error> {
    call.leaf(&[])?;
    Ok(HandlerConfig::LogSkip)
}

/// 🏷️ The header operations one component carries, in writing order.
#[derive(Default)]
struct HeaderOps {
    set: std::collections::BTreeMap<String, String>,
    add: std::collections::BTreeMap<String, Vec<String>>,
    remove: Vec<String>,
    replace: Vec<HeaderReplacement>,
    set_if_absent: std::collections::BTreeMap<String, String>,
}

/// 🏷️ `RequestHeader(...)`: rewrites the request later handlers read.
fn request_headers(call: &Call) -> Result<HandlerConfig, Error> {
    let ops = header_ops(call, false)?;
    Ok(HandlerConfig::RequestHeaders {
        set: ops.set,
        add: ops.add,
        remove: ops.remove,
        replace: ops.replace,
    })
}

/// 🏷️ `ResponseHeader(...)`: rewrites the response on its way to the client.
fn response_headers(call: &Call) -> Result<HandlerConfig, Error> {
    let ops = header_ops(call, true)?;
    Ok(HandlerConfig::Headers {
        set: ops.set,
        add: ops.add,
        remove: ops.remove,
        replace: ops.replace,
        default_set: ops.set_if_absent,
        require: None,
    })
}

/// 🏷️ Reads the action list both header components share.
///
/// One reader because the two components differ in *which message* they edit,
/// never in how an action is written — two readers would be two chances to
/// disagree, which is exactly how the Caddyfile's `?` prefix once reached the
/// request side of a format that refuses it.
fn header_ops(call: &Call, response_side: bool) -> Result<HeaderOps, Error> {
    if call.body.is_some() {
        return Err(call.at.error(format!(
            "{} does not take a block; write one action per call",
            call.name
        )));
    }
    call.no_modifiers()?;
    if call.args.is_empty() {
        return Err(call.at.error(format!(
            "{} needs at least one action such as .set(\"X-Name\", \"value\")",
            call.name
        )));
    }
    header_ops_from(&call.args, &call.name, call.at, response_side)
}

/// 🏷️ Reads one list of header actions, whoever is holding it.
///
/// 📌 Two holders: the `RequestHeader`/`ResponseHeader` components, whose own
/// arguments *are* the list, and a proxy's `headersUp:`/`headersDown:`, which
/// carry it as a labelled array. One reader, so an action means the same thing
/// in both places — the Caddyfile has one `applyHeaderOp` for the same reason.
fn header_ops_from(
    actions: &[(Option<String>, Value)],
    name: &str,
    at: Position,
    response_side: bool,
) -> Result<HeaderOps, Error> {
    let mut ops = HeaderOps::default();
    let mut claimed = std::collections::HashSet::new();
    for (label, value) in actions {
        let (None, Value::Typed(action)) = (label, value) else {
            return Err(at.error(format!(
                "{name} takes unlabeled actions such as .set(\"X-Name\", \"value\")"
            )));
        };
        match action.name.as_str() {
            "set" => {
                let (field, value) = header_pair(action)?;
                claim_once(&mut claimed, &field, name, at)?;
                ops.set.insert(field, value);
            }
            "setIfAbsent" => {
                if !response_side {
                    return Err(action.at.error(
                        "setIfAbsent inspects the finished response; a request header has nothing to inspect yet",
                    ));
                }
                let (field, value) = header_pair(action)?;
                claim_once(&mut claimed, &field, name, at)?;
                ops.set_if_absent.insert(field, value);
            }
            // 📋 Repeating this action is the point: two cookies are two
            // values of one field, and folding them into one line is the bug
            // RFC 6265 §3 forbids.
            "append" => {
                let (field, value) = header_pair(action)?;
                ops.add.entry(field).or_default().push(value);
            }
            "remove" => {
                let [(None, Value::String(field))] = action.args.as_slice() else {
                    return Err(action.at.error("remove takes one quoted field name"));
                };
                ops.remove.push(field.clone());
            }
            "replace" => {
                let [(None, Value::String(field)), rest @ ..] = action.args.as_slice() else {
                    return Err(action
                        .at
                        .error("replace takes a field name, pattern: and with:"));
                };
                if rest.len() != 2 {
                    return Err(action
                        .at
                        .error("replace takes a field name, pattern: and with:"));
                }
                ops.replace.push(HeaderReplacement {
                    field: field.clone(),
                    search_regexp: labeled_string(action, "pattern")?,
                    replace: labeled_string(action, "with")?,
                });
            }
            other => {
                return Err(action.at.error(format!(
                    "unknown header action '.{other}'; expected .set, .append, .remove{} or .replace",
                    if response_side { ", .setIfAbsent" } else { "" }
                )));
            }
        }
    }
    Ok(ops)
}

/// 🏷️ Reads the two unlabeled operands of `.set`/`.append`/`.setIfAbsent`.
fn header_pair(action: &Call) -> Result<(String, String), Error> {
    let [(None, Value::String(field)), (None, Value::String(value))] = action.args.as_slice()
    else {
        return Err(action.at.error(format!(
            ".{} takes a quoted field name and a quoted value",
            action.name
        )));
    };
    Ok((field.clone(), value.clone()))
}

/// 🚫 Refuses a second map-backed action for one field.
///
/// `set` and `setIfAbsent` are stored as maps, so a repeated field would keep
/// one of the two values without saying which. A caller who means to write the
/// field twice can write a second component, where the order is visible.
fn claim_once(
    claimed: &mut std::collections::HashSet<String>,
    field: &str,
    name: &str,
    at: Position,
) -> Result<(), Error> {
    if !claimed.insert(field.to_string()) {
        return Err(at.error(format!(
            "'{field}' is set twice in one {name}; one field takes one .set or .setIfAbsent"
        )));
    }
    Ok(())
}

/// ✂️ `Rewrite(...)`: exactly one path or method edit, where it is written.
///
/// 📌 One operation per component is deliberate. The shared model can carry
/// several at once and applies them in a fixed order of its own, so a
/// component that set two would read as the order they were written and mean
/// 🏷️ The argument labels `rewrite` accepts, named once for the parser and `describe`.
pub(crate) const REWRITE_LABELS: &[&str] = &["to", "stripPrefix", "stripSuffix", "path", "method"];

/// something else; two components in a row say what they mean.
fn rewrite(call: &Call) -> Result<HandlerConfig, Error> {
    call.leaf(REWRITE_LABELS)?;
    let [(label, value)] = call.args.as_slice() else {
        return Err(call.at.error(
            "Rewrite takes exactly one operation: to:, stripPrefix:, stripSuffix:, path: or method:",
        ));
    };
    let mut strip_prefix = None;
    let mut strip_suffix = None;
    let mut replace = None;
    let mut regex = None;
    let mut regex_replace = None;
    let mut method = None;
    match (label.as_deref(), value) {
        (Some("to"), Value::String(path)) => replace = Some(path.clone()),
        (Some("stripPrefix"), Value::String(prefix)) => strip_prefix = Some(prefix.clone()),
        (Some("stripSuffix"), Value::String(suffix)) => strip_suffix = Some(suffix.clone()),
        (Some("path"), Value::Typed(pattern)) if pattern.name == "regex" => {
            pattern.leaf(&["pattern", "replacement"])?;
            regex = Some(pattern.string("pattern")?);
            regex_replace = Some(pattern.string("replacement")?);
        }
        (Some("method"), Value::Typed(verb)) => method = Some(method_name(verb)?.to_string()),
        (Some("to" | "stripPrefix" | "stripSuffix"), _) => {
            return Err(call.at.error("this operation takes one quoted string"));
        }
        (Some("path"), _) => {
            return Err(call
                .at
                .error("path takes .regex(pattern: \"…\", replacement: \"…\")"));
        }
        (Some("method"), _) => {
            return Err(call.at.error("method takes one value such as .put"));
        }
        _ => unreachable!("leaf checked the labels"),
    }
    Ok(HandlerConfig::Rewrite {
        strip_prefix,
        strip_suffix,
        replace,
        regex,
        regex_replace,
        method,
    })
}

/// 🏷️ The argument labels `serve_files` accepts, named once for the parser and `describe`.
pub(crate) const RESPOND_LABELS: &[&str] = &["body", "status"];

pub(crate) const FILE_SERVER_LABELS: &[&str] = &[
    "root",
    "browse",
    "browseLimit",
    "index",
    "hide",
    "precompressed",
    "status",
    "passThru",
    "canonicalUris",
    "etagFileExtensions",
    "compress",
];

/// 📂 `.ServeFiles(root:, browse:, index:)`: the static file handler.
fn serve_files(call: &Call) -> Result<HandlerConfig, Error> {
    call.leaf(FILE_SERVER_LABELS)?;
    let root = call.string("root")?;
    let browse = if call.get("browse").is_some() {
        call.boolean("browse")?
    } else {
        false
    };
    let browse_limit = if call.get("browseLimit").is_some() {
        // 🚫 A listing ceiling for a listing nobody asked for is a setting
        // that reads as if it did something.
        if !browse {
            return Err(call
                .at
                .error("browseLimit needs browse: true; it caps the listing that turn on"));
        }
        Some(
            usize::try_from(call.integer("browseLimit")?)
                .map_err(|_| call.at.error("browseLimit exceeds the platform range"))?,
        )
    } else {
        None
    };
    let index = if call.get("index").is_some() {
        call.strings("index")?
    } else {
        vec!["index.html".to_string()]
    };
    if index.is_empty() {
        return Err(call.at.error("index needs at least one file name"));
    }
    let hide = call.strings("hide")?;
    // 🗜️ Sidecar lookup is asked for, never assumed: a stale `.gz` beside a
    // file is a wrong answer, and the Caddyfile's bare `precompressed` is the
    // three codings this build reads in its own default order.
    let precompressed = match call.get("precompressed") {
        None => Vec::new(),
        Some(Value::Array(items)) => {
            if items.is_empty() {
                return Err(call
                    .at
                    .error("precompressed needs at least one coding; leave it out for none"));
            }
            let mut codings = Vec::new();
            for item in items {
                let Value::Typed(coding) = item else {
                    return Err(call
                        .at
                        .error("precompressed takes .br, .zstd and .gzip values"));
                };
                coding.leaf(&[])?;
                let name = match coding.name.as_str() {
                    "br" | "zstd" | "gzip" => coding.name.as_str(),
                    other => {
                        return Err(coding.at.error(format!(
                            "unknown precompressed coding '.{other}'; expected .br, .zstd or \
                             .gzip"
                        )));
                    }
                };
                if codings.contains(&name.to_string()) {
                    return Err(coding.at.error("duplicate coding"));
                }
                codings.push(name.to_string());
            }
            codings
        }
        Some(_) => {
            return Err(call
                .at
                .error("precompressed takes an array such as [.br, .zstd, .gzip]"));
        }
    };
    let status = if call.get("status").is_some() {
        let code = u16::try_from(call.integer("status")?)
            .map_err(|_| call.at.error("status must fit in 0..=65535"))?;
        if !(100..=599).contains(&code) {
            return Err(call.at.error("status is a code between 100 and 599"));
        }
        Some(code)
    } else {
        None
    };
    let pass_thru = if call.get("passThru").is_some() {
        call.boolean("passThru")?
    } else {
        false
    };
    let canonical_uris = if call.get("canonicalUris").is_some() {
        call.boolean("canonicalUris")?
    } else {
        true
    };
    let etag_file_extensions = call.strings("etagFileExtensions")?;
    Ok(HandlerConfig::FileServer {
        root,
        index,
        browse,
        browse_limit,
        // 🗜️ Allowed here, and lowered by the site's own coding list: a site
        // without `.encode` turns this off after the routes are built, exactly
        // as `encode off` does for a file server written in a Pingclairfile.
        // A file server may also opt itself out on a site that did ask for a
        // coding, which is the one thing `encode` alone cannot say.
        compress: if call.get("compress").is_some() {
            call.boolean("compress")?
        } else {
            true
        },
        precompressed,
        hide,
        status,
        pass_thru,
        canonical_uris,
        etag_file_extensions,
    })
}

/// 🌐 `.Proxy(to:)`: the reverse proxy with the build's bare defaults.
/// 📌 Middleware, not a terminal, even though it ends in a proxy: the rewrite
/// element stands down for paths that are not PHP, and the file server written
/// after it is what serves them. The Caddyfile composes the two the same way —
/// a pipeline inside a pipeline — which is why this component lowers to one.
fn php_fastcgi(call: &Call) -> Result<HandlerConfig, Error> {
    call.leaf(&[
        "to",
        "root",
        "index",
        "split",
        "env",
        "tryFiles",
        "resolveRootSymlink",
        "dialTimeout",
        "readTimeout",
        "writeTimeout",
        "captureStderr",
    ])?;
    let upstreams = upstream_addresses(call)?;
    let root = if call.get("root").is_some() {
        Some(call.string("root")?)
    } else {
        None
    };
    let split_path = match call.get("split") {
        None => vec![".php".to_string()],
        Some(_) => {
            let split = call.strings("split")?;
            // 🛡️ Matching is byte-wise ASCII, so a Unicode delimiter would
            // never match anything; the Caddyfile refuses it for the same
            // reason rather than storing a rule that cannot fire.
            if let Some(non_ascii) = split.iter().find(|entry| !entry.is_ascii()) {
                return Err(call.at.error(format!(
                    "split path '{non_ascii}' contains non-ASCII characters, which would \
                     never match"
                )));
            }
            split
        }
    };
    let mut env = std::collections::BTreeMap::new();
    match call.get("env") {
        None => {}
        Some(Value::Array(items)) => {
            if items.is_empty() {
                return Err(call.at.error("env must not be empty; leave it out instead"));
            }
            for item in items {
                let Value::Typed(entry) = item else {
                    return Err(call.at.error("env takes .env(\"NAME\", \"value\") values"));
                };
                if entry.name != "env" {
                    return Err(entry.at.error("env takes .env(\"NAME\", \"value\") values"));
                }
                let [(None, Value::String(name)), (None, Value::String(value))] =
                    entry.args.as_slice()
                else {
                    return Err(entry.at.error(".env takes a name and a value"));
                };
                if env.insert(name.clone(), value.clone()).is_some() {
                    return Err(entry.at.error(format!("'{name}' is set twice in env")));
                }
            }
        }
        Some(_) => {
            return Err(call
                .at
                .error("env takes an array of .env(\"NAME\", \"value\")"));
        }
    }
    // 🔤 `index: .off` is the Caddyfile's `index off`: it turns the whole
    // rewrite half off and leaves a plain FastCGI proxy behind.
    let index = match call.get("index") {
        None => "index.php".to_string(),
        Some(Value::String(name)) if !name.is_empty() => name.clone(),
        Some(Value::Typed(off)) if off.name == "off" => {
            off.leaf(&[])?;
            "off".to_string()
        }
        Some(_) => {
            return Err(call.at.error("index takes a quoted file name, or .off"));
        }
    };
    let try_files = match call.get("tryFiles") {
        None => None,
        Some(Value::Array(items)) => {
            if items.is_empty() {
                return Err(call
                    .at
                    .error("tryFiles must not be empty; leave it out instead"));
            }
            let mut candidates = Vec::new();
            for item in items {
                candidates.push(file_candidate(item, call.at)?);
            }
            Some(candidates)
        }
        Some(_) => {
            return Err(call.at.error(
                "tryFiles takes an array of candidates such as [.requestPath, \"/index.php\"]",
            ));
        }
    };
    let fastcgi = FastCgiTransportConfig {
        root: root.clone(),
        split_path: split_path.clone(),
        env,
        resolve_root_symlink: if call.get("resolveRootSymlink").is_some() {
            call.boolean("resolveRootSymlink")?
        } else {
            false
        },
        dial_timeout_ms: if call.get("dialTimeout").is_some() {
            Some(call.measure("dialTimeout", false)?)
        } else {
            None
        },
        read_timeout_ms: if call.get("readTimeout").is_some() {
            Some(call.measure("readTimeout", false)?)
        } else {
            None
        },
        write_timeout_ms: if call.get("writeTimeout").is_some() {
            Some(call.measure("writeTimeout", false)?)
        } else {
            None
        },
        capture_stderr: if call.get("captureStderr").is_some() {
            call.boolean("captureStderr")?
        } else {
            false
        },
    };
    // 🧭 The expansion, exactly as the Caddyfile's `php_fastcgi` writes it: a
    // directory redirect, a file matcher that rewrites to whichever candidate
    // exists, and the FastCGI proxy for the extensions that were split off. One
    // shape, so the front-controller behaviour cannot drift between the two
    // spellings.
    let extensions = split_path;
    let mut elements = Vec::new();
    if index != "off" {
        // 📌 The engine's own path placeholders, because this is the shape the
        // Caddyfile compiles to; a hand-written `TryFiles` uses `.requestPath`
        // and lowers to `{path}`, which resolves to the same value.
        let path = "{http.request.uri.path}";
        let dir_index = format!("{path}/{index}");
        let (try_policy, dir_redirect) = match &try_files {
            Some(overrides) => (
                overrides
                    .last()
                    .is_some_and(|last| last.ends_with(".php"))
                    .then_some("first_exist_fallback"),
                overrides.contains(&dir_index),
            ),
            None => (Some("first_exist_fallback"), true),
        };
        let candidates = try_files
            .clone()
            .unwrap_or_else(|| vec![path.to_string(), dir_index.clone(), index.clone()]);
        if dir_redirect {
            elements.push(HandlerElement {
                matcher: Some(Matcher::And(
                    Box::new(Matcher::File {
                        try_files: vec![dir_index.clone()],
                        root: root.clone(),
                        try_policy: None,
                        split_path: Vec::new(),
                    }),
                    Box::new(Matcher::Not(Box::new(Matcher::Path {
                        patterns: vec!["*/".to_string()],
                    }))),
                )),
                handler: HandlerConfig::Redirect {
                    to: "{http.request.orig_uri.path}/{http.request.orig_uri.prefixed_query}"
                        .into(),
                    code: 308,
                },
            });
        }
        elements.push(HandlerElement {
            matcher: Some(Matcher::File {
                try_files: candidates,
                root: root.clone(),
                try_policy: try_policy.map(str::to_string),
                split_path: extensions.clone(),
            }),
            handler: HandlerConfig::Rewrite {
                strip_prefix: None,
                strip_suffix: None,
                replace: Some("{http.matchers.file.relative}".to_string()),
                regex: None,
                regex_replace: None,
                method: None,
            },
        });
    }
    elements.push(HandlerElement {
        matcher: Some(Matcher::Path {
            patterns: extensions
                .iter()
                .map(|extension| format!("*{extension}"))
                .collect(),
        }),
        handler: HandlerConfig::ReverseProxy(Box::new(reverse_proxy(
            upstreams,
            Some(Box::new(fastcgi)),
        ))),
    });
    // 🧵 A pipeline, not a first-match group: the directory redirect may not
    // match, the file matcher may rewrite and stand down, and the proxy answers
    // last. Grouping them as alternatives would stop at the first element that
    // matched, which is a different server.
    Ok(HandlerConfig::Pipeline { handlers: elements })
}

/// 🏷️ The argument labels `proxy` accepts, named once for the parser and `describe`.
pub(crate) const PROXY_LABELS: &[&str] = &["to", "headersUp", "headersDown"];

/// 🌐 `.Proxy(to:)`: the reverse proxy with the build's bare defaults.
fn proxy(call: &Call) -> Result<HandlerConfig, Error> {
    // 🌐 Identity stays in the call, policy goes in the modifier chain, which
    // is the shape the RFC promised: `Proxy(to: […]).loadBalance(…)`.
    call.labels(PROXY_LABELS)?;
    if call.body.is_some() {
        return Err(call.at.error(
            "Proxy does not take a block; write its policy as modifiers, as in \
             `.loadBalance(.roundRobin)`",
        ));
    }
    let upstreams = upstream_values(call)?;
    let up = header_list(call, "headersUp", false)?;
    let down = header_list(call, "headersDown", true)?;
    let mut config = reverse_proxy(
        upstreams.iter().map(|item| item.address.clone()).collect(),
        None,
    );
    config.upstream_options = upstreams;
    let mut chosen_policy = None;
    let mut seen = std::collections::HashSet::new();
    for modifier in &call.modifiers {
        if !seen.insert(modifier.name.clone()) {
            return Err(modifier.at.error("duplicate Proxy modifier"));
        }
        match modifier.name.as_str() {
            "loadBalance" => {
                chosen_policy = Some(load_balance(modifier, &mut config)?);
            }
            "healthCheck" => {
                config.health_check = Some(Box::new(health_check(
                    &single_value(modifier, "healthCheck")?,
                    modifier.at,
                )?));
            }
            "upstreamTLS" => {
                config.upstream_tls = Box::new(upstream_tls(
                    &single_value(modifier, "upstreamTLS")?,
                    modifier.at,
                )?);
            }
            "timeouts" => proxy_timeouts(modifier, &mut config)?,
            "retry" => proxy_retry(modifier, &mut config)?,
            "flush" => {
                let value = single_value(modifier, "flush")?;
                config.flush_interval = Some(match &value {
                    Value::Typed(value) if value.name == "immediate" => {
                        value.leaf(&[])?;
                        -1
                    }
                    Value::Typed(_) => i64::try_from(measured(&value, "flush", modifier.at)?)
                        .map_err(|_| modifier.at.error("flush exceeds the supported range"))?,
                    _ => {
                        return Err(modifier
                            .at
                            .error("flush takes .immediate or one duration such as .seconds(1)"));
                    }
                });
            }
            "versions" => {
                let value = single_value(modifier, "versions")?;
                let Value::Typed(versions) = &value else {
                    return Err(modifier
                        .at
                        .error("versions takes .http11, .h2 or .h2AndHttp11"));
                };
                versions.leaf(&[])?;
                config.upstream_versions = Some(match versions.name.as_str() {
                    "http11" => UpstreamHttpVersions::Http11,
                    "h2" => UpstreamHttpVersions::H2,
                    "h2AndHttp11" => UpstreamHttpVersions::H2AndHttp11,
                    other => {
                        return Err(versions.at.error(format!(
                            "unknown upstream version set '.{other}'; expected .http11, .h2 or \
                             .h2AndHttp11"
                        )));
                    }
                });
            }
            other => {
                return Err(modifier.at.error(format!(
                    "unknown Proxy modifier '.{other}'; expected .loadBalance, .healthCheck, \
                     .upstreamTLS, .timeouts, .retry, .flush or .versions"
                )));
            }
        }
    }
    // 🌱 Weights are round-robin's own knob. Writing them beside another
    // policy asks for two different things, and weighted round-robin is the
    // strategy the Caddyfile spells as its own name — so the strategy is
    // written out rather than left to a default the JSON happens to carry.
    let weighted = config
        .upstream_options
        .iter()
        .any(|option| option.weight != 1 || option.backup);
    if weighted {
        match chosen_policy {
            Some(policy) if policy != "roundRobin" => {
                return Err(call.at.error(format!(
                    "weights and backup belong to .roundRobin, not .{policy}; pick one"
                )));
            }
            Some(_) => {}
            None => config.load_balance.strategy = "round_robin".to_string(),
        }
    }
    config.headers_up = up.set;
    config.headers_up_add = up.add;
    config.headers_up_remove = up.remove;
    config.headers_up_replace = up.replace;
    config.headers_down = down.set;
    config.headers_down_add = down.add;
    config.headers_down_remove = down.remove;
    config.headers_down_replace = down.replace;
    config.headers_down_default = down.set_if_absent;
    Ok(HandlerConfig::ReverseProxy(Box::new(config)))
}

/// 🌐 `to:` — quoted addresses, or `.upstream(…)` values that carry their own
/// weight and backup mark.
///
/// 📌 The weight travels with the address, which is the whole point of the
/// value: a parallel array made reordering the list silently re-assign who
/// weighs what, and no type could help.
fn upstream_values(call: &Call) -> Result<Vec<ProxyUpstream>, Error> {
    let Some(value) = call.get("to") else {
        return Err(call.at.error(
            "Proxy requires to: \"host:port\" or to: [.upstream(\"host:port\", weight: 2)]",
        ));
    };
    let items: Vec<&Value> = match value {
        Value::Array(items) => items.iter().collect(),
        other => vec![other],
    };
    if items.is_empty() {
        return Err(call.at.error("to needs at least one upstream"));
    }
    let typed = items.iter().any(|item| matches!(item, Value::Typed(_)));
    if !typed {
        return items
            .iter()
            .map(|item| {
                let Value::String(address) = item else {
                    return Err(call.at.error("to takes quoted addresses"));
                };
                Ok(ProxyUpstream {
                    address: address.clone(),
                    weight: 1,
                    backup: false,
                })
            })
            .collect();
    }
    let mut upstreams = Vec::new();
    for item in items {
        let Value::Typed(upstream) = item else {
            return Err(call
                .at
                .error("to takes either quoted addresses or .upstream(…) values, not both"));
        };
        if upstream.name != "upstream" {
            return Err(upstream.at.error(format!(
                "unknown upstream value '.{}'; expected .upstream(\"host:port\", weight:, backup:)",
                upstream.name
            )));
        }
        let [(None, Value::String(address)), rest @ ..] = upstream.args.as_slice() else {
            return Err(upstream
                .at
                .error(".upstream takes a quoted address, and optionally weight: and backup:"));
        };
        if rest.len() > 2 {
            return Err(upstream
                .at
                .error(".upstream takes a quoted address, and optionally weight: and backup:"));
        }
        upstream.no_modifiers()?;
        let weight = if upstream.get("weight").is_some() {
            let weight = u32::try_from(upstream.integer("weight")?)
                .map_err(|_| upstream.at.error("a weight must fit in 0..=4294967295"))?;
            // 🚫 Zero is not "no traffic yet": the runtime clamps it to one,
            // which is the opposite of what a drained backend asked for.
            if weight == 0 {
                return Err(upstream
                    .at
                    .error("a weight of 0 would be clamped to 1; leave the upstream out instead"));
            }
            weight
        } else {
            1
        };
        let backup = if upstream.get("backup").is_some() {
            upstream.boolean("backup")?
        } else {
            false
        };
        upstreams.push(ProxyUpstream {
            address: address.clone(),
            weight,
            backup,
        });
    }
    Ok(upstreams)
}

/// 🎛️ `.loadBalance(…)`: the strategy, and the field a hashing one reads.
fn load_balance(modifier: &Call, config: &mut ReverseProxyConfig) -> Result<String, Error> {
    let [(None, Value::Typed(policy))] = modifier.args.as_slice() else {
        return Err(modifier
            .at
            .error("loadBalance takes one policy such as .leastConn"));
    };
    let strategy = match policy.name.as_str() {
        "roundRobin" | "random" | "leastConn" | "ipHash" | "first" => {
            policy.leaf(&[])?;
            match policy.name.as_str() {
                "roundRobin" => "round_robin",
                "leastConn" => "least_conn",
                "ipHash" => "ip_hash",
                other => other,
            }
        }
        // 🔑 The hashing strategies that read a request field must name it: a
        // cookie policy with no cookie hashes the same empty string for every
        // client and pins the site to one upstream.
        "header" | "cookie" | "query" => {
            let [(None, Value::String(key))] = policy.args.as_slice() else {
                return Err(policy.at.error(format!(
                    ".{} takes one name, such as .{}(\"X-User\")",
                    policy.name, policy.name
                )));
            };
            policy.no_modifiers()?;
            config.load_balance.hash_key = Some(key.clone());
            match policy.name.as_str() {
                "header" => "header",
                "cookie" => "cookie",
                _ => "query",
            }
        }
        other => {
            return Err(policy.at.error(format!(
                "unknown load balance policy '.{other}'; expected .roundRobin, .random, \
                 .leastConn, .ipHash, .first, .header(\"…\"), .cookie(\"…\") or .query(\"…\")"
            )));
        }
    };
    config.load_balance.strategy = strategy.to_string();
    Ok(match strategy {
        "round_robin" => "roundRobin".to_string(),
        "least_conn" => "leastConn".to_string(),
        "ip_hash" => "ipHash".to_string(),
        other => other.to_string(),
    })
}

/// ⏱️ `.timeouts(connect:, firstByte:, betweenReads:, read:, write:)`.
fn proxy_timeouts(modifier: &Call, config: &mut ReverseProxyConfig) -> Result<(), Error> {
    modifier.leaf(&["connect", "firstByte", "betweenReads", "read", "write"])?;
    if modifier.args.is_empty() {
        return Err(modifier.at.error("timeouts needs at least one deadline"));
    }
    let millis = |key: &str| -> Result<i64, Error> {
        i64::try_from(modifier.measure(key, false)?).map_err(|_| {
            modifier
                .at
                .error(format!("{key} exceeds the supported range"))
        })
    };
    if modifier.get("connect").is_some() {
        config.connect_timeout = Some(millis("connect")?);
    }
    if modifier.get("firstByte").is_some() {
        config.first_byte_timeout = Some(millis("firstByte")?);
    }
    if modifier.get("betweenReads").is_some() {
        config.between_reads_timeout = Some(millis("betweenReads")?);
    }
    if modifier.get("read").is_some() {
        config.read_timeout = Some(millis("read")?);
    }
    if modifier.get("write").is_some() {
        config.write_timeout = Some(millis("write")?);
    }
    Ok(())
}

/// \(\u{1f501}\) `.retry(tryDuration:, tryInterval:, maxFails:, failDuration:)`.
fn proxy_retry(modifier: &Call, config: &mut ReverseProxyConfig) -> Result<(), Error> {
    modifier.leaf(&["tryDuration", "tryInterval", "maxFails", "failDuration"])?;
    if modifier.args.is_empty() {
        return Err(modifier.at.error("retry needs at least one setting"));
    }
    if modifier.get("tryDuration").is_some() {
        config.retry.total_timeout_ms = Some(modifier.measure("tryDuration", false)?);
    }
    if modifier.get("tryInterval").is_some() {
        config.retry.backoff_ms = modifier.measure("tryInterval", false)?;
    }
    if modifier.get("maxFails").is_some() {
        config.max_fails = Some(
            u32::try_from(modifier.integer("maxFails")?)
                .map_err(|_| modifier.at.error("maxFails must fit in 0..=4294967295"))?,
        );
    }
    if modifier.get("failDuration").is_some() {
        config.fail_duration_ms = Some(modifier.measure("failDuration", false)?);
    }
    Ok(())
}

/// 🌐 The one unlabelled value a modifier takes.
fn single_value(modifier: &Call, name: &str) -> Result<Value, Error> {
    let [(None, value)] = modifier.args.as_slice() else {
        return Err(modifier.at.error(format!("{name} takes exactly one value")));
    };
    modifier.no_modifiers()?;
    Ok(value.clone())
}

/// ⏱️ The duration a `.flush(.seconds(1))`-shaped value names.
fn measured(value: &Value, name: &str, at: Position) -> Result<u64, Error> {
    let Value::Typed(value) = value else {
        return Err(at.error(format!("{name} takes a duration")));
    };
    let [(None, Value::Number(number))] = value.args.as_slice() else {
        return Err(value.at.error(format!("{name} takes a duration")));
    };
    let factor = match value.name.as_str() {
        "milliseconds" => 1,
        "seconds" => 1_000,
        "minutes" => 60_000,
        "hours" => 3_600_000,
        _ => return Err(value.at.error(format!("{name} takes a duration"))),
    };
    number.checked_mul(factor).ok_or_else(|| {
        value
            .at
            .error(format!("{name} exceeds the supported range"))
    })
}

/// 🏷️ One of a proxy's header lists, read with the components' own reader.
fn header_list(call: &Call, key: &str, response_side: bool) -> Result<HeaderOps, Error> {
    let Some(value) = call.get(key) else {
        return Ok(HeaderOps::default());
    };
    let Value::Array(items) = value else {
        return Err(call.at.error(format!(
            "{key} takes an array of actions such as [.set(\"X-Name\", \"value\")]"
        )));
    };
    if items.is_empty() {
        return Err(call
            .at
            .error(format!("{key} must not be empty; leave it out instead")));
    }
    // 📎 An array's entries carry no labels of their own, which is exactly the
    // shape `header_ops_from` reads: the label slot is what says "this action
    // is named", and a named action here is a mistake it already refuses.
    let actions: Vec<(Option<String>, Value)> =
        items.iter().cloned().map(|item| (None, item)).collect();
    header_ops_from(&actions, key, call.at, response_side)
}

/// 🔌 The addresses an upstream list names.
fn upstream_addresses(call: &Call) -> Result<Vec<String>, Error> {
    let mut upstreams = Vec::new();
    match call.get("to") {
        Some(Value::String(address)) => upstreams.push(address.clone()),
        Some(Value::Array(items)) => {
            for item in items {
                let Value::String(address) = item else {
                    return Err(call.at.error("to takes quoted addresses"));
                };
                upstreams.push(address.clone());
            }
        }
        _ => {
            return Err(call
                .at
                .error("to takes \"host:port\" or [\"host:port\", ...]"));
        }
    }
    if upstreams.is_empty() {
        return Err(call.at.error("to needs at least one address"));
    }
    Ok(upstreams)
}

/// 🌐 The proxy the build's bare defaults describe, with an optional FastCGI
/// transport. Shared by `Proxy` and `PHPFastCGI`, so the two cannot disagree
/// about a default neither of them wrote.
/// 🩺 `.http(path:, …)`: the probe a proxy sends to decide a peer's health.
/// 🏷️ The argument labels `upstream_tls` accepts, named once for the parser and `describe`.
pub(crate) const UPSTREAM_TLS_LABELS: &[&str] = &[
    "serverName",
    "trustedCACerts",
    "clientCert",
    "clientKey",
    "insecureSkipVerify",
];

/// 🔒 `.enabled(…)`: the TLS policy a proxy applies to its upstreams.
fn upstream_tls(value: &Value, at: Position) -> Result<UpstreamTlsConfig, Error> {
    let Value::Typed(tls) = value else {
        return Err(at.error("upstreamTLS takes .enabled(serverName:, …)"));
    };
    if tls.name != "enabled" {
        return Err(tls.at.error(format!(
            "unknown upstream TLS '.{}'; expected .enabled(serverName:, trustedCACerts:, \
             clientCert:, clientKey:, insecureSkipVerify:)",
            tls.name
        )));
    }
    tls.leaf(UPSTREAM_TLS_LABELS)?;
    let server_name = if tls.get("serverName").is_some() {
        Some(tls.string("serverName")?)
    } else {
        None
    };
    let trusted_ca_certs = tls.strings("trustedCACerts")?;
    // 🎫 Both halves or neither: an upstream must never see an anonymous
    // handshake because a client certificate was named without its key.
    let (client_cert, client_key) = match (tls.get("clientCert"), tls.get("clientKey")) {
        (None, None) => (None, None),
        (Some(_), Some(_)) => (
            Some(tls.string("clientCert")?),
            Some(tls.string("clientKey")?),
        ),
        _ => {
            return Err(tls
                .at
                .error("clientCert and clientKey are one setting; name both or neither"));
        }
    };
    let insecure_skip_verify = if tls.get("insecureSkipVerify").is_some() {
        tls.boolean("insecureSkipVerify")?
    } else {
        false
    };
    // 🚫 Naming a private CA *and* skipping verification asks for two
    // different things: the first says "trust exactly these", the second says
    // "trust anything".
    if insecure_skip_verify && !trusted_ca_certs.is_empty() {
        return Err(tls
            .at
            .error("insecureSkipVerify and trustedCACerts are alternatives; pick one"));
    }
    Ok(UpstreamTlsConfig {
        enable: true,
        server_name,
        trusted_ca_certs,
        client_cert,
        client_key,
        insecure_skip_verify,
    })
}

/// 🏷️ The argument labels `health_check` accepts, named once for the parser and `describe`.
pub(crate) const HEALTH_CHECK_LABELS: &[&str] = &[
    "path",
    "port",
    "method",
    "interval",
    "timeout",
    "passes",
    "fails",
    "status",
    "body",
    "headers",
    "host",
    "reuseConnection",
];

/// 🩺 `.http(path:, …)`: the probe a proxy sends to decide a peer's health.
fn health_check(value: &Value, at: Position) -> Result<HealthCheckConfig, Error> {
    let Value::Typed(check) = value else {
        return Err(
            at.error("healthCheck takes .http(path: \"/healthz\", interval: .seconds(10), …)")
        );
    };
    if check.name != "http" {
        return Err(check.at.error(format!(
            "unknown health check '.{}'; expected .http(path:, …)",
            check.name
        )));
    }
    check.leaf(HEALTH_CHECK_LABELS)?;
    // 🛣️ The path is the one field with no default worth guessing: probing `/`
    // when the operator meant `/healthz` reports every upstream healthy for the
    // wrong reason.
    let path = check.string("path")?;
    let method = match check.get("method") {
        None => "GET".to_string(),
        Some(Value::Typed(method)) => method_name(method)?.to_string(),
        Some(_) => return Err(check.at.error("method takes a value such as .get")),
    };
    // 🚫 A probe may only read: the runtime refuses anything that could carry a
    // body, so accepting `.post` here would be a configuration that loads and
    // cannot run.
    if !matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS") {
        return Err(check
            .at
            .error("a health probe may only read; expected .get, .head or .options"));
    }
    let interval = if check.get("interval").is_some() {
        whole_seconds(check, "interval")?
    } else {
        10
    };
    let timeout = if check.get("timeout").is_some() {
        whole_seconds(check, "timeout")?
    } else {
        5
    };
    let port = if check.get("port").is_some() {
        Some(
            u16::try_from(check.integer("port")?)
                .map_err(|_| check.at.error("a port must be between 1 and 65535"))?,
        )
    } else {
        None
    };
    let positive = |key: &str| -> Result<u32, Error> {
        let value = u32::try_from(check.integer(key)?)
            .map_err(|_| check.at.error(format!("{key} must fit in 0..=4294967295")))?;
        if value == 0 {
            return Err(check.at.error(format!("{key} must be at least 1")));
        }
        Ok(value)
    };
    let consecutive_success = if check.get("passes").is_some() {
        positive("passes")?
    } else {
        1
    };
    let consecutive_failure = if check.get("fails").is_some() {
        Some(positive("fails")?)
    } else {
        None
    };
    // ✅ Codes and classes, the same two things the response matchers take.
    let expected_statuses = match check.get("status") {
        None => vec![200],
        Some(Value::Array(items)) => {
            if items.is_empty() {
                return Err(check.at.error("status needs at least one code or class"));
            }
            let mut codes = Vec::new();
            for item in items {
                let code = match item {
                    Value::Number(code) => u16::try_from(*code)
                        .map_err(|_| check.at.error("status must fit in 0..=65535"))?,
                    // ✅ The health checker stores exact codes, so a class is
                    // expanded here rather than kept as its leading digit —
                    // which is what the Caddyfile's `health_status 2xx` does,
                    // and why this reads differently from the response
                    // matchers that keep the digit.
                    Value::Typed(class) => {
                        let hundred = status_class(class)? * 100;
                        codes.extend(hundred..=hundred + 99);
                        continue;
                    }
                    _ => return Err(check.at.error("status takes codes and class values")),
                };
                if !codes.contains(&code) {
                    codes.push(code);
                }
            }
            codes
        }
        Some(_) => return Err(check.at.error("status takes an array such as [.success]")),
    };
    let expected_body = if check.get("body").is_some() {
        Some(check.string("body")?)
    } else {
        None
    };
    let host = if check.get("host").is_some() {
        Some(check.string("host")?)
    } else {
        None
    };
    let reuse_connection = if check.get("reuseConnection").is_some() {
        check.boolean("reuseConnection")?
    } else {
        false
    };
    // 🏷️ The probe's own headers, written with the same actions as everywhere
    // else; only the two that write a value make sense here, since a probe has
    // no incoming message to edit.
    let mut headers: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    if let Some(value) = check.get("headers") {
        let Value::Array(items) = value else {
            return Err(check
                .at
                .error("headers takes an array such as [.set(\"X-Probe\", \"1\")]"));
        };
        if items.is_empty() {
            return Err(check
                .at
                .error("headers must not be empty; leave it out instead"));
        }
        for item in items {
            let Value::Typed(action) = item else {
                return Err(check
                    .at
                    .error("headers takes .set(…) and .append(…) values"));
            };
            match action.name.as_str() {
                "set" | "append" => {
                    let [(None, Value::String(name)), (None, Value::String(text))] =
                        action.args.as_slice()
                    else {
                        return Err(action
                            .at
                            .error(format!(".{} takes a quoted name and value", action.name)));
                    };
                    let values = headers.entry(name.clone()).or_default();
                    // 📌 `.set` replaces, `.append` adds — the same reading the
                    // components give the two words.
                    if action.name == "set" {
                        values.clear();
                    }
                    values.push(text.clone());
                }
                other => {
                    return Err(action.at.error(format!(
                        "unknown probe header action '.{other}'; expected .set or .append"
                    )));
                }
            }
        }
    }
    Ok(HealthCheckConfig {
        path,
        interval,
        timeout,
        threshold: consecutive_failure.unwrap_or(3),
        method,
        host,
        headers,
        expected_statuses,
        expected_body,
        port,
        consecutive_success,
        consecutive_failure,
        reuse_connection,
        max_response_body_bytes: pingclair_core::config::default_health_body_limit(),
        slow_start_ms: 0,
    })
}

/// ⏲️ One of a health check's deadlines, in whole seconds.
fn whole_seconds(call: &Call, key: &str) -> Result<u64, Error> {
    let millis = call.measure(key, false)?;
    if millis == 0 || millis % 1000 != 0 {
        return Err(call.at.error(format!("{key} is at least one whole second")));
    }
    Ok(millis / 1000)
}

/// ✅ The one-digit class a status selector names.
fn status_class(class: &Call) -> Result<u16, Error> {
    class.leaf(&[])?;
    Ok(match class.name.as_str() {
        "informational" => 1,
        "success" => 2,
        "redirect" => 3,
        "clientError" => 4,
        "serverError" => 5,
        other => {
            return Err(class.at.error(format!(
                "unknown status class '.{other}'; expected .informational, .success, .redirect, \
                 .clientError or .serverError"
            )));
        }
    })
}

fn reverse_proxy(
    upstreams: Vec<String>,
    fastcgi: Option<Box<FastCgiTransportConfig>>,
) -> ReverseProxyConfig {
    let upstream_options = upstreams
        .iter()
        .map(|address| ProxyUpstream {
            address: address.clone(),
            weight: 1,
            backup: false,
        })
        .collect();
    ReverseProxyConfig {
        upstreams,
        fastcgi,
        dynamic_upstream: None,
        rewrite_method: None,
        rewrite_uri: None,
        request_buffer_bytes: None,
        response_buffer_bytes: None,
        upstream_versions: None,
        handle_response: Vec::new(),
        subrequest: None,
        upstream_options,
        load_balance: LoadBalanceConfig::default(),
        health_check: None,
        max_fails: None,
        fail_duration_ms: None,
        headers_up: std::collections::BTreeMap::new(),
        headers_down: std::collections::BTreeMap::new(),
        headers_down_add: std::collections::BTreeMap::new(),
        headers_down_remove: Vec::new(),
        headers_down_default: std::collections::BTreeMap::new(),
        headers_down_replace: Vec::new(),
        headers_up_remove: Vec::new(),
        headers_up_add: std::collections::BTreeMap::new(),
        headers_up_replace: Vec::new(),
        flush_interval: None,
        read_timeout: None,
        write_timeout: None,
        connect_timeout: None,
        first_byte_timeout: None,
        between_reads_timeout: None,
        retry: Box::new(RetryConfig {
            max_attempts: 16,
            total_timeout_ms: None,
            backoff_ms: 0,
            retry_match: Vec::new(),
        }),
        overload: Box::new(OverloadConfig {
            max_in_flight: None,
            max_pending: 0,
            pending_timeout_ms: 1000,
            upstream_max_connections: None,
        }),
        circuit_breaker: Box::new(CircuitBreakerConfig {
            consecutive_failures: None,
            error_rate_percent: None,
            minimum_requests: 20,
            window_requests: 100,
            open_duration_ms: 30_000,
            half_open_requests: 1,
            failure_statuses: Vec::new(),
        }),
        upstream_tls: Box::new(UpstreamTlsConfig::default()),
        cache: None,
    }
}

/// 🏷️ The argument labels `redirect` accepts, named once for the parser and `describe`.
pub(crate) const REDIRECT_LABELS: &[&str] = &["to", "status"];

/// ➡️ `.Redirect(to:, status:)`: the redirect statuses the RFC names.
fn redirect(call: &Call) -> Result<HandlerConfig, Error> {
    call.leaf(REDIRECT_LABELS)?;
    let to = call.string("to")?;
    let code = match call.get("status") {
        None => 302,
        Some(Value::Typed(value)) => {
            if !value.args.is_empty() {
                return Err(value.at.error("a redirect status takes no arguments"));
            }
            match value.name.as_str() {
                "permanent" => 301,
                "temporary" => 302,
                "seeOther" => 303,
                "temporaryRedirect" => 307,
                "permanentRedirect" => 308,
                other => {
                    return Err(value.at.error(format!(
                        "unknown redirect status '.{other}'; expected .permanent, .temporary, .seeOther, .temporaryRedirect or .permanentRedirect"
                    )));
                }
            }
        }
        Some(_) => {
            return Err(call
                .at
                .error("status takes a redirect status such as .permanent"));
        }
    };
    Ok(HandlerConfig::Redirect {
        to: pingclair_core::config::ConfigText::literal(to),
        code,
    })
}

/// 🏷️ The argument labels `fail` accepts, named once for the parser and `describe`.
pub(crate) const FAIL_LABELS: &[&str] = &["status", "message"];

/// 🚨 `.Fail(status:, message:)`: raise an error response.
fn fail(call: &Call) -> Result<HandlerConfig, Error> {
    call.leaf(FAIL_LABELS)?;
    let status = match call.get("status") {
        None => 500,
        Some(_) => u16::try_from(call.integer("status")?)
            .map_err(|_| call.at.error("status must fit in 0..=65535"))?,
    };
    let message = if call.get("message").is_some() {
        Some(pingclair_core::config::ConfigText::literal(
            call.string("message")?,
        ))
    } else {
        None
    };
    Ok(HandlerConfig::Error { status, message })
}

/// 🏷️ The argument labels `serve_metrics` accepts, named once for the parser and `describe`.
pub(crate) const METRICS_LABELS: &[&str] = &["disableOpenMetrics"];

/// 📊 `.ServeMetrics()`: answer with the Prometheus endpoint.
fn serve_metrics(call: &Call) -> Result<HandlerConfig, Error> {
    call.leaf(METRICS_LABELS)?;
    let disable_openmetrics = if call.get("disableOpenMetrics").is_some() {
        call.boolean("disableOpenMetrics")?
    } else {
        false
    };
    Ok(HandlerConfig::Metrics {
        disable_openmetrics,
    })
}
