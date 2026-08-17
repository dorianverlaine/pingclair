// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

use super::AdapterError;
use super::args::{expect_one_argument, parse_dns_refresh, parse_required_duration};
use super::logs::adapt_log_block;
use crate::parser::ast::*;
use crate::parser::caddy_ast::{Block, Directive};
use pingclair_core::config::DnsProviderConfig;

// MARK: - Global Block

pub(super) fn adapt_global(d: Directive) -> Result<GlobalBlock, AdapterError> {
    let mut global = GlobalBlock::default();
    if let Some(block) = d.block {
        // 🧭 Lift any nested `servers { … }` children to this level first, so
        // the loop below sees one flat list of options regardless of how the
        // operator chose to group them.
        let directives = expand_servers_block(block.directives)?;

        for sub in directives {
            match sub.name.as_str() {
                // 🪵 `log <name> { … }` declares a named channel. Several
                // servers may reference one channel, and they share a single
                // writer — two writers on one file would interleave, so "the
                // same channel" has to mean the same queue.
                "log" => {
                    if sub.args.len() > 1 {
                        return Err(AdapterError::ArgumentCount("log".into(), 1, sub.args.len()));
                    }
                    let Some(channel_block) = sub.block else {
                        return Err(AdapterError::InvalidArgument(
                            "log".into(),
                            "a global `log` option needs a block describing its output".into(),
                        ));
                    };
                    let channel = adapt_log_block(channel_block)?;
                    // 🚫 `hostnames` selects which request hosts reach a
                    // logger, and a global logger is not attached to a site
                    // block, so there is nothing for it to select from. Upstream
                    // refuses it here; accepting it would leave an operator with
                    // a host filter that quietly never applies.
                    if !channel.hostnames.is_empty() {
                        return Err(AdapterError::InvalidArgument(
                            "log".into(),
                            "hostnames is not allowed in the log global options".into(),
                        ));
                    }
                    let logging = global.logging.get_or_insert_with(Default::default);
                    let Some(name) = sub.args.first().cloned() else {
                        // 🪵 An unnamed global `log` configures the default
                        // logger. Process-level runtime logging is still
                        // environment-driven, but the format accepts this
                        // spelling and the compiled config now carries it.
                        if logging.default.is_some() {
                            return Err(AdapterError::InvalidArgument(
                                "log".into(),
                                "the default logger is declared twice".into(),
                            ));
                        }
                        logging.default = Some(channel);
                        continue;
                    };
                    // 🚫 A redeclared channel is a mistake, not a merge: the
                    // second block would silently win and the first one's
                    // output would vanish.
                    if logging.channels.insert(name.clone(), channel).is_some() {
                        return Err(AdapterError::InvalidArgument(
                            "log".into(),
                            format!("channel `{name}` is declared twice"),
                        ));
                    }
                }
                // 🔢 Consumed before any site is adapted, in `adapt_from`,
                // because the order has to exist before the first site uses it.
                // Accepted (and already validated) here so it does not fall
                // through to the unknown-option arm.
                "order" => {}
                "debug" => {
                    // 🚩 `debug fales` used to parse as "debug off": a typo
                    // silently disabled the very diagnostics being asked for.
                    // Caddy's `debug` is a bare flag, so any argument is a
                    // mistake worth rejecting.
                    if !sub.args.is_empty() {
                        return Err(AdapterError::ArgumentCount(
                            "debug".into(),
                            0,
                            sub.args.len(),
                        ));
                    }
                    global.debug = Some(true);
                }
                "email" => {
                    global.email = sub.args.first().cloned();
                }
                "http_port" => {
                    let value = expect_one_argument(&sub)?;
                    global.http_port = Some(value.parse::<u16>().map_err(|_| {
                        AdapterError::InvalidArgument("http_port".into(), value.to_string())
                    })?);
                }
                "https_port" => {
                    let value = expect_one_argument(&sub)?;
                    global.https_port = Some(value.parse::<u16>().map_err(|_| {
                        AdapterError::InvalidArgument("https_port".into(), value.to_string())
                    })?);
                }
                "metrics" => {
                    if !sub.args.is_empty() {
                        return Err(AdapterError::ArgumentCount(
                            "metrics".into(),
                            0,
                            sub.args.len(),
                        ));
                    }
                    // 📊 Bare `metrics` still means "collect", which is what it
                    // has always meant here. The block only adds detail, so an
                    // empty one is not an error and does not switch anything off.
                    global.metrics = Some(true);
                    if let Some(block) = &sub.block {
                        let parsed = parse_metrics_options(block, MetricsScope::Global)?;
                        global.metrics_options.merge(&parsed);
                    }
                }
                "auto_https" => {
                    let arg = sub
                        .args
                        .first()
                        .ok_or_else(|| AdapterError::ArgumentCount("auto_https".into(), 1, 0))?;
                    match arg.as_str() {
                        "on" => global.auto_https = Some(AutoHttpsMode::On),
                        "off" => global.auto_https = Some(AutoHttpsMode::Off),
                        "disable_redirects" => {
                            global.auto_https = Some(AutoHttpsMode::DisableRedirects)
                        }
                        // 🚫 Caddy's `disable_certs` and `ignore_loaded_certs`
                        // modes are real syntax; name them explicitly instead
                        // of reporting a bare invalid argument.
                        "disable_certs" | "ignore_loaded_certs" => {
                            // TODO(v0.3): implement certificate-only and
                            // ignore-loaded-certificates automation modes.
                            return Err(AdapterError::UnsupportedFeature(
                                format!("auto_https {arg}"),
                                "only on, off and disable_redirects are implemented".into(),
                            ));
                        }
                        _ => {
                            return Err(AdapterError::InvalidArgument(
                                "auto_https".into(),
                                arg.clone(),
                            ));
                        }
                    }
                }
                // 🚰 `grace_period <duration>` — how long shutdown waits for
                // requests already in flight. Caddy waits forever by default,
                // and so do we; this option is how an operator trades that for
                // a bounded restart.
                "grace_period" => {
                    // 🕐 Rounded up, so a sub-second grace period asks for one
                    // second rather than for zero — `grace_period 500ms` must
                    // not silently become "kill everything immediately".
                    global.grace_period_secs = Some(parse_required_duration(&sub)?.div_ceil(1000));
                }
                "admin" => {
                    // 🌐 `admin <addr> { origins …; enforce_origin }`. The
                    // block used to compile with its contents silently dropped,
                    // leaving the endpoint without the origin checks the
                    // operator had written down — then it was made a hard
                    // rejection, and now it is implemented.
                    let mut origins = Vec::new();
                    let mut enforce_origin = false;
                    if let Some(block) = sub.block.clone() {
                        for entry in block.directives {
                            match entry.name.as_str() {
                                "origins" => {
                                    if entry.args.is_empty() {
                                        return Err(AdapterError::InvalidArgument(
                                            "admin origins".into(),
                                            "list at least one allowed origin".into(),
                                        ));
                                    }
                                    origins.extend(entry.args.iter().cloned());
                                }
                                "enforce_origin" => {
                                    if !entry.args.is_empty() {
                                        return Err(AdapterError::ArgumentCount(
                                            "enforce_origin".into(),
                                            0,
                                            entry.args.len(),
                                        ));
                                    }
                                    enforce_origin = true;
                                }
                                other => {
                                    return Err(AdapterError::UnknownDirective(format!(
                                        "admin: {other}"
                                    )));
                                }
                            }
                        }
                    }
                    match sub.args.first() {
                        // `admin off` explicitly disables the admin API
                        Some(arg) if arg == "off" => {
                            global.admin = Some(AdminDirective {
                                listen: String::new(),
                                enabled: false,
                                api_key: None,
                                origins: Vec::new(),
                                enforce_origin: false,
                            });
                        }
                        // `admin <listen> [api_key]` — the optional second
                        // argument is the Bearer token for the admin API.
                        Some(arg) => {
                            global.admin = Some(AdminDirective {
                                listen: arg.clone(),
                                enabled: true,
                                api_key: sub.args.get(1).cloned(),
                                origins,
                                enforce_origin,
                            });
                        }
                        // 🌐 No address means the default admin endpoint,
                        // exactly as upstream parses it — `admin { origins
                        // … }` must not demand an address Caddy does not.
                        None => {
                            global.admin = Some(AdminDirective {
                                listen: "127.0.0.1:2019".into(),
                                enabled: true,
                                api_key: None,
                                origins,
                                enforce_origin,
                            });
                        }
                    }
                }
                "local_certs" => {
                    // 🔐 A bare toggle, like Caddy's: default automation
                    // switches to the built-in local authority. Any argument
                    // is a mistake, because `local_certs off` would read like
                    // it disabled the option while Caddy's flag parser ignores
                    // the word entirely — a silent misreading either way.
                    if !sub.args.is_empty() {
                        return Err(AdapterError::ArgumentCount(
                            "local_certs".into(),
                            0,
                            sub.args.len(),
                        ));
                    }
                    global.local_certs = true;
                }
                "persist_config" => {
                    // 💾 `persist_config off` is the only accepted spelling,
                    // exactly as upstream parses it: Caddy's admin API
                    // persists the loaded config by default, and this server
                    // never does, so `off` is the behaviour we already have.
                    // `on` and a bare option are refused rather than guessed.
                    match sub.args.as_slice() {
                        [value] if value == "off" => global.persist_config_off = true,
                        [value] => {
                            return Err(AdapterError::InvalidArgument(
                                "persist_config".into(),
                                format!("must be 'off', got {value}"),
                            ));
                        }
                        [_, _, ..] => {
                            return Err(AdapterError::InvalidArgument(
                                "persist_config".into(),
                                "must be a single 'off'".into(),
                            ));
                        }
                        [] => {
                            return Err(AdapterError::ArgumentCount("persist_config".into(), 1, 0));
                        }
                    }
                }
                "trusted_proxies" => {
                    if sub.args.is_empty() {
                        return Err(AdapterError::ArgumentCount("trusted_proxies".into(), 1, 0));
                    }
                    for rule in sub.args {
                        let valid = rule.parse::<ipnet::IpNet>().is_ok()
                            || rule.parse::<std::net::IpAddr>().is_ok();
                        if !valid {
                            return Err(AdapterError::InvalidArgument(
                                "trusted_proxies".into(),
                                format!("invalid IP or CIDR `{rule}`"),
                            ));
                        }
                        global.trusted_proxies.push(rule);
                    }
                }
                // 📡 `dns <provider> [args…]` names the provider used both for
                // DNS-01 challenges and, upstream, for general resolution. We
                // only have the first meaning, which is why `acme_dns` below
                // is what actually switches a site's challenge over.
                // 🏛️ Parsed so a configuration written for upstream still
                // translates; this build never acts as a CA, and the refusal
                // to do so lives at startup where it can be acted on.
                "pki" => {
                    global.pki = super::tls::parse_pki_block(&sub)?;
                }
                // 🤝 A bare toggle describing behaviour we already have: the
                // internal CA root is installed only by `pingclair trust`,
                // never automatically. Refusing an argument rather than
                // ignoring one, because `skip_install_trust off` would read
                // like it re-enabled something.
                "skip_install_trust" => {
                    if !sub.args.is_empty() {
                        return Err(AdapterError::ArgumentCount(
                            "skip_install_trust".into(),
                            0,
                            sub.args.len(),
                        ));
                    }
                    global.skip_install_trust = true;
                }
                "dns" => {
                    let name = sub
                        .args
                        .first()
                        .ok_or_else(|| AdapterError::ArgumentCount("dns".into(), 1, 0))?;
                    global.dns = Some(DnsProviderConfig {
                        name: name.clone(),
                        arguments: sub.args[1..]
                            .iter()
                            .map(|arg| arg.as_str().into())
                            .collect(),
                    });
                }
                // 📡 `acme_dns [<provider> [args…]]` moves automatic issuance
                // onto DNS-01 for every site that has not said otherwise. The
                // bare spelling means "use whatever `dns` named", which is why
                // the field is an `Option<Option<…>>` rather than a provider:
                // "not asked for" and "asked for, unnamed" are different
                // answers, and only the second one is an error when no `dns`
                // option exists.
                "acme_dns" => {
                    global.acme_dns = Some(sub.args.first().map(|name| {
                        DnsProviderConfig {
                            name: name.clone(),
                            arguments: sub.args[1..]
                                .iter()
                                .map(|arg| arg.as_str().into())
                                .collect(),
                        }
                    }));
                }
                // 🔎 `tls_resolvers <ip…>` — which resolvers a propagation
                // check asks. Not the system resolvers on purpose: a recursive
                // resolver that cached the record's absence keeps saying so.
                "tls_resolvers" => {
                    if sub.args.is_empty() {
                        return Err(AdapterError::ArgumentCount("tls_resolvers".into(), 1, 0));
                    }
                    global.tls_resolvers = sub.args.clone();
                }
                "dns_refresh" => {
                    let Some(value) = sub.args.first() else {
                        return Err(AdapterError::ArgumentCount("dns_refresh".into(), 1, 0));
                    };
                    global.dns_refresh_secs = Some(parse_dns_refresh(value)?);
                }
                // 🏷️ The same reader as the site-level `tls { default_sni … }`,
                // so the two spellings cannot accept different things.
                "default_sni" => {
                    global.default_sni = Some(super::tls::parse_default_sni(&sub)?);
                }
                // 🔄 A fraction of the certificate's lifetime, not a duration.
                // That distinction is the whole point of the option: a fixed
                // window renews a short-lived certificate the moment it is
                // issued, over and over.
                "renewal_window_ratio" => {
                    let raw = expect_one_argument(&sub)?;
                    let ratio = raw.parse::<f64>().ok().filter(|value| {
                        // 🚫 Zero would mean "renew when it has already
                        // expired", and one would mean "renew continuously".
                        // Both are configurations nobody means to write.
                        value.is_finite() && *value > 0.0 && *value < 1.0
                    });
                    match ratio {
                        Some(ratio) => global.renewal_window_ratio = Some(ratio),
                        None => {
                            return Err(AdapterError::InvalidArgument(
                                "renewal_window_ratio".into(),
                                format!(
                                    "`{raw}` is not a fraction between 0 and 1; \
                                     0.3333 renews once a third of the lifetime remains"
                                ),
                            ));
                        }
                    }
                }
                // 🌐 Addresses every site without its own `bind` inherits.
                "default_bind" => {
                    if sub.args.is_empty() {
                        return Err(AdapterError::ArgumentCount("default_bind".into(), 1, 0));
                    }
                    global.default_bind = sub.args.clone();
                }
                "preferred_chains" => {
                    global.preferred_chains = Some(parse_preferred_chains(&sub)?);
                }
                "protocols" => {
                    for arg in &sub.args {
                        match arg.to_lowercase().as_str() {
                            "h1" => global.protocols.push(Protocol::H1),
                            "h2" => global.protocols.push(Protocol::H2),
                            "h3" => global.protocols.push(Protocol::H3),
                            other => {
                                return Err(AdapterError::InvalidArgument(
                                    "protocols".into(),
                                    other.to_string(),
                                ));
                            }
                        }
                    }
                }
                // 🚩 An unrecognised global directive is a typo, and a silently
                // ignored typo is a silently missing setting. `trusted_proxis`
                // would have meant "no trusted proxies at all" while reading
                // like the opposite — the same shape as `encode gzipp` and
                // `listen :443 proxy_protocol`, both of which were fixed for
                // exactly this reason.
                //
                // 🚫 Options that are real Caddy syntax but not implemented
                // here get a distinct message so a migrating Caddyfile is not
                // mistaken for a typo.
                other => {
                    if super::registry::global_option(other).is_some() {
                        // TODO(v0.3): implement the remaining global options
                        // (default_bind, storage, on_demand_tls, ...).
                        return Err(AdapterError::UnsupportedFeature(
                            format!("global: {other}"),
                            "this Caddy global option is not implemented yet".into(),
                        ));
                    }
                    return Err(AdapterError::UnknownDirective(format!("global: {other}")));
                }
            }
        }
    }
    Ok(global)
}

/// 🏠 Whether a host is a bind wildcard rather than a name a client can send.
///
/// These are the addresses that mean "every interface". A request's `Host`
/// header never carries one, so a site registered under one is unreachable —
/// which is why they must collapse to the catch-all name instead.
pub(super) fn is_wildcard_host(host: &str) -> bool {
    matches!(host, "[::]" | "::" | "0.0.0.0" | "[::0]")
}

/// Flatten Caddy's nested `servers [<address>] { ... }` block.
///
/// ```text
/// {
///     servers :80 {
///         protocols h1 h2
///     }
/// }
/// ```
///
/// The children are lifted to the global level, which means the optional
/// address is **dropped**: an option written for one listener applies to every
/// listener here. For `metrics` that is exactly right — upstream hoists it to
/// the app either way, so the address never selected anything to begin with.
/// For the rest it is an approximation, and one worth knowing about before
/// writing two `servers` blocks that disagree.
///
/// 🚫 The nested `metrics` block is checked here rather than after flattening,
/// because flattening is what destroys the distinction: upstream accepts only
/// `per_host` in this position, and once the block has been lifted it is
/// indistinguishable from a global one that accepts three more names. Checking
/// afterwards would silently widen what a `servers` block may say.
pub(super) fn expand_servers_block(
    directives: Vec<Directive>,
) -> Result<Vec<Directive>, AdapterError> {
    let mut result = Vec::new();
    for d in directives {
        if d.name == "servers" {
            if let Some(block) = d.block {
                for child in &block.directives {
                    if child.name == "metrics"
                        && let Some(inner) = &child.block
                    {
                        parse_metrics_options(inner, MetricsScope::Server)?;
                    }
                }
                result.extend(block.directives);
            }
        } else {
            result.push(d);
        }
    }
    Ok(result)
}

/// 📊 Where a `metrics` block was written, which decides what it may say.
#[derive(Clone, Copy, PartialEq, Eq)]
enum MetricsScope {
    /// Directly in the global block, where all three options are available.
    Global,
    /// Nested inside `servers`, where upstream accepts only `per_host` — and
    /// warns that the whole nesting is deprecated in favour of the global form.
    Server,
}

/// 📊 Reads `metrics { per_host | observe_catchall_hosts | otlp }`.
///
/// Every option is a bare flag with no arguments, so an argument is a typo
/// rather than a value and is refused as one. Unknown names are refused too:
/// a metrics option that quietly does nothing is the worst kind of silence,
/// because the configuration and the dashboards both look correct and only the
/// data disagrees.
fn parse_metrics_options(
    block: &Block,
    scope: MetricsScope,
) -> Result<pingclair_core::config::MetricsOptions, AdapterError> {
    let mut options = pingclair_core::config::MetricsOptions::default();
    for option in &block.directives {
        if !option.args.is_empty() {
            return Err(AdapterError::ArgumentCount(
                format!("metrics {}", option.name),
                0,
                option.args.len(),
            ));
        }
        match (option.name.as_str(), scope) {
            ("per_host", _) => options.per_host = true,
            ("observe_catchall_hosts", MetricsScope::Global) => {
                options.observe_catchall_hosts = true;
            }
            ("otlp", MetricsScope::Global) => options.otlp = true,
            // 🚫 Real names, wrong place. Saying so beats "unrecognized",
            // which would send an operator looking for a spelling mistake.
            ("observe_catchall_hosts" | "otlp", MetricsScope::Server) => {
                return Err(AdapterError::InvalidArgument(
                    format!("metrics {}", option.name),
                    "only `per_host` may appear inside a `servers` block; write this one in \
                     the global `metrics` block instead"
                        .into(),
                ));
            }
            (other, _) => {
                return Err(AdapterError::InvalidArgument(
                    "metrics".into(),
                    format!(
                        "`{other}` is not a metrics option; expected `per_host`, \
                         `observe_catchall_hosts` or `otlp`"
                    ),
                ));
            }
        }
    }
    Ok(options)
}

/// 🔗 Reads `preferred_chains smallest` or a block naming issuer common names.
///
/// The two spellings are exclusive, and so are the two block keys — a chain
/// cannot be both "any of these issuers" and "rooted at one of these". Upstream
/// refuses the combinations for the same reason, and refusing here keeps a
/// configuration from meaning one thing on paper and another once loaded.
///
/// ⚠️ What is read here is never acted on; see `GlobalConfig::preferred_chains`
/// for why, and `run.rs` for the startup line that says so out loud.
fn parse_preferred_chains(
    directive: &Directive,
) -> Result<pingclair_core::config::PreferredChains, AdapterError> {
    use pingclair_core::config::PreferredChains;

    if let Some(argument) = directive.args.first() {
        if argument != "smallest" {
            return Err(AdapterError::InvalidArgument(
                "preferred_chains".into(),
                format!("`{argument}` is not a chain preference; expected `smallest`"),
            ));
        }
        if directive.args.len() > 1 || directive.block.is_some() {
            return Err(AdapterError::InvalidArgument(
                "preferred_chains".into(),
                "`smallest` takes nothing else".into(),
            ));
        }
        return Ok(PreferredChains::Smallest);
    }

    let Some(block) = &directive.block else {
        return Err(AdapterError::ArgumentCount("preferred_chains".into(), 1, 0));
    };
    let mut any_common_name: Option<Vec<String>> = None;
    let mut root_common_name: Option<Vec<String>> = None;
    for sub in &block.directives {
        let target = match sub.name.as_str() {
            "any_common_name" => &mut any_common_name,
            "root_common_name" => &mut root_common_name,
            other => {
                return Err(AdapterError::UnknownDirective(format!(
                    "preferred_chains: {other}"
                )));
            }
        };
        if sub.args.is_empty() {
            return Err(AdapterError::ArgumentCount(
                format!("preferred_chains {}", sub.name),
                1,
                0,
            ));
        }
        target
            .get_or_insert_with(Vec::new)
            .extend(sub.args.iter().cloned());
    }
    match (any_common_name, root_common_name) {
        (Some(names), None) => Ok(PreferredChains::AnyCommonName(names)),
        (None, Some(names)) => Ok(PreferredChains::RootCommonName(names)),
        (Some(_), Some(_)) => Err(AdapterError::InvalidArgument(
            "preferred_chains".into(),
            "`any_common_name` and `root_common_name` cannot both be set".into(),
        )),
        (None, None) => Err(AdapterError::InvalidArgument(
            "preferred_chains".into(),
            "the block sets nothing; name `any_common_name` or `root_common_name`".into(),
        )),
    }
}

#[cfg(test)]
mod admin_origin_tests {
    use crate::compile;

    /// 🌐 The block that used to be refused now configures the endpoint.
    #[test]
    fn origins_and_enforce_origin_reach_the_config() {
        let config = compile(
            "{\n    admin :2019 {\n        origins http://admin.example.com\n        enforce_origin\n    }\n}\n\
             http://:8080 {\n    respond \"ok\"\n}\n",
        )
        .expect("the admin block compiles");
        let admin = config.admin.expect("admin configured");
        assert_eq!(admin.origins, vec!["http://admin.example.com".to_string()]);
        assert!(admin.enforce_origin);
    }

    /// 🎯 An admin directive with no block keeps working and enforces nothing,
    /// so adding the feature did not tighten anyone's existing config.
    #[test]
    fn a_bare_admin_directive_enforces_nothing() {
        let config = compile("{\n    admin :2019\n}\nhttp://:8080 {\n    respond \"ok\"\n}\n")
            .expect("compiles");
        let admin = config.admin.expect("admin configured");
        assert!(admin.origins.is_empty());
        assert!(!admin.enforce_origin);
    }

    /// 🚫 `origins` with nothing after it is a mistake — it reads as "allow
    /// these" while allowing none, which would silently lock the operator out.
    #[test]
    fn empty_origins_is_rejected() {
        let error = compile(
            "{\n    admin :2019 {\n        origins\n    }\n}\nhttp://:8080 {\n    respond \"ok\"\n}\n",
        )
        .expect_err("an empty allow list must not compile");
        assert!(error.to_string().contains("origin"));
    }
}
