// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧭 Pingclair's declarative language lowers directly to shared configuration.

pub(crate) mod http;
pub(crate) mod log;
pub(crate) mod tcp;

use http::http_listener;
use tcp::listener;

pub(crate) use http::is_http_condition;

use crate::attributes::{Attr, resolve_attribute};
use crate::bindings::Bindings;
use crate::syntax::{self, Call, Declaration, Position, Value};
use pingclair_core::config::{
    AccessControlConfig, AcmeServerConfig, AcmeServerPolicy, AdminConfig, AutoHttpsMode,
    BasicAuthAlgorithm, CircuitBreakerConfig, Encoding, ErrorRouteConfig, FastCgiTransportConfig,
    ForwardAuthConfig, ForwardAuthHeaderMap, HandlerConfig, HandlerElement, HeaderReplacement,
    HealthCheckConfig, IpRanges, Layer4Matcher, Layer4Route, Layer4Server, Layer4TlsMatcher,
    ListenerOptions, LoadBalanceConfig, LogConfig, LogFormat, LogOutput, LogRotation, Matcher,
    MatcherCondition, OverloadConfig, PRIVATE_RANGES, PingclairConfig, ProxyUpstream, RateLimitKey,
    ResourceLimitsConfig, ResponseHandlerConfig, ResponseMatcher, RetryConfig, ReverseProxyConfig,
    RouteConfig, ServerConfig, TlsConfig, UpstreamHttpVersions, UpstreamTlsConfig,
    normalize_listen_addr,
};

/// 📍 Reports location and expected structure without echoing configuration values.
#[derive(Debug, thiserror::Error)]
#[error("line {line}:{column}: {message}")]
pub struct Error {
    pub(crate) line: usize,
    pub(crate) column: usize,
    pub(crate) message: String,
}

/// 🔐 Refuses a `@Secret` value anywhere the configuration would record it —
/// except the one field family that stores secrets on purpose.
///
/// 📌 The DNS-01 provider arguments are `SecretString`s: the runtime has to
/// read them, so storing the value *is* the point and every surface that dumps
/// configuration masks them. Anywhere else the attribute's promise ("never
/// shown") would be broken by the write itself, so the use is refused rather
/// than masked after the fact.
fn reject_secret_values(call: &Call) -> Result<(), Error> {
    for (_, value) in &call.args {
        reject_secret(value)?;
    }
    for child in call.body.iter().flatten() {
        reject_secret_values(child)?;
    }
    for modifier in &call.modifiers {
        reject_secret_values(modifier)?;
    }
    Ok(())
}

/// 🔐 The value half of the same walk.
fn reject_secret(value: &Value) -> Result<(), Error> {
    match value {
        Value::Secret { at, .. } => Err(at.error(
            "a @Secret value can only flow into a field that stores secrets — the DNS-01 \
             provider arguments. Anywhere else it would be written into the configuration \
             and everything that dumps it",
        )),
        Value::Array(items) => items.iter().try_for_each(reject_secret),
        // 🔐 `.dns(...)` is the one subtree whose arguments are stored as
        // `SecretString`s; its reader accepts the marked values explicitly.
        Value::Typed(call) if call.name == "dns" => Ok(()),
        Value::Typed(call) | Value::Component(call) => reject_secret_values(call),
        _ => Ok(()),
    }
}

/// 🧭 Recognizes native declarations without guessing from a file extension.
pub fn is_native(source: &str) -> bool {
    let mut rest = source.trim_start();
    while let Some(comment) = rest.strip_prefix("//") {
        rest = comment
            .split_once('\n')
            .map_or("", |(_, tail)| tail)
            .trim_start();
    }
    if rest
        .strip_prefix("let")
        .is_some_and(|tail| tail.starts_with(char::is_whitespace))
    {
        return true;
    }
    if rest.starts_with('@') {
        return true;
    }
    let name_len = rest
        .bytes()
        .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        .count();
    name_len > 0
        && rest.as_bytes()[0].is_ascii_alphabetic()
        && rest[name_len..].trim_start().starts_with('(')
}

/// 🗂️ The global declarations a native file makes, by name.
///
/// 📌 The *value* a declaration carries cannot answer this: `Metrics(enabled:
/// false)` and saying nothing at all compile to the same configuration, so a
/// merge that compares values cannot tell an explicit `false` from silence.
/// The syntax can, which is why the merge asks here instead of guessing.
pub(crate) fn declared_globals(source: &str) -> Result<Vec<String>, Error> {
    let mut names = Vec::new();
    for declaration in syntax::parse(source)? {
        if let Declaration::Component { call, .. } = declaration
            && !matches!(call.name.as_str(), "TCPListener" | "HTTPListener")
        {
            names.push(call.name);
        }
    }
    Ok(names)
}

/// 🏷️ The argument labels the global declarations accept, named once for the
/// parser and `describe`.
pub(crate) const TRUSTED_PROXIES_LABELS: &[&str] = &["ranges", "headers"];
pub(crate) const STORAGE_LABELS: &[&str] = &["root"];
pub(crate) const LOG_LABELS: &[&str] = &["output", "level"];
pub(crate) const AUTOMATIC_TLS_LABELS: &[&str] =
    &["mode", "httpPort", "httpsPort", "skipInstallTrust"];

pub(super) fn adapt(source: &str) -> Result<PingclairConfig, Error> {
    let declarations = syntax::parse(source)?;
    let mut bindings = Bindings::default();
    bindings.declare(&declarations)?;
    let mut config = PingclairConfig::default();
    let mut seen = std::collections::HashSet::new();
    for declaration in &declarations {
        let call = match declaration {
            Declaration::Binding {
                attributes,
                name,
                value,
                ..
            } => {
                bindings.bind(attributes, name, value)?;
                continue;
            }
            Declaration::Component { attributes, call } => {
                if let Some(attribute) = attributes.first() {
                    let name = match resolve_attribute(attribute)? {
                        Attr::Matcher => "@Matcher",
                        Attr::Secret => "@Secret",
                    };
                    return Err(attribute.at.error(format!("{name} applies to bindings")));
                }
                let call = bindings.expand_call(call)?;
                // 🔐 Before anything reads a value: a secret that reaches the
                // configuration would be written into it, into the admin JSON
                // and into every log that dumps either.
                reject_secret_values(&call)?;
                call
            }
        };
        if call.name == "Pingclair" {
            return Err(call.at.error(
                "the Pingclair(version: ...) header was removed; declare components at the top level",
            ));
        }
        if !matches!(call.name.as_str(), "TCPListener" | "HTTPListener")
            && !seen.insert(call.name.clone())
        {
            return Err(call.at.error("duplicate global declaration"));
        }
        match call.name.as_str() {
            "TCPListener" => config.layer4.push(listener(&call)?),
            "HTTPListener" => http_listener(&call, &mut config)?,
            "Admin" => {
                call.leaf(&["listen"])?;
                config.admin = Some(AdminConfig {
                    listen: call.string("listen")?,
                    enabled: true,
                    api_key: None,
                    origins: Vec::new(),
                    enforce_origin: false,
                });
            }
            "Metrics" => {
                call.leaf(&["enabled"])?;
                config.global.metrics = call.boolean("enabled")?;
            }
            "Shutdown" => {
                call.leaf(&["grace"])?;
                let millis = call.measure("grace", false)?;
                if millis % 1000 != 0 {
                    return Err(call.at.error("shutdown grace requires whole seconds"));
                }
                config.global.grace_period_secs = Some(millis / 1000);
            }
            "TrustedProxies" => {
                let trusted = parse_trusted_proxies(&call, "TrustedProxies")?;
                if let Some(ranges) = trusted.ranges {
                    config.global.trusted_proxies = ranges;
                }
                if let Some(headers) = trusted.headers {
                    config.global.client_ip_headers = headers;
                }
            }
            "UnderscoreHeaders" => {
                config.global.expected_underscore_headers = parse_underscore_headers(&call)?;
            }
            "Storage" => {
                call.leaf(STORAGE_LABELS)?;
                let root = call.string("root")?;
                if root.is_empty() {
                    return Err(call.at.error("Storage root must not be empty"));
                }
                config.global.storage_path = Some(root);
            }
            "Log" => {
                call.leaf(LOG_LABELS)?;
                if call.get("output").is_none() && call.get("level").is_none() {
                    return Err(call.at.error("Log needs output:, level:, or both"));
                }
                let output = match call.get("output") {
                    Some(value) => log::log_output(value, call.at)?,
                    // 📌 The unnamed global logger writes to stdout unless told
                    // otherwise, which is the same default the Caddyfile has.
                    None => LogOutput::Stdout,
                };
                let level = match call.get("level") {
                    Some(value) => Some(log::log_level(value, call.at)?),
                    None => None,
                };
                config.logging.default = Some(process_log(output, level));
            }
            "AutomaticTLS" => {
                call.leaf(AUTOMATIC_TLS_LABELS)?;
                if call.get("mode").is_none()
                    && call.get("httpPort").is_none()
                    && call.get("httpsPort").is_none()
                    && call.get("skipInstallTrust").is_none()
                {
                    return Err(call.at.error(
                        "AutomaticTLS needs at least one setting: mode:, httpPort:, httpsPort: \
                         or skipInstallTrust:",
                    ));
                }
                if let Some(mode) = call.get("mode") {
                    let Value::Typed(case) = mode else {
                        return Err(call.at.error(
                            "mode takes .automatic, .off, .disableRedirects or .ignoreLoadedCerts",
                        ));
                    };
                    config.global.auto_https = match case.name.as_str() {
                        "automatic" => {
                            expect_bare_case(case, ".automatic")?;
                            AutoHttpsMode::On
                        }
                        "off" => {
                            expect_bare_case(case, ".off")?;
                            AutoHttpsMode::Off
                        }
                        "disableRedirects" => {
                            expect_bare_case(case, ".disableRedirects")?;
                            AutoHttpsMode::DisableRedirects
                        }
                        "ignoreLoadedCerts" => {
                            expect_bare_case(case, ".ignoreLoadedCerts")?;
                            AutoHttpsMode::IgnoreLoadedCerts
                        }
                        "disableCerts" => {
                            return Err(case.at.error(
                                "disable_certs is not implemented; expected .automatic, .off, \
                                 .disableRedirects or .ignoreLoadedCerts",
                            ));
                        }
                        other => {
                            return Err(case.at.error(format!(
                                "unknown auto-HTTPS mode `.{other}`; expected .automatic, .off, \
                                 .disableRedirects or .ignoreLoadedCerts"
                            )));
                        }
                    };
                }
                if let Some(value) = call.get("httpPort") {
                    config.global.http_port = parse_port(value, "httpPort", call.at)?;
                }
                if let Some(value) = call.get("httpsPort") {
                    config.global.https_port = parse_port(value, "httpsPort", call.at)?;
                }
                if let Some(value) = call.get("skipInstallTrust") {
                    match value {
                        Value::Bool(true) => config.global.skip_install_trust = true,
                        Value::Bool(false) => {
                            return Err(call.at.error(
                                "skipInstallTrust only accepts true: this build never installs \
                                 the internal root at startup, so false would describe a step \
                                 that never happens",
                            ));
                        }
                        _ => return Err(call.at.error("skipInstallTrust takes true")),
                    }
                }
            }
            _ => {
                return Err(call.at.error(
                    "unknown global declaration; expected TCPListener, HTTPListener, Admin, \
                     Metrics, Shutdown, TrustedProxies, UnderscoreHeaders, Storage, Log or \
                     AutomaticTLS",
                ));
            }
        }
    }
    // 📌 A file is allowed to hold nothing but declarations: `Admin`, `Metrics`,
    // `Shutdown`, `TrustedProxies`, `UnderscoreHeaders`, `Storage`, `Log` and
    // `AutomaticTLS` are options of the server, not of a listener, and a
    // directory splits them into their own file. Whether the *merged* result
    // can serve anything is a question for the runtime.
    Ok(config)
}

/// 🌐 `ranges:` accepts CIDR strings and `.privateRanges`, which expands to the
/// six prefixes every other private-range spelling uses.
fn parse_ranges(value: &Value, at: Position) -> Result<Vec<String>, Error> {
    let Value::Array(items) = value else {
        return Err(at.error("ranges takes an array of CIDR strings or .privateRanges"));
    };
    if items.is_empty() {
        return Err(at.error("ranges must not be empty"));
    }
    let mut ranges = Vec::new();
    for item in items {
        match item {
            Value::String(text) => {
                if text.parse::<ipnet::IpNet>().is_err()
                    && text.parse::<std::net::IpAddr>().is_err()
                {
                    return Err(at.error(format!("ranges contains invalid IP or CIDR `{text}`")));
                }
                ranges.push(text.clone());
            }
            Value::Typed(case) if case.name == "privateRanges" => {
                expect_bare_case(case, ".privateRanges")?;
                ranges.extend(PRIVATE_RANGES.iter().map(|range| (*range).to_string()));
            }
            Value::Typed(case) => {
                return Err(case.at.error(format!(
                    "unknown range `.{name}`; expected .privateRanges or a quoted CIDR",
                    name = case.name
                )));
            }
            _ => {
                return Err(at.error("ranges takes an array of CIDR strings or .privateRanges"));
            }
        }
    }
    Ok(ranges)
}

/// 🛡️ The two halves a trust list names.
///
/// 📌 `None` is "this label was not written", which is what makes a listener
/// modifier able to replace half of the global list and keep the other half.
pub(super) struct TrustedProxiesArgs {
    pub(super) ranges: Option<Vec<String>>,
    pub(super) headers: Option<Vec<String>>,
}

/// 🛡️ Reads `ranges:` and `headers:` for `TrustedProxies(…)` and for the
/// listener modifier `.trustedProxies(…)`.
///
/// 🚫 One grammar, one implementation: the two spellings sit at different
/// levels, and a value rule that lived in only one of them would let the same
/// line mean two things depending on where it was written.
fn parse_trusted_proxies(call: &Call, what: &str) -> Result<TrustedProxiesArgs, Error> {
    call.leaf(TRUSTED_PROXIES_LABELS)?;
    if call.get("ranges").is_none() && call.get("headers").is_none() {
        return Err(call
            .at
            .error(format!("{what} needs ranges:, headers:, or both")));
    }
    Ok(TrustedProxiesArgs {
        ranges: call
            .get("ranges")
            .map(|value| parse_ranges(value, call.at))
            .transpose()?,
        headers: call
            .get("headers")
            .map(|value| parse_header_names(value, call.at))
            .transpose()?,
    })
}

/// 🛡️ The allowlist `UnderscoreHeaders([…])` declares and `.underscoreHeaders([…])`
/// overrides with: exactly one array of header names, each an exact name or a
/// trailing-star prefix.
///
/// 📌 The entries are checked here, where the line is, *and* by
/// [`crate::underscore_headers::validate`], which every configuration path
/// goes through: the Admin JSON path never sees a `Position`.
pub(super) fn parse_underscore_headers(call: &Call) -> Result<Vec<String>, Error> {
    if call.body.is_some() {
        return Err(call.at.error("the underscore allowlist takes no block"));
    }
    if !call.modifiers.is_empty() {
        return Err(call.at.error("the underscore allowlist takes no modifiers"));
    }
    let [(None, Value::Array(items))] = call.args.as_slice() else {
        return Err(call.at.error(
            "expected one array of quoted header names, for example [\"X_Probe\", \"Webhook_*\"]",
        ));
    };
    if items.is_empty() {
        return Err(call.at.error(
            "an empty allowlist is not accepted: name at least one header that survives, or \
             leave the declaration out",
        ));
    }
    let mut names = Vec::with_capacity(items.len());
    for item in items {
        let Value::String(name) = item else {
            return Err(call.at.error("the list takes quoted header names"));
        };
        if !crate::underscore_headers::well_formed(name) {
            return Err(call.at.error(format!(
                "`{name}` {}",
                crate::underscore_headers::ENTRY_REQUIREMENT
            )));
        }
        names.push(name.clone());
    }
    Ok(names)
}

/// 🛡️ `headers:` names the request headers a trusted proxy may set the client
/// address in, in the order they are consulted.
fn parse_header_names(value: &Value, at: Position) -> Result<Vec<String>, Error> {
    let Value::Array(items) = value else {
        return Err(at.error(
            "headers takes an array of .xForwardedFor, .forwarded, .xRealIP, .cfConnectingIP \
             or .header(\"Name\")",
        ));
    };
    if items.is_empty() {
        return Err(at.error(
            "headers must not be empty: an empty list and the built-in set would read the same",
        ));
    }
    let mut names = Vec::new();
    for item in items {
        let Value::Typed(case) = item else {
            return Err(
                at.error("headers takes typed values such as .xRealIP or .header(\"X-Name\")")
            );
        };
        let name = match case.name.as_str() {
            "xForwardedFor" => {
                expect_bare_case(case, ".xForwardedFor")?;
                "X-Forwarded-For".to_string()
            }
            "forwarded" => {
                expect_bare_case(case, ".forwarded")?;
                "Forwarded".to_string()
            }
            "xRealIP" => {
                expect_bare_case(case, ".xRealIP")?;
                "X-Real-IP".to_string()
            }
            "cfConnectingIP" => {
                expect_bare_case(case, ".cfConnectingIP")?;
                "CF-Connecting-IP".to_string()
            }
            "header" => {
                if case.body.is_some() || !case.modifiers.is_empty() {
                    return Err(case.at.error(".header does not take a block or modifiers"));
                }
                let [(None, Value::String(name))] = case.args.as_slice() else {
                    return Err(case.at.error(".header takes one quoted header name"));
                };
                // 📌 `::http` is the crate; the bare name is this module's own
                // `http` child.
                if ::http::HeaderName::from_bytes(name.as_bytes()).is_err() {
                    return Err(case
                        .at
                        .error(format!("`{name}` is not a valid header name")));
                }
                name.clone()
            }
            other => {
                return Err(case.at.error(format!(
                    "unknown header `.{other}`; expected .xForwardedFor, .forwarded, .xRealIP, \
                     .cfConnectingIP or .header(\"Name\")"
                )));
            }
        };
        names.push(name);
    }
    Ok(names)
}

/// 🪵 A process logger with the model's defaults for everything but output and
/// level; the log batch extends this declaration along the same fields.
fn process_log(output: LogOutput, level: Option<&str>) -> LogConfig {
    LogConfig {
        output,
        format: LogFormat::default(),
        level: level.map(str::to_string),
        exclude_fields: Vec::new(),
        rotation: LogRotation::default(),
        request_headers: Vec::new(),
        response_headers: Vec::new(),
        include_tls: false,
        hostnames: Vec::new(),
        include: Vec::new(),
        exclude: Vec::new(),
        sampling: None,
    }
}

/// 🔢 A port for `httpPort:`/`httpsPort:`.
fn parse_port(value: &Value, setting: &str, at: Position) -> Result<u16, Error> {
    match value {
        Value::Number(port) if (1..=65535).contains(port) => Ok(*port as u16),
        _ => Err(at.error(format!("{setting} takes a port between 1 and 65535"))),
    }
}

/// 🧷 Checks a typed case takes no block, no modifiers and no arguments.
fn expect_bare_case(case: &Call, what: &str) -> Result<(), Error> {
    if case.body.is_some() {
        return Err(case.at.error(format!("{what} does not take a block")));
    }
    if !case.modifiers.is_empty() {
        return Err(case.at.error(format!("{what} does not take modifiers")));
    }
    if !case.args.is_empty() {
        return Err(case.at.error(format!("{what} takes no arguments")));
    }
    Ok(())
}

/// ⏱️ A typed duration value (`.seconds(30)`, `.minutes(2)`, `.hours(1)`,
/// `.milliseconds(500)`) in milliseconds.
pub(super) fn duration_millis(value: &Value, what: &str, at: Position) -> Result<u64, Error> {
    let Value::Typed(unit) = value else {
        return Err(at.error(format!(
            "{what} takes a duration with an explicit unit such as .seconds(30) or .minutes(2)"
        )));
    };
    if unit.body.is_some() {
        return Err(unit.at.error(format!("{what} does not take a block")));
    }
    if !unit.modifiers.is_empty() {
        return Err(unit.at.error(format!("{what} does not take modifiers")));
    }
    let [(None, Value::Number(number))] = unit.args.as_slice() else {
        return Err(unit
            .at
            .error(format!("{what} takes one unsigned integer inside its unit")));
    };
    let millis = match unit.name.as_str() {
        "milliseconds" => *number,
        "seconds" => number
            .checked_mul(1_000)
            .ok_or_else(|| unit.at.error("duration exceeds the supported range"))?,
        "minutes" => number
            .checked_mul(60_000)
            .ok_or_else(|| unit.at.error("duration exceeds the supported range"))?,
        "hours" => number
            .checked_mul(3_600_000)
            .ok_or_else(|| unit.at.error("duration exceeds the supported range"))?,
        other => {
            return Err(unit.at.error(format!(
                "unknown unit `.{other}`; expected .milliseconds, .seconds, .minutes or .hours"
            )));
        }
    };
    Ok(millis)
}

/// ⏱️ The same duration in whole seconds.
///
/// 📌 Sub-second values round up, the way the Caddyfile adapter rounds its own
/// sub-second durations: rounding down would turn "wait a moment" into "do
/// not wait".
pub(super) fn duration_secs(value: &Value, what: &str, at: Position) -> Result<u64, Error> {
    Ok(duration_millis(value, what, at)?.div_ceil(1_000))
}

impl Call {
    fn get(&self, name: &str) -> Option<&Value> {
        self.args
            .iter()
            .find(|(key, _)| key.as_deref() == Some(name))
            .map(|(_, value)| value)
    }
    fn labels(&self, allowed: &[&str]) -> Result<(), Error> {
        if self
            .args
            .iter()
            .any(|(key, _)| !key.as_deref().is_some_and(|key| allowed.contains(&key)))
        {
            return Err(self.at.error("unknown or missing argument label"));
        }
        Ok(())
    }
    fn leaf(&self, allowed: &[&str]) -> Result<(), Error> {
        self.labels(allowed)?;
        self.no_modifiers()?;
        if self.body.is_some() {
            return Err(self.at.error("this declaration does not accept a block"));
        }
        Ok(())
    }
    fn no_modifiers(&self) -> Result<(), Error> {
        if !self.modifiers.is_empty() {
            return Err(self.at.error("this component does not accept modifiers"));
        }
        Ok(())
    }
    fn block(&self) -> Result<&[Call], Error> {
        self.body
            .as_deref()
            .ok_or_else(|| self.at.error("expected a configuration block"))
    }
    fn string(&self, key: &str) -> Result<String, Error> {
        match self.get(key) {
            Some(Value::String(value)) => Ok(value.clone()),
            _ => Err(self.at.error(format!("{key} requires a quoted string"))),
        }
    }
    fn integer(&self, key: &str) -> Result<u64, Error> {
        match self.get(key) {
            Some(Value::Number(value)) => Ok(*value),
            _ => Err(self.at.error(format!("{key} requires an unsigned integer"))),
        }
    }
    fn boolean(&self, key: &str) -> Result<bool, Error> {
        match self.get(key) {
            Some(Value::Bool(value)) => Ok(*value),
            _ => Err(self.at.error(format!("{key} requires true or false"))),
        }
    }
    fn strings(&self, key: &str) -> Result<Vec<String>, Error> {
        let Some(value) = self.get(key) else {
            return Ok(Vec::new());
        };
        let Value::Array(values) = value else {
            return Err(self.at.error(format!("{key} requires an array of strings")));
        };
        if values.is_empty() {
            return Err(self.at.error(format!("{key} must not be empty")));
        }
        values
            .iter()
            .map(|value| match value {
                Value::String(value) => Ok(value.clone()),
                _ => Err(self.at.error(format!("{key} requires an array of strings"))),
            })
            .collect()
    }
    fn measure(&self, key: &str, bytes: bool) -> Result<u64, Error> {
        let Some(Value::Typed(value)) = self.get(key) else {
            return Err(self.at.error(format!("{key} requires an explicit unit")));
        };
        let [(None, Value::Number(number))] = value.args.as_slice() else {
            return Err(value.at.error("unit requires one unsigned integer"));
        };
        let factor = match (bytes, value.name.as_str()) {
            (true, "bytes") => 1,
            (true, "kibibytes") => 1024,
            (true, "mebibytes") => 1024 * 1024,
            (false, "milliseconds") => 1,
            (false, "seconds") => 1000,
            (false, "minutes") => 60_000,
            (false, "hours") => 3_600_000,
            _ => return Err(value.at.error("unknown unit or wrong unit type")),
        };
        number
            .checked_mul(factor)
            .ok_or_else(|| value.at.error("unit value exceeds supported range"))
    }
}

#[cfg(test)]
mod globals_tests;
#[cfg(test)]
mod log_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tls_tests;
