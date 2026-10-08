// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧭 Pingclair's declarative language lowers directly to shared configuration.

pub(crate) mod http;
pub(crate) mod tcp;

use http::http_listener;
use tcp::listener;

pub(crate) use http::is_http_condition;

use crate::attributes::{Attr, resolve_attribute};
use crate::bindings::Bindings;
use crate::syntax::{self, Call, Declaration, Position, Value};
use pingclair_core::config::{
    AccessControlConfig, AcmeServerConfig, AcmeServerPolicy, AdminConfig, BasicAuthAlgorithm,
    CircuitBreakerConfig, Encoding, ErrorRouteConfig, FastCgiTransportConfig, ForwardAuthConfig,
    ForwardAuthHeaderMap, HandlerConfig, HandlerElement, HeaderReplacement, HealthCheckConfig,
    IpRanges, Layer4Matcher, Layer4Route, Layer4Server, Layer4TlsMatcher, ListenerOptions,
    LoadBalanceConfig, LogConfig, LogFormat, LogOutput, LogRotation, Matcher, MatcherCondition,
    OverloadConfig, PRIVATE_RANGES, PingclairConfig, ProxyUpstream, RateLimitKey,
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
            _ => {
                return Err(call.at.error(
                    "unknown global declaration; expected TCPListener, Admin, Metrics, or Shutdown",
                ));
            }
        }
    }
    // 📌 A file is allowed to hold nothing but declarations: `Admin`, `Metrics`
    // and `Shutdown` are options of the server, not of a listener, and a
    // directory splits them into their own file. Whether the *merged* result
    // can serve anything is a question for the runtime.
    Ok(config)
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
mod tests;
#[cfg(test)]
mod tls_tests;
