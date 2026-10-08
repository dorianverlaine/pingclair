// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧭 Pingclair's declarative language lowers directly to shared configuration.

mod syntax;
use pingclair_core::config::{
    AdminConfig, Layer4Matcher, Layer4Route, Layer4Server, Layer4TlsMatcher, PingclairConfig,
};
use syntax::{Call, Declaration, Value};

/// 📍 Reports location and expected structure without echoing configuration values.
#[derive(Debug, thiserror::Error)]
#[error("line {line}:{column}: {message}")]
pub struct Error {
    line: usize,
    column: usize,
    message: String,
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
    let name_len = rest
        .bytes()
        .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        .count();
    name_len > 0
        && rest.as_bytes()[0].is_ascii_alphabetic()
        && rest[name_len..].trim_start().starts_with('(')
}

pub(super) fn adapt(source: &str) -> Result<PingclairConfig, Error> {
    let declarations = syntax::parse(source)?;
    let mut bindings = Bindings::default();
    bindings.declare(&declarations)?;
    let mut config = PingclairConfig::default();
    let mut seen = std::collections::HashSet::new();
    for declaration in &declarations {
        let call = match declaration {
            Declaration::Binding { name, value, .. } => {
                bindings.bind(name, value)?;
                continue;
            }
            Declaration::Component(call) => bindings.expand_call(call)?,
        };
        if call.name == "Pingclair" {
            return Err(call.at.error(
                "the Pingclair(version: ...) header was removed; declare components at the top level",
            ));
        }
        if call.name != "TCPListener" && !seen.insert(call.name.clone()) {
            return Err(call.at.error("duplicate global declaration"));
        }
        match call.name.as_str() {
            "TCPListener" => config.layer4.push(listener(&call)?),
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
    if config.layer4.is_empty() {
        return Err(
            syntax::Position { line: 1, column: 1 }.error("expected at least one TCPListener")
        );
    }
    Ok(config)
}

/// 🧩 Expansion bounds keep reuse from turning into unbounded work.
const MAX_EXPANDED_NODES: usize = 4096;
const MAX_EXPANDED_BYTES: usize = 8 * 1024 * 1024;

#[derive(Default)]
struct Bindings {
    names: std::collections::HashSet<String>,
    resolved: std::collections::HashMap<String, Bound>,
    nodes: usize,
    bytes: usize,
}

struct Bound {
    fragment: Fragment,
    nodes: usize,
    bytes: usize,
}

enum Fragment {
    Value(Value),
    Component(Call),
}

impl Bindings {
    fn declare(&mut self, declarations: &[Declaration]) -> Result<(), Error> {
        for declaration in declarations {
            let Declaration::Binding { name, at, .. } = declaration else {
                continue;
            };
            if !name.starts_with(|c: char| c.is_ascii_lowercase())
                || matches!(name.as_str(), "let" | "true" | "false")
            {
                return Err(at.error(
                    "binding names must start with a lowercase letter and cannot be reserved",
                ));
            }
            if !self.names.insert(name.clone()) {
                return Err(at.error("duplicate immutable binding"));
            }
        }
        Ok(())
    }

    fn bind(&mut self, name: &str, value: &Value) -> Result<(), Error> {
        let fragment = match value {
            Value::Component(call) => Fragment::Component(self.expand_call(call)?),
            other => Fragment::Value(self.expand_value(other)?),
        };
        let (nodes, bytes) = fragment_size(&fragment);
        self.resolved.insert(
            name.to_string(),
            Bound {
                fragment,
                nodes,
                bytes,
            },
        );
        Ok(())
    }

    fn expand_value(&mut self, value: &Value) -> Result<Value, Error> {
        match value {
            Value::Reference { name, at } => {
                let (value, nodes, bytes) = match self.resolved.get(name) {
                    Some(Bound {
                        fragment: Fragment::Value(value),
                        nodes,
                        bytes,
                    }) => (value.clone(), *nodes, *bytes),
                    Some(_) => {
                        return Err(at.error("expected a value; this binding names a component"));
                    }
                    None => return Err(self.unresolved(name, *at)),
                };
                self.charge(*at, nodes, bytes)?;
                Ok(value)
            }
            Value::Array(values) => Ok(Value::Array(
                values
                    .iter()
                    .map(|item| self.expand_value(item))
                    .collect::<Result<Vec<_>, _>>()?,
            )),
            Value::Typed(call) => Ok(Value::Typed(self.expand_call(call)?)),
            Value::Component(call) => Ok(Value::Component(self.expand_call(call)?)),
            literal => Ok(literal.clone()),
        }
    }

    fn expand_call(&mut self, call: &Call) -> Result<Call, Error> {
        if call.args.is_empty() && call.body.is_none() && call.modifiers.is_empty() {
            match self.resolved.get(&call.name) {
                Some(Bound {
                    fragment: Fragment::Component(inner),
                    nodes,
                    bytes,
                }) => {
                    let (inner, nodes, bytes) = (inner.clone(), *nodes, *bytes);
                    self.charge(call.at, nodes, bytes)?;
                    return Ok(inner);
                }
                Some(_) => {
                    return Err(call
                        .at
                        .error("expected a component; this binding names a value"));
                }
                None => {}
            }
            if self.names.contains(&call.name) {
                return Err(call.at.error("binding used before its declaration"));
            }
        }
        let mut args = Vec::with_capacity(call.args.len());
        for (label, value) in &call.args {
            args.push((label.clone(), self.expand_value(value)?));
        }
        let body = match &call.body {
            Some(children) => {
                let mut expanded = Vec::with_capacity(children.len());
                for child in children {
                    expanded.push(self.expand_call(child)?);
                }
                Some(expanded)
            }
            None => None,
        };
        let mut modifiers = Vec::with_capacity(call.modifiers.len());
        for modifier in &call.modifiers {
            modifiers.push(self.expand_call(modifier)?);
        }
        Ok(Call {
            name: call.name.clone(),
            args,
            body,
            modifiers,
            at: call.at,
        })
    }

    fn charge(&mut self, at: syntax::Position, nodes: usize, bytes: usize) -> Result<(), Error> {
        self.nodes = self.nodes.saturating_add(nodes);
        self.bytes = self.bytes.saturating_add(bytes);
        if self.nodes > MAX_EXPANDED_NODES || self.bytes > MAX_EXPANDED_BYTES {
            return Err(at.error("configuration expansion exceeds 4096 components or 8 MiB"));
        }
        Ok(())
    }

    fn unresolved(&self, name: &str, at: syntax::Position) -> Error {
        if self.names.contains(name) {
            at.error("binding used before its declaration")
        } else {
            at.error(format!("unknown binding '{name}'"))
        }
    }
}

fn fragment_size(fragment: &Fragment) -> (usize, usize) {
    let mut nodes = 0;
    let mut bytes = 0;
    match fragment {
        Fragment::Value(value) => count_value(value, &mut nodes, &mut bytes),
        Fragment::Component(call) => count_call(call, &mut nodes, &mut bytes),
    }
    (nodes, bytes)
}

fn count_call(call: &Call, nodes: &mut usize, bytes: &mut usize) {
    *nodes += 1;
    *bytes += call.name.len();
    for (label, value) in &call.args {
        *nodes += 1;
        *bytes += label.as_deref().map_or(0, str::len);
        count_value(value, nodes, bytes);
    }
    if let Some(children) = &call.body {
        for child in children {
            count_call(child, nodes, bytes);
        }
    }
    for modifier in &call.modifiers {
        count_call(modifier, nodes, bytes);
    }
}

fn count_value(value: &Value, nodes: &mut usize, bytes: &mut usize) {
    *nodes += 1;
    match value {
        Value::String(text) => *bytes += text.len(),
        Value::Array(values) => {
            for item in values {
                count_value(item, nodes, bytes);
            }
        }
        Value::Typed(call) | Value::Component(call) => count_call(call, nodes, bytes),
        Value::Reference { name, .. } => *bytes += name.len(),
        Value::Number(_) | Value::Bool(_) => {}
    }
}

fn listener(call: &Call) -> Result<Layer4Server, Error> {
    call.labels(&["on"])?;
    let mut server = Layer4Server::new(call.string("on")?);
    let mut seen = std::collections::HashSet::new();
    for child in call.block()? {
        match child.name.as_str() {
            "Route" | "Fallback" => server.routes.push(route(child)?),
            _ => {
                return Err(child.at.error(
                    "TCPListener children must be Route, Fallback, or a component binding",
                ));
            }
        }
    }
    for child in &call.modifiers {
        if !seen.insert(&child.name) {
            return Err(child.at.error("duplicate listener modifier"));
        }
        match child.name.as_str() {
            "limits" => {
                child.leaf(&["connections", "preread", "relay"])?;
                if child.get("connections").is_some() {
                    server.max_connections = usize::try_from(child.integer("connections")?)
                        .map_err(|_| child.at.error("connection count exceeds platform range"))?;
                }
                if child.get("preread").is_some() {
                    server.preread_buffer_size =
                        usize::try_from(child.measure("preread", true)?)
                            .map_err(|_| child.at.error("buffer size exceeds platform range"))?;
                }
                if child.get("relay").is_some() {
                    server.proxy_buffer_size = usize::try_from(child.measure("relay", true)?)
                        .map_err(|_| child.at.error("buffer size exceeds platform range"))?;
                }
            }
            "timeouts" => {
                child.leaf(&["preread", "connect", "idle"])?;
                if child.get("preread").is_some() {
                    server.preread_timeout_ms = child.measure("preread", false)?;
                }
                if child.get("connect").is_some() {
                    server.proxy_connect_timeout_ms = child.measure("connect", false)?;
                }
                if child.get("idle").is_some() {
                    server.proxy_timeout_ms = child.measure("idle", false)?;
                }
            }
            "halfClose" => {
                child.leaf(&["enabled"])?;
                server.proxy_half_close = child.boolean("enabled")?;
            }
            _ => return Err(child.at.error("unknown TCPListener modifier")),
        }
    }
    Ok(server)
}

fn route(call: &Call) -> Result<Layer4Route, Error> {
    call.no_modifiers()?;
    let mut matches = Vec::new();
    if call.name == "Fallback" {
        call.labels(&[])?;
    } else {
        call.labels(&["when", "from"])?;
        if call.args.is_empty() {
            return Err(call
                .at
                .error("route requires when or from; use Fallback for an unconditional route"));
        }
        let mut matcher = Layer4Matcher::default();
        if let Some(value) = call.get("when") {
            let Value::Typed(tls) = value else {
                return Err(call.at.error("when requires .tls(...)"));
            };
            if tls.name != "tls" {
                return Err(tls
                    .at
                    .error("unsupported route condition; expected .tls(...)"));
            }
            tls.leaf(&["sni", "alpn"])?;
            matcher.tls = Some(Layer4TlsMatcher {
                sni: tls.strings("sni")?,
                alpn: tls.strings("alpn")?,
            });
        }
        matcher.remote_ip = call.strings("from")?;
        matches.push(matcher);
    }
    let body = call.block()?;
    let [proxy] = body else {
        return Err(call.at.error("route requires exactly one Proxy component"));
    };
    if proxy.name != "Proxy" {
        return Err(proxy.at.error("expected Proxy(to: ...)"));
    }
    proxy.leaf(&["to"])?;
    Ok(Layer4Route {
        matches,
        upstream: proxy.string("to")?,
    })
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
            _ => return Err(value.at.error("unknown unit or wrong unit type")),
        };
        number
            .checked_mul(factor)
            .ok_or_else(|| value.at.error("unit value exceeds supported range"))
    }
}

#[cfg(test)]
mod tests;
