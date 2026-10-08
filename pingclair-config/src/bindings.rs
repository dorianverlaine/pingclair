// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧩 File-level bindings: immutable fragments with bounded expansion.

use crate::attributes::{Attr, resolve_attribute};
use crate::frontend::Error;
use crate::syntax::{Attribute, Call, Declaration, Position, Value};

/// 🧩 Expansion bounds keep reuse from turning into unbounded work.
const MAX_EXPANDED_NODES: usize = 4096;
const MAX_EXPANDED_BYTES: usize = 8 * 1024 * 1024;

#[derive(Default)]
pub(super) struct Bindings {
    names: std::collections::HashSet<String>,
    resolved: std::collections::HashMap<String, Bound>,
    nodes: usize,
    bytes: usize,
}

struct Bound {
    fragment: Fragment,
    nodes: usize,
    bytes: usize,
    matcher: bool,
}

enum Fragment {
    Value(Value),
    Component(Call),
}

impl Bindings {
    pub(super) fn declare(&mut self, declarations: &[Declaration]) -> Result<(), Error> {
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

    pub(super) fn bind(
        &mut self,
        attributes: &[Attribute],
        name: &str,
        value: &Value,
    ) -> Result<(), Error> {
        let mut matcher = None;
        let mut secret = None;
        for attribute in attributes {
            match resolve_attribute(attribute)? {
                Attr::Matcher => matcher = Some(attribute.at),
                Attr::Secret => secret = Some(attribute.at),
            }
        }
        if let (Some(_), Some(at)) = (matcher, secret) {
            return Err(at.error("cannot combine @Matcher with @Secret"));
        }
        let fragment = match value {
            Value::Component(call) => Fragment::Component(self.expand_call(call)?),
            other if matcher.is_some() => Fragment::Value(self.expand_condition(other)?),
            other => Fragment::Value(self.expand_value(other)?),
        };
        if let Some(at) = matcher
            && !is_condition_fragment(&fragment)
        {
            return Err(at.error(
                "@Matcher requires a condition: an HTTP condition such as \
                 .path(prefix: \"/api\"), or the L4 .tls(sni: [...])",
            ));
        }
        if let Some(at) = secret
            && !matches!(&fragment, Fragment::Value(_))
        {
            return Err(at.error("@Secret applies to a value binding"));
        }
        let (nodes, bytes) = fragment_size(&fragment);
        self.resolved.insert(
            name.to_string(),
            Bound {
                fragment,
                nodes,
                bytes,
                matcher: matcher.is_some(),
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
                        ..
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

    pub(super) fn expand_call(&mut self, call: &Call) -> Result<Call, Error> {
        if call.args.is_empty() && call.body.is_none() && call.modifiers.is_empty() {
            match self.resolved.get(&call.name) {
                Some(Bound {
                    fragment: Fragment::Component(inner),
                    nodes,
                    bytes,
                    ..
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
            let expanded = match (call.name.as_str(), label.as_deref()) {
                ("Route", Some("when")) => self.expand_condition(value)?,
                _ => self.expand_value(value)?,
            };
            args.push((label.clone(), expanded));
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
            parens: call.parens,
            block_end: call.block_end,
            end: call.end,
            at: call.at,
        })
    }

    fn expand_condition(&mut self, value: &Value) -> Result<Value, Error> {
        match value {
            Value::Reference { name, at } => {
                match self.resolved.get(name) {
                    Some(Bound { matcher: true, .. }) => {}
                    Some(_) => {
                        return Err(
                            at.error("when: requires an @Matcher binding or an inline condition")
                        );
                    }
                    None => return Err(self.unresolved(name, *at)),
                }
                self.expand_value(value)
            }
            Value::Typed(call) if matches!(call.name.as_str(), "all" | "any" | "not") => {
                let mut expanded = call.clone();
                for (_, value) in &mut expanded.args {
                    *value = match &*value {
                        Value::Array(values) => Value::Array(
                            values
                                .iter()
                                .map(|value| self.expand_condition(value))
                                .collect::<Result<_, _>>()?,
                        ),
                        value => self.expand_condition(value)?,
                    };
                }
                Ok(Value::Typed(expanded))
            }
            _ => self.expand_value(value),
        }
    }

    fn charge(&mut self, at: Position, nodes: usize, bytes: usize) -> Result<(), Error> {
        self.nodes = self.nodes.saturating_add(nodes);
        self.bytes = self.bytes.saturating_add(bytes);
        if self.nodes > MAX_EXPANDED_NODES || self.bytes > MAX_EXPANDED_BYTES {
            return Err(at.error("configuration expansion exceeds 4096 components or 8 MiB"));
        }
        Ok(())
    }

    fn unresolved(&self, name: &str, at: Position) -> Error {
        if self.names.contains(name) {
            at.error("binding used before its declaration")
        } else {
            at.error(format!("unknown binding '{name}'"))
        }
    }
}

fn is_condition_fragment(fragment: &Fragment) -> bool {
    matches!(
        fragment,
        // 🌐 Both families: `.tls(sni:, alpn:)` routes a TCP listener, and the
        // HTTP conditions are the rest of the list.
        Fragment::Value(Value::Typed(call))
            if call.name == "tls" || crate::frontend::is_http_condition(&call.name)
    )
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
