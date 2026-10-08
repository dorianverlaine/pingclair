// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🎀 The closed attribute set: compile-time markers on top-level declarations.

use crate::frontend::Error;
use crate::syntax::Attribute;

/// 🎀 v0.3 ships Matcher and Secret only; the set is closed by design.
const ATTRIBUTES: &[&str] = &["Matcher", "Secret"];

#[derive(Clone, Copy, PartialEq)]
pub(super) enum Attr {
    Matcher,
    Secret,
}

pub(super) fn resolve_attribute(attribute: &Attribute) -> Result<Attr, Error> {
    let resolved = match attribute.name.as_str() {
        "Matcher" => Attr::Matcher,
        "Secret" => Attr::Secret,
        _ => {
            return Err(match nearest(&attribute.name) {
                Some(name) => attribute
                    .at
                    .error(format!("unknown attribute; did you mean @{name}?")),
                None => attribute
                    .at
                    .error("unknown attribute; expected @Matcher or @Secret"),
            });
        }
    };
    if !attribute.args.is_empty() {
        return Err(attribute
            .at
            .error(format!("@{} does not take arguments", attribute.name)));
    }
    Ok(resolved)
}

fn nearest(name: &str) -> Option<&'static str> {
    ATTRIBUTES
        .iter()
        .map(|candidate| (*candidate, edit_distance(name, candidate)))
        .filter(|(_, distance)| *distance <= 2)
        .min_by_key(|(_, distance)| *distance)
        .map(|(candidate, _)| candidate)
}

fn edit_distance(left: &str, right: &str) -> usize {
    let right: Vec<char> = right.chars().collect();
    let mut previous: Vec<usize> = (0..=right.len()).collect();
    let mut current = vec![0; right.len() + 1];
    for (index, left_char) in left.chars().enumerate() {
        current[0] = index + 1;
        for (offset, right_char) in right.iter().enumerate() {
            let cost = usize::from(left_char != *right_char);
            current[offset + 1] = (previous[offset] + cost)
                .min(previous[offset + 1] + 1)
                .min(current[offset] + 1);
        }
        std::mem::swap(&mut previous, &mut current);
    }
    previous[right.len()]
}
