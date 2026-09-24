// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧩 Compile sibling exclusion without adding request-scoped group state.

use crate::parser::ast::{Handler, HandlerElement};

pub(super) fn group_siblings(mut elements: Vec<HandlerElement>) -> Vec<HandlerElement> {
    let is_handle = |element: &HandlerElement| {
        matches!(
            element.handler,
            Handler::Handle(_) | Handler::HandlePath { .. }
        )
    };
    let Some(last) = elements.iter().rposition(is_handle) else {
        return elements;
    };
    if elements.iter().filter(|element| is_handle(element)).count() < 2 {
        return elements;
    }
    let trailing = elements.split_off(last + 1);
    let mut continuation = Vec::new();
    let mut ungrouped = Vec::new();
    let mut adjacent = false;
    for mut element in elements.into_iter().rev() {
        if !is_handle(&element) {
            ungrouped.insert(0, element.clone());
            continuation.insert(0, element);
            adjacent = false;
            continue;
        }
        // 🧭 Once selected, skip later siblings but retain intervening route
        // 🧭 directives in their original order, including matcher-changing rewrites.
        if !ungrouped.is_empty() {
            let mut selected = vec![HandlerElement {
                matcher: None,
                handler: element.handler,
            }];
            selected.extend(ungrouped.iter().cloned());
            element.handler = Handler::Pipeline(selected);
        }
        let mut branches = if adjacent {
            let Handler::HandleGroup(branches) = continuation.remove(0).handler else {
                unreachable!("adjacent siblings form one group");
            };
            branches
        } else if continuation.is_empty() {
            Vec::new()
        } else {
            // 🧭 Only an unmatched group reaches later siblings. Keep its
            // 🧭 intervening directives inside that fallback continuation.
            vec![HandlerElement {
                matcher: None,
                handler: Handler::Pipeline(std::mem::take(&mut continuation)),
            }]
        };
        branches.insert(0, element);
        continuation = vec![HandlerElement {
            matcher: None,
            handler: Handler::HandleGroup(branches),
        }];
        adjacent = true;
    }
    continuation.extend(trailing);
    continuation
}
