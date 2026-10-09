// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🛡️ The server allowlist takes names, never a boolean or a nested block.

use super::*;

pub(super) fn parse(directive: &Directive) -> Result<Vec<String>, AdapterError> {
    if directive.args.is_empty() || directive.block.is_some() {
        return Err(AdapterError::InvalidArgument(
            "expected_underscore_headers".into(),
            "expected one or more header names or trailing-star prefixes, without a block".into(),
        ));
    }
    Ok(directive.args.clone())
}
