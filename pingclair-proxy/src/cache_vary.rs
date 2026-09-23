// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔀 Complete field sequences keep cache variants from collapsing together.

use http::{HeaderMap, HeaderName};
use pingora_cache::{VarianceBuilder, key::HashBinary};

/// 🛡️ Validates every nominated name before a response may enter the cache.
pub(crate) fn names(
    headers: &HeaderMap,
) -> impl Iterator<Item = Result<HeaderName, &'static str>> + '_ {
    headers
        .get_all("vary")
        .iter()
        .flat_map(|value| value.as_bytes().split(|byte| *byte == b','))
        .map(|name| name.trim_ascii())
        .filter(|name| !name.is_empty())
        .map(|name| {
            if name == b"*" {
                Err("response varies on everything")
            } else {
                HeaderName::from_bytes(name).map_err(|_| "response has an invalid Vary field")
            }
        })
}

/// 🔑 Includes every response nomination and every matching request field line.
pub(crate) fn variance(response: &HeaderMap, request: &HeaderMap) -> Option<HashBinary> {
    // 🛡️ Storage rejects invalid nominations. Do not partially interpret one
    // here: a later unreadable line must never erase part of the variant key.
    let mut names = names(response).collect::<Result<Vec<_>, _>>().ok()?;
    names.sort_unstable_by(|left, right| left.as_str().cmp(right.as_str()));
    names.dedup();
    let mut variance = VarianceBuilder::new();
    for name in names {
        let values = request.get_all(&name);
        // 🔐 Field counts and lengths preserve order and boundaries, including
        // absence versus an empty value. Arbitrary fields are not necessarily
        // comma-separated lists, so do not guess at their normalization rules.
        let count = values.iter().count();
        let capacity = 8 + values
            .iter()
            .map(|value| 8 + value.as_bytes().len())
            .sum::<usize>();
        let mut combined = Vec::with_capacity(capacity);
        combined.extend_from_slice(&(count as u64).to_be_bytes());
        for value in values {
            combined.extend_from_slice(&(value.as_bytes().len() as u64).to_be_bytes());
            combined.extend_from_slice(value.as_bytes());
        }
        variance.add_owned_name_value(name.as_str().to_owned(), combined);
    }
    variance.finalize()
}

#[cfg(test)]
#[path = "cache_vary_tests.rs"]
mod tests;
