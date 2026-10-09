// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🛡️ One precomputed underscore allowlist for H1, H2, and H3.
//!
//! Caddy's server.go at 1b3838c1 (2026-10-09) defines exact and trailing-star
//! matches, suppression of hyphenated aliases, and rejection of repeated values.
//! Names containing both dots and underscores require an exact entry.

use http::HeaderName;
use std::collections::HashSet;
use std::sync::Arc;

#[derive(Default)]
pub(crate) struct HeaderAliasPolicy {
    exact: HashSet<String>,
    aliases: HashSet<String>,
    prefixes: Vec<(String, String)>,
}

impl HeaderAliasPolicy {
    fn new(entries: &[String]) -> Self {
        let mut policy = Self::default();
        for entry in entries {
            let name = entry.to_ascii_lowercase();
            if let Some(prefix) = name.strip_suffix('*') {
                policy
                    .prefixes
                    .push((prefix.to_owned(), prefix.replace('_', "-")));
            } else {
                policy.aliases.insert(name.replace('_', "-"));
                policy.exact.insert(name);
            }
        }
        policy
    }

    pub(crate) fn dropped<'a>(
        &self,
        names: impl Iterator<Item = &'a HeaderName>,
    ) -> HashSet<HeaderName> {
        let mut seen = HashSet::new();
        let mut dropped = HashSet::new();
        for name in names {
            let key = name.as_str();
            let drop = if crate::http_policy::underscore_named(key.as_bytes()) {
                let allowed = self.exact.contains(key)
                    || (!key.contains('.')
                        && self
                            .prefixes
                            .iter()
                            .any(|(prefix, _)| key.starts_with(prefix)));
                !allowed || !seen.insert(name)
            } else {
                // 🛡️ Only plain hyphenated variants collide under this allowlist.
                !key.contains('.')
                    && (self.aliases.contains(key)
                        || self
                            .prefixes
                            .iter()
                            .any(|(_, alias)| key.starts_with(alias)))
            };
            if drop {
                dropped.insert(name.clone());
            }
        }
        if !dropped.is_empty() {
            tracing::debug!(fields = ?dropped, "🚫 Dropped request fields under the underscore-header policy");
        }
        dropped
    }
}

impl crate::server::PingclairProxy {
    /// 🛡️ Compiles validated listener names once; changing them requires a restart.
    pub fn expecting_underscore_headers(mut self, entries: &[String]) -> Self {
        self.header_alias_policy = Arc::new(HeaderAliasPolicy::new(entries));
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 🧾 The allowlist entries that drop `sent`, sorted for comparison.
    fn dropped(entries: &[&str], sent: &[&str]) -> Vec<String> {
        let entries: Vec<String> = entries.iter().map(|entry| entry.to_string()).collect();
        let sent: Vec<HeaderName> = sent
            .iter()
            .map(|name| HeaderName::from_bytes(name.as_bytes()).unwrap())
            .collect();
        let mut dropped: Vec<String> = HeaderAliasPolicy::new(&entries)
            .dropped(sent.iter())
            .into_iter()
            .map(|name| name.as_str().to_owned())
            .collect();
        dropped.sort();
        dropped
    }

    /// 🛡️ Without an allowlist, only the underscore spelling goes; `x-probe` is not
    /// an alias of anything yet.
    #[test]
    fn default_policy_drops_underscore_names_only() {
        assert_eq!(
            dropped(&[], &["x_probe", "x-probe", "content-type"]),
            ["x_probe"]
        );
    }

    /// 🛡️ An exact entry keeps its spelling and retires the hyphenated alias, which
    /// the backend would fold onto the same CGI variable.
    #[test]
    fn exact_entry_keeps_the_name_and_drops_its_alias() {
        assert_eq!(
            dropped(&["X_Probe"], &["x_probe", "x-probe", "x_other"]),
            ["x-probe", "x_other"]
        );
    }

    /// 🛡️ A trailing star matches a prefix; a name carrying both separators is
    /// never vetted by a prefix, so only an exact entry can keep it.
    #[test]
    fn trailing_star_matches_a_prefix_but_not_a_dot() {
        assert_eq!(
            dropped(
                &["Webhook_*"],
                &["webhook_event", "webhook-event", "webhook_bad.dot"],
            ),
            ["webhook-event", "webhook_bad.dot"]
        );
        assert!(dropped(&["Webhook_Bad.Dot"], &["webhook_bad.dot"]).is_empty());
    }

    /// 🛡️ A repeated allowlisted field drops every occurrence, because one of the
    /// copies is exactly what a spoofed request adds.
    #[test]
    fn repeated_allowlisted_values_drop_together() {
        assert_eq!(dropped(&["X_Probe"], &["x_probe", "x_probe"]), ["x_probe"]);
    }
}
