// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! High-performance route matcher using radix tree
//!
//! Provides O(log n) path matching with support for wildcards and parameters.

use crate::config::{Matcher, MatcherCondition, RouteConfig};
use matchit::Router as RadixRouter;
use std::collections::HashMap;
use std::sync::Arc;

/// 🧭 Bundles the immutable request attributes used by matcher evaluation.
struct MatcherRequest<'a> {
    path: &'a str,
    method: &'a str,
    headers: &'a http::HeaderMap,
    host: &'a str,
    remote_ip: &'a str,
    protocol: &'a str,
}

/// Pre-compiled matcher with cached regex
#[derive(Debug, Clone)]
pub struct CompiledMatcher {
    /// Original matcher
    pub matcher: Matcher,
    /// Pre-compiled regex patterns (keyed by pattern string)
    pub compiled_regexes: HashMap<String, Arc<regex::Regex>>,
}

impl CompiledMatcher {
    /// Compile a matcher, pre-compiling any regex patterns
    pub fn compile(matcher: &Matcher) -> Self {
        let mut compiled_regexes = HashMap::new();
        Self::collect_regexes(matcher, &mut compiled_regexes);
        Self {
            matcher: matcher.clone(),
            compiled_regexes,
        }
    }

    /// Recursively collect and compile all regex patterns in a matcher
    fn collect_regexes(matcher: &Matcher, regexes: &mut HashMap<String, Arc<regex::Regex>>) {
        match matcher {
            Matcher::Header { condition, .. } | Matcher::Query { condition, .. } => {
                if let MatcherCondition::Regex(pattern) = condition
                    && let Ok(re) = regex::Regex::new(pattern)
                {
                    regexes.insert(pattern.clone(), Arc::new(re));
                }
            }
            Matcher::And(left, right) | Matcher::Or(left, right) => {
                Self::collect_regexes(left, regexes);
                Self::collect_regexes(right, regexes);
            }
            Matcher::Not(inner) => {
                Self::collect_regexes(inner, regexes);
            }
            _ => {}
        }
    }

    /// Get a pre-compiled regex by pattern
    pub fn get_regex(&self, pattern: &str) -> Option<&regex::Regex> {
        self.compiled_regexes.get(pattern).map(|r| r.as_ref())
    }
}

/// Route entry with precompiled matchers
#[derive(Debug, Clone)]
pub struct CompiledRoute {
    /// Original route configuration
    pub config: RouteConfig,
    /// Route index for handler lookup
    pub index: usize,
    /// Pre-compiled matcher (if route has one)
    pub compiled_matcher: Option<CompiledMatcher>,
}

/// High-performance router using radix tree
pub struct Router {
    /// Radix tree for path matching
    path_router: RadixRouter<Vec<CompiledRoute>>,
    /// Default routes (no specific path)
    default_routes: Vec<CompiledRoute>,
    /// All routes for iteration
    all_routes: Vec<RouteConfig>,
}

impl Router {
    /// Create a new router from route configurations
    pub fn new(routes: Vec<RouteConfig>) -> Self {
        let mut path_router = RadixRouter::new();
        let mut default_routes = Vec::new();
        let mut path_groups: HashMap<String, Vec<CompiledRoute>> = HashMap::new();

        for (index, config) in routes.iter().enumerate() {
            // Pre-compile matcher if present
            let compiled_matcher = config.matcher.as_ref().map(CompiledMatcher::compile);

            let compiled = CompiledRoute {
                config: config.clone(),
                index,
                compiled_matcher,
            };

            // Normalize path for radix tree
            let path = Self::normalize_path(&config.path);

            if path == "/*" || path == "/" {
                default_routes.push(compiled);
            } else {
                path_groups.entry(path).or_default().push(compiled);
            }
        }

        // Insert path groups into radix router
        for (path, routes) in path_groups {
            // Convert glob patterns to matchit format
            let matchit_path = Self::glob_to_matchit(&path);

            // A glob like "/proxy/*" must also match the bare directory it
            // was written to catch — both "/proxy/" and "/proxy" — with
            // nothing after the prefix. That's how Caddy's own `*` glob and
            // Nginx's prefix `location` both behave, and hitting the exact
            // directory is an extremely common request. matchit's `{*rest}`
            // wildcard requires at least one character after the prefix, and
            // treats "/proxy" and "/proxy/" as distinct paths, so without
            // these extra static registrations the bare forms fall through
            // to the server's default route instead of matching —
            // previously surfacing as a 500 ConnectNoRoute inside
            // upstream_peer() when the default route had no upstream.
            for bare in Self::bare_prefixes(&path) {
                if let Err(e) = path_router.insert(bare.clone(), routes.clone()) {
                    // A conflict here just means an explicit route already
                    // owns that exact path; that route legitimately wins.
                    tracing::debug!("Skipping bare-prefix route {}: {}", bare, e);
                }
            }

            if let Err(e) = path_router.insert(&matchit_path, routes) {
                tracing::warn!("Failed to insert route {}: {}", path, e);
            }
        }

        Self {
            path_router,
            default_routes,
            all_routes: routes,
        }
    }

    /// Match a request path and return matching routes
    pub fn match_path(&self, path: &str) -> Vec<&CompiledRoute> {
        let mut matches = Vec::new();

        // Try radix tree match first
        if let Ok(matched) = self.path_router.at(path) {
            for route in matched.value.iter() {
                matches.push(route);
            }
        }

        // Add default routes
        for route in &self.default_routes {
            matches.push(route);
        }

        matches
    }

    /// 🧭 Matches a request after normalizing paths supplied by direct callers.
    pub fn match_request(
        &self,
        path: &str,
        method: &str,
        headers: &http::HeaderMap,
        host: &str,
        remote_ip: &str,
        protocol: &str,
    ) -> Option<&CompiledRoute> {
        let normalized_path = Self::normalize_request_path(path);
        self.match_normalized_request(&normalized_path, method, headers, host, remote_ip, protocol)
    }

    /// 🍃 Matches a path already normalized by the protocol ingress.
    ///
    /// H1, H2, and H3 all resolve dot segments before routing so security
    /// policy and the origin see the same resource. Repeating that work here
    /// allocated both a segment vector and a new string on every ordinary
    /// request. Direct callers can continue to use [`Self::match_request`].
    pub fn match_normalized_request(
        &self,
        path: &str,
        method: &str,
        headers: &http::HeaderMap,
        host: &str,
        remote_ip: &str,
        protocol: &str,
    ) -> Option<&CompiledRoute> {
        let request = MatcherRequest {
            path,
            method,
            headers,
            host,
            remote_ip,
            protocol,
        };

        // 🌲 Consult the radix match before catch-all routes while borrowing
        // both collections directly; the old candidate Vec allocated once per
        // request only to iterate it immediately.
        if let Ok(matched) = self.path_router.at(path) {
            for route in matched.value {
                if Self::route_matches(route, &request) {
                    return Some(route);
                }
            }
        }
        self.default_routes
            .iter()
            .find(|route| Self::route_matches(route, &request))
    }

    /// 🔎 Evaluates the constraints attached to one precompiled route.
    fn route_matches(route: &CompiledRoute, request: &MatcherRequest<'_>) -> bool {
        if let Some(methods) = &route.config.methods
            && !methods
                .iter()
                .any(|method| method.eq_ignore_ascii_case(request.method))
        {
            return false;
        }
        route
            .compiled_matcher
            .as_ref()
            .is_none_or(|compiled| Self::evaluate_matcher_compiled(compiled, request))
    }

    /// Evaluate a pre-compiled matcher against request context
    fn evaluate_matcher_compiled(compiled: &CompiledMatcher, request: &MatcherRequest<'_>) -> bool {
        Self::evaluate_matcher_inner(&compiled.matcher, compiled, request)
    }

    /// Inner matcher evaluation with access to pre-compiled regexes
    fn evaluate_matcher_inner(
        matcher: &Matcher,
        compiled: &CompiledMatcher,
        request: &MatcherRequest<'_>,
    ) -> bool {
        match matcher {
            Matcher::Path { patterns } => patterns
                .iter()
                .any(|pattern| Self::path_matches(request.path, pattern)),
            Matcher::Header { name, condition } => {
                let header_value = request.headers.get(name).and_then(|v| v.to_str().ok());
                Self::evaluate_condition(header_value, condition, compiled)
            }
            Matcher::Method { methods } => methods
                .iter()
                .any(|method| method.eq_ignore_ascii_case(request.method)),
            Matcher::Query { name, condition } => {
                Self::query_matches(request.path, name, condition, compiled)
            }
            Matcher::Host(hosts) => hosts
                .iter()
                .any(|host| host.eq_ignore_ascii_case(request.host)),
            Matcher::RemoteIp(ips) => Self::remote_ip_matches(ips, request.remote_ip),
            Matcher::Protocol(protocols) => protocols
                .iter()
                .any(|protocol| protocol.eq_ignore_ascii_case(request.protocol)),
            Matcher::And(left, right) => {
                Self::evaluate_matcher_inner(left, compiled, request)
                    && Self::evaluate_matcher_inner(right, compiled, request)
            }
            Matcher::Or(left, right) => {
                Self::evaluate_matcher_inner(left, compiled, request)
                    || Self::evaluate_matcher_inner(right, compiled, request)
            }
            Matcher::Not(inner) => !Self::evaluate_matcher_inner(inner, compiled, request),
        }
    }

    /// 🔎 Evaluates one query-parameter condition against the request's query
    /// string. A key with several repeated values matches when any one value
    /// satisfies the condition; a key that is absent never matches, even for
    /// `Exists`. This replaces the old unconditional `true`, which turned any
    /// query matcher into a match-all rule.
    fn query_matches(
        path: &str,
        name: &str,
        condition: &MatcherCondition,
        compiled: &CompiledMatcher,
    ) -> bool {
        let Some(query) = path.split_once('?').map(|(_, q)| q) else {
            return false;
        };
        query.split('&').any(|pair| {
            let Some((key, value)) = pair.split_once('=') else {
                return false;
            };
            if key != name {
                return false;
            }
            Self::evaluate_condition(Some(value), condition, compiled)
        })
    }

    /// Evaluate a condition against a value (using pre-compiled regex)
    fn evaluate_condition(
        value: Option<&str>,
        condition: &MatcherCondition,
        compiled: &CompiledMatcher,
    ) -> bool {
        match condition {
            MatcherCondition::Exists => value.is_some(),
            MatcherCondition::Equals(expected) => value.map(|v| v == expected).unwrap_or(false),
            MatcherCondition::Contains(substring) => {
                value.map(|v| v.contains(substring)).unwrap_or(false)
            }
            MatcherCondition::StartsWith(prefix) => {
                value.map(|v| v.starts_with(prefix)).unwrap_or(false)
            }
            MatcherCondition::EndsWith(suffix) => {
                value.map(|v| v.ends_with(suffix)).unwrap_or(false)
            }
            MatcherCondition::Regex(pattern) => {
                // Use pre-compiled regex for performance
                if let Some(re) = compiled.get_regex(pattern) {
                    value.map(|v| re.is_match(v)).unwrap_or(false)
                } else {
                    // Fallback (shouldn't happen normally)
                    false
                }
            }
        }
    }

    /// 🌐 Matches the remote/client IP against exact literals and CIDR
    /// ranges, as Caddy's `remote_ip`/`client_ip` matchers do.
    fn remote_ip_matches(patterns: &[String], remote_ip: &str) -> bool {
        let Ok(remote) = remote_ip.parse::<std::net::IpAddr>() else {
            return false;
        };
        patterns.iter().any(|pattern| {
            if let Ok(net) = pattern.parse::<ipnet::IpNet>() {
                net.contains(&remote)
            } else {
                pattern.parse::<std::net::IpAddr>().ok() == Some(remote)
            }
        })
    }

    /// Check if path matches a glob pattern
    fn path_matches(path: &str, pattern: &str) -> bool {
        Self::glob_match(pattern, path)
    }

    /// 🧭 Classic glob matching with `*` as a wildcard, compared
    /// case-insensitively like Caddy. Matching is byte-based (ASCII case
    /// folding) to stay allocation-free on the request hot path.
    fn glob_match(pattern: &str, text: &str) -> bool {
        let pattern = pattern.as_bytes();
        let text = text.as_bytes();
        let mut p = 0usize;
        let mut t = 0usize;
        let mut star_p: Option<usize> = None;
        let mut star_t = 0usize;
        let ascii_eq = |a: u8, b: u8| a.eq_ignore_ascii_case(&b);

        while t < text.len() {
            if p < pattern.len() && ascii_eq(pattern[p], text[t]) {
                p += 1;
                t += 1;
            } else if p < pattern.len() && pattern[p] == b'*' {
                star_p = Some(p);
                star_t = t;
                p += 1;
            } else if let Some(sp) = star_p {
                p = sp + 1;
                star_t += 1;
                t = star_t;
            } else {
                return false;
            }
        }
        while p < pattern.len() && pattern[p] == b'*' {
            p += 1;
        }
        p == pattern.len()
    }

    /// 🧹 Cleans a request path before matching: merges repeated slashes and
    /// resolves `.`/`..` segments, mirroring Caddy's pre-match normalization.
    /// The query string is preserved so query matchers still see it.
    fn normalize_request_path(path: &str) -> String {
        let (path, query) = match path.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (path, None),
        };
        let mut segments: Vec<&str> = Vec::new();
        for segment in path.split('/') {
            match segment {
                "" | "." => {
                    // 🧹 Empty segments come from repeated slashes; collapse
                    // them unless this is the root's leading slash.
                    if segments.is_empty() && path.starts_with('/') {
                        segments.push("");
                    }
                }
                ".." => {
                    segments.pop();
                }
                other => segments.push(other),
            }
        }
        if segments.is_empty() {
            return query.map_or_else(|| "/".to_string(), |q| format!("/?{q}"));
        }
        let mut normalized = segments.join("/");
        if !normalized.starts_with('/') {
            normalized.insert(0, '/');
        }
        match query {
            Some(query) => format!("{normalized}?{query}"),
            None => normalized,
        }
    }

    /// Normalize path for consistent matching
    fn normalize_path(path: &str) -> String {
        let path = if path.is_empty() { "/" } else { path };
        path.to_string()
    }

    /// The bare (non-wildcard) prefixes a glob path should also match.
    ///
    /// `/proxy/*` → `["/proxy", "/proxy/"]` so a request to either the bare
    /// directory or its trailing-slash form still hits the route.
    /// `/foo*`    → `["/foo"]`.
    /// Non-glob paths yield nothing.
    fn bare_prefixes(path: &str) -> Vec<String> {
        if let Some(prefix) = path.strip_suffix("/*") {
            // "/proxy/*" -> prefix "/proxy": match both "/proxy" and "/proxy/".
            if prefix.is_empty() {
                // "/*" is the catch-all; leave it to default_routes.
                Vec::new()
            } else {
                vec![prefix.to_string(), format!("{}/", prefix)]
            }
        } else if let Some(prefix) = path.strip_suffix('*') {
            // "/foo*" -> prefix "/foo".
            if prefix.is_empty() {
                Vec::new()
            } else {
                vec![prefix.to_string()]
            }
        } else {
            Vec::new()
        }
    }

    /// Convert glob pattern to matchit format
    fn glob_to_matchit(path: &str) -> String {
        if let Some(prefix) = path.strip_suffix("/*") {
            format!("{prefix}/{{*rest}}")
        } else if let Some(prefix) = path.strip_suffix('*') {
            format!("{prefix}{{*rest}}")
        } else {
            path.to_string()
        }
    }

    /// Get all routes
    pub fn routes(&self) -> &[RouteConfig] {
        &self.all_routes
    }
}

impl Default for Router {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::HandlerConfig;
    use http::HeaderMap;

    fn make_route(path: &str) -> RouteConfig {
        RouteConfig {
            path: path.to_string(),
            handler: HandlerConfig::Respond {
                status: 200,
                body: None,
                headers: HashMap::new(),
            },
            methods: None,
            matcher: None,
        }
    }

    #[test]
    fn test_exact_match() {
        let routes = vec![make_route("/api/users"), make_route("/api/posts")];
        let router = Router::new(routes);

        let matched = router.match_path("/api/users");
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].config.path, "/api/users");
    }

    #[test]
    fn test_wildcard_match() {
        let routes = vec![make_route("/api/*"), make_route("/static/*")];
        let router = Router::new(routes);

        let matched = router.match_path("/api/users/123");
        assert!(!matched.is_empty());
    }

    #[test]
    fn test_default_route() {
        let routes = vec![make_route("/api/*"), make_route("/*")];
        let router = Router::new(routes);

        let matched = router.match_path("/unknown");
        assert!(!matched.is_empty());
    }

    /// Regression: a `/proxy/*` route must also match the bare `/proxy/`
    /// (nothing after the slash) and `/proxy` — the exact directory the
    /// glob was written to catch. matchit's `{*rest}` wildcard needs at
    /// least one trailing char, so without the bare-prefix registration
    /// these fall through to the default route (or 500 with ConnectNoRoute
    /// when there is no default upstream), diverging from how Caddy/Nginx
    /// treat the same pattern.
    #[test]
    fn test_glob_matches_bare_prefix() {
        let routes = vec![make_route("/proxy/*")];
        let router = Router::new(routes);

        // With a trailing segment — always worked.
        assert!(
            !router.match_path("/proxy/foo").is_empty(),
            "/proxy/foo should match /proxy/*"
        );
        // The bare directory with a trailing slash — the reported bug.
        assert!(
            !router.match_path("/proxy/").is_empty(),
            "/proxy/ should match /proxy/*"
        );
        // The bare directory with no trailing slash.
        assert!(
            !router.match_path("/proxy").is_empty(),
            "/proxy should match /proxy/*"
        );
    }

    /// The bare-prefix registration must not over-match a sibling path that
    /// merely shares a textual prefix (`/proxying` is not under `/proxy/*`).
    #[test]
    fn test_glob_bare_prefix_does_not_overmatch_siblings() {
        let routes = vec![make_route("/proxy/*")];
        let router = Router::new(routes);
        assert!(
            router.match_path("/proxyfoo").is_empty(),
            "/proxyfoo must NOT match /proxy/*"
        );
        assert!(
            router.match_path("/other").is_empty(),
            "/other must NOT match /proxy/*"
        );
    }

    /// The consequence of the matcher representation, not just its shape:
    /// a route loaded from JSON must *route* the way it was written.
    ///
    /// This is the failure that made the tagged representation necessary.
    /// The untagged form serialized `Not(inner)` as bare `inner`, so a
    /// config that reached the router through JSON or an Admin hot reload
    /// arrived with the negation stripped — the route then matched exactly
    /// the requests it was written to exclude.
    #[test]
    fn a_negation_loaded_from_json_still_inverts_the_match() {
        let json = r#"{
            "path": "/*",
            "handler": {"type": "respond", "status": 200},
            "matcher": {"not": {"path": {"patterns": ["/admin/*"]}}}
        }"#;
        let route: RouteConfig = serde_json::from_str(json).expect("parse route");
        let router = Router::new(vec![route]);
        let headers = http::HeaderMap::new();

        let matches = |path: &str| {
            router
                .match_request(path, "GET", &headers, "example.com", "10.0.0.1", "https")
                .is_some()
        };

        assert!(matches("/public"), "`not path /admin/*` must allow /public");
        assert!(
            !matches("/admin/secrets"),
            "`not path /admin/*` must exclude /admin/* — a dropped negation \
             turns this route into the opposite of what was configured"
        );
    }

    /// `or` must not collapse into `and` on the way through JSON: both are
    /// two-element arrays, so the untagged form read every `or` as an `and`.
    #[test]
    fn an_or_loaded_from_json_still_matches_either_side() {
        let json = r#"{
            "path": "/*",
            "handler": {"type": "respond", "status": 200},
            "matcher": {"or": [
                {"path": {"patterns": ["/a/*"]}},
                {"path": {"patterns": ["/b/*"]}}
            ]}
        }"#;
        let route: RouteConfig = serde_json::from_str(json).expect("parse route");
        let router = Router::new(vec![route]);
        let headers = http::HeaderMap::new();

        let matches = |path: &str| {
            router
                .match_request(path, "GET", &headers, "example.com", "10.0.0.1", "https")
                .is_some()
        };

        // An `and` of two disjoint paths can never match anything, which is
        // what this config silently became before.
        assert!(matches("/a/one"));
        assert!(matches("/b/two"));
        assert!(!matches("/c/three"));
    }

    /// 🛡️ A query matcher must actually evaluate the query string. The old
    /// implementation returned `true` unconditionally, so any JSON/Admin
    /// config carrying a query condition silently matched every request.
    #[test]
    fn a_query_matcher_matches_only_matching_query_strings() {
        use crate::config::Matcher;
        let route = RouteConfig {
            path: "/*".to_string(),
            handler: HandlerConfig::Respond {
                status: 200,
                body: None,
                headers: HashMap::new(),
            },
            methods: None,
            matcher: Some(Matcher::Query {
                name: "admin".to_string(),
                condition: MatcherCondition::Equals("1".to_string()),
            }),
        };
        let router = Router::new(vec![route]);
        let headers = HeaderMap::new();

        let matches = |path: &str| {
            router
                .match_request(path, "GET", &headers, "example.com", "10.0.0.1", "https")
                .is_some()
        };

        assert!(matches("/?admin=1"), "the configured value must match");
        assert!(!matches("/?admin=2"), "a different value must not match");
        assert!(!matches("/?other=1"), "a different key must not match");
        assert!(
            !matches("/"),
            "a request without a query string must not match"
        );
        assert!(!matches("/?admin"), "a key without '=' must not match");
        assert!(
            matches("/?admin=1&admin=2"),
            "a repeated key matches when any value matches"
        );
    }

    /// 🧭 Caddy's path globs support suffix, prefix, substring and mid-path
    /// wildcards, not just the trailing `/*` form.
    #[test]
    fn path_globs_match_all_four_wildcard_positions() {
        use crate::config::Matcher;
        let route_for = |pattern: &str| RouteConfig {
            path: "/*".to_string(),
            handler: HandlerConfig::Respond {
                status: 200,
                body: None,
                headers: HashMap::new(),
            },
            methods: None,
            matcher: Some(Matcher::Path {
                patterns: vec![pattern.to_string()],
            }),
        };
        let headers = HeaderMap::new();

        let suffix = Router::new(vec![route_for("*.css")]);
        assert!(
            suffix
                .match_request(
                    "/assets/site.css",
                    "GET",
                    &headers,
                    "e.com",
                    "10.0.0.1",
                    "https"
                )
                .is_some()
        );
        assert!(
            suffix
                .match_request("/site.js", "GET", &headers, "e.com", "10.0.0.1", "https")
                .is_none()
        );

        let prefix = Router::new(vec![route_for("/api/*")]);
        assert!(
            prefix
                .match_request("/api/users", "GET", &headers, "e.com", "10.0.0.1", "https")
                .is_some()
        );

        let contains = Router::new(vec![route_for("*/download/*")]);
        assert!(
            contains
                .match_request(
                    "/x/download/y",
                    "GET",
                    &headers,
                    "e.com",
                    "10.0.0.1",
                    "https"
                )
                .is_some()
        );

        let middle = Router::new(vec![route_for("/accounts/*/info")]);
        assert!(
            middle
                .match_request(
                    "/accounts/42/info",
                    "GET",
                    &headers,
                    "e.com",
                    "10.0.0.1",
                    "https"
                )
                .is_some()
        );
        assert!(
            middle
                .match_request(
                    "/accounts/42/other",
                    "GET",
                    &headers,
                    "e.com",
                    "10.0.0.1",
                    "https"
                )
                .is_none()
        );
    }

    /// 🧹 Dot segments and repeated slashes are normalized before matching.
    #[test]
    fn path_matching_normalizes_dots_and_slashes() {
        use crate::config::Matcher;
        let route = RouteConfig {
            path: "/*".to_string(),
            handler: HandlerConfig::Respond {
                status: 200,
                body: None,
                headers: HashMap::new(),
            },
            methods: None,
            matcher: Some(Matcher::Path {
                patterns: vec!["/admin/*".to_string()],
            }),
        };
        let router = Router::new(vec![route]);
        let headers = HeaderMap::new();

        assert!(
            router
                .match_request(
                    "/public/../admin/users",
                    "GET",
                    &headers,
                    "e.com",
                    "10.0.0.1",
                    "https"
                )
                .is_some()
        );
        assert!(
            router
                .match_request(
                    "//admin//users",
                    "GET",
                    &headers,
                    "e.com",
                    "10.0.0.1",
                    "https"
                )
                .is_some()
        );
    }

    /// 🍃 The ingress fast path must select the same route as the public
    /// normalizing entry after the protocol layer has cleaned the URI.
    #[test]
    fn normalized_fast_path_preserves_route_selection() {
        use crate::config::Matcher;
        let route = RouteConfig {
            path: "/*".to_string(),
            handler: HandlerConfig::Respond {
                status: 200,
                body: None,
                headers: HashMap::new(),
            },
            methods: Some(vec!["GET".to_string()]),
            matcher: Some(Matcher::Path {
                patterns: vec!["/admin/*".to_string()],
            }),
        };
        let router = Router::new(vec![route]);
        let headers = HeaderMap::new();

        let direct = router
            .match_request(
                "/public/../admin/users",
                "GET",
                &headers,
                "e.com",
                "10.0.0.1",
                "https",
            )
            .map(|route| route.index);
        let normalized = router
            .match_normalized_request(
                "/admin/users",
                "GET",
                &headers,
                "e.com",
                "10.0.0.1",
                "https",
            )
            .map(|route| route.index);

        assert_eq!(direct, normalized);
        assert_eq!(normalized, Some(0));
    }

    /// 🌐 remote_ip accepts CIDR ranges, not just exact literals.
    #[test]
    fn remote_ip_matcher_accepts_cidr_ranges() {
        use crate::config::Matcher;
        let route = RouteConfig {
            path: "/*".to_string(),
            handler: HandlerConfig::Respond {
                status: 200,
                body: None,
                headers: HashMap::new(),
            },
            methods: None,
            matcher: Some(Matcher::RemoteIp(vec!["10.0.0.0/8".to_string()])),
        };
        let router = Router::new(vec![route]);
        let headers = HeaderMap::new();

        assert!(
            router
                .match_request("/", "GET", &headers, "e.com", "10.1.2.3", "https")
                .is_some()
        );
        assert!(
            router
                .match_request("/", "GET", &headers, "e.com", "192.168.1.1", "https")
                .is_none()
        );
    }

    /// 🚫 A `header !Foo` matcher must exclude requests that HAVE the header.
    #[test]
    fn negated_header_matcher_requires_absence() {
        use crate::config::{Matcher, MatcherCondition};
        let route = RouteConfig {
            path: "/*".to_string(),
            handler: HandlerConfig::Respond {
                status: 200,
                body: None,
                headers: HashMap::new(),
            },
            methods: None,
            matcher: Some(Matcher::Not(Box::new(Matcher::Header {
                name: "Foo".to_string(),
                condition: MatcherCondition::Exists,
            }))),
        };
        let router = Router::new(vec![route]);
        let mut headers = HeaderMap::new();
        assert!(
            router
                .match_request("/", "GET", &headers, "e.com", "10.0.0.1", "https")
                .is_some()
        );
        headers.insert("Foo", "bar".parse().unwrap());
        assert!(
            router
                .match_request("/", "GET", &headers, "e.com", "10.0.0.1", "https")
                .is_none()
        );
    }
}
