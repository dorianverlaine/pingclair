// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! High-performance route matcher using radix tree
//!
//! Provides O(log n) path matching with support for wildcards and parameters.

use crate::config::{HandlerConfig, HandlerElement, Matcher, MatcherCondition, RouteConfig};
use matchit::Router as RadixRouter;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

/// 🧭 Bundles the immutable request attributes used by matcher evaluation.
pub struct MatcherRequest<'a> {
    pub path: &'a str,
    pub method: &'a str,
    pub headers: &'a http::HeaderMap,
    pub host: &'a str,
    pub remote_ip: &'a str,
    pub protocol: &'a str,
    /// 🧰 Request-scoped variables and regexp captures, written and read by
    /// the `vars` and regexp matchers. `None` means nothing is visible,
    /// which matches nothing.
    pub vars: Option<&'a mut std::collections::BTreeMap<String, String>>,
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
            Matcher::PathRegexp { pattern, .. } | Matcher::HeaderRegexp { pattern, .. } => {
                if let Ok(re) = regex::Regex::new(pattern) {
                    regexes.insert(pattern.clone(), Arc::new(re));
                }
            }
            Matcher::File { .. } => {}
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

/// 🔎 Evaluates a pre-compiled matcher against one request's immutable
/// attributes. This is the standalone primitive C2 will reuse for matchers
/// attached to pipeline elements; the router calls the same function so the
/// two paths cannot drift.
pub fn evaluate(compiled: &CompiledMatcher, request: &mut MatcherRequest<'_>) -> bool {
    matches!(evaluate_verdict(compiled, request), MatcherVerdict::Match)
}

/// 🧭 The outcome of one matcher evaluation.
///
/// The extra `Error` arm exists for the `file` matcher's `=404` fallback
/// candidates: upstream turns a reached status candidate into an HTTP error
/// response, and a boolean matcher cannot say so. Callers that only need a
/// yes/no (route matching, H3 planning) treat `Error` as no-match; pipeline
/// execution surfaces it as a raised status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatcherVerdict {
    /// ✅ The request matched.
    Match,
    /// 🚫 The request did not match and evaluation finished normally.
    NoMatch,
    /// 🚨 Evaluation hit an error fallback (a `=code` try_files candidate).
    Error(u16),
}

/// 🔎 Evaluates a pre-compiled matcher with the error-able verdict.
pub fn evaluate_verdict(
    compiled: &CompiledMatcher,
    request: &mut MatcherRequest<'_>,
) -> MatcherVerdict {
    evaluate_matcher_inner(&compiled.matcher, compiled, request)
}

/// 🧭 Precompiled per-route matcher state, populated by C2.
///
/// The tree mirrors the route's handler tree: each node carries the compiled
/// matcher of the element it belongs to and holds one child per element
/// inside that element's container handler. Skipping an element therefore
/// skips its whole subtree with no cursor to keep in sync.
#[derive(Debug, Clone, Default)]
pub struct MatcherPrecompile {
    /// Compiled matcher for the element owning this node; `None` at the
    /// route root and for unconditional elements.
    pub element_matcher: Option<CompiledMatcher>,
    /// Children mirroring the handler tree below this node.
    pub children: Vec<MatcherPrecompile>,
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
    /// Pre-compiled per-element matchers for this route's handler tree.
    pub matcher_precompile: MatcherPrecompile,
}

/// High-performance router using radix tree
pub struct Router {
    /// Radix tree for path matching
    path_router: RadixRouter<Vec<CompiledRoute>>,
    /// Default routes (no specific path)
    default_routes: Vec<CompiledRoute>,
    /// All routes for iteration
    all_routes: Vec<RouteConfig>,
    /// Compiled routes indexed the same way as `all_routes`.
    compiled_routes: Vec<CompiledRoute>,
}

impl Router {
    /// Create a new router from route configurations
    pub fn new(routes: Vec<RouteConfig>) -> Self {
        let mut path_router = RadixRouter::new();
        let mut default_routes = Vec::new();
        let mut path_groups: HashMap<String, Vec<CompiledRoute>> = HashMap::new();
        let mut compiled_routes = Vec::new();

        for (index, config) in routes.iter().enumerate() {
            // Pre-compile matcher if present
            let compiled_matcher = config.matcher.as_ref().map(CompiledMatcher::compile);

            let compiled = CompiledRoute {
                config: config.clone(),
                index,
                compiled_matcher,
                matcher_precompile: precompile_handler(&config.handler),
            };
            compiled_routes.push(compiled.clone());

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
            compiled_routes,
        }
    }

    /// 🔎 Returns the compiled route at `index`, matching the index the
    /// runtime uses for its per-route tables.
    pub fn compiled_route(&self, index: usize) -> Option<&CompiledRoute> {
        self.compiled_routes.get(index)
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
    // 📏 The eighth argument is the request-vars map for `vars` matchers;
    // bundling the six request facts into a struct is a refactor, not part
    // of this change.
    #[allow(clippy::too_many_arguments)]
    pub fn match_request(
        &self,
        path: &str,
        method: &str,
        headers: &http::HeaderMap,
        host: &str,
        remote_ip: &str,
        protocol: &str,
        vars: Option<&mut std::collections::BTreeMap<String, String>>,
    ) -> Option<&CompiledRoute> {
        let normalized_path = Self::normalize_request_path(path);
        self.match_normalized_request(
            &normalized_path,
            method,
            headers,
            host,
            remote_ip,
            protocol,
            vars,
        )
    }

    /// 🍃 Matches a path already normalized by the protocol ingress.
    ///
    /// H1, H2, and H3 all resolve dot segments before routing so security
    /// policy and the origin see the same resource. Repeating that work here
    /// allocated both a segment vector and a new string on every ordinary
    /// request. Direct callers can continue to use [`Self::match_request`].
    #[allow(clippy::too_many_arguments)]
    pub fn match_normalized_request(
        &self,
        path: &str,
        method: &str,
        headers: &http::HeaderMap,
        host: &str,
        remote_ip: &str,
        protocol: &str,
        vars: Option<&mut std::collections::BTreeMap<String, String>>,
    ) -> Option<&CompiledRoute> {
        let mut request = MatcherRequest {
            path,
            method,
            headers,
            host,
            remote_ip,
            protocol,
            vars,
        };

        // 🌲 Consult the radix match before catch-all routes while borrowing
        // both collections directly; the old candidate Vec allocated once per
        // request only to iterate it immediately.
        if let Ok(matched) = self.path_router.at(path) {
            for route in matched.value {
                if Self::route_matches(route, &mut request) {
                    return Some(route);
                }
            }
        }
        self.default_routes
            .iter()
            .find(|route| Self::route_matches(route, &mut request))
    }

    /// 🔎 Evaluates the constraints attached to one precompiled route.
    fn route_matches(route: &CompiledRoute, request: &mut MatcherRequest<'_>) -> bool {
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
            .is_none_or(|compiled| evaluate(compiled, request))
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

/// 🧭 Builds the precompiled matcher tree for one handler.
fn precompile_handler(handler: &HandlerConfig) -> MatcherPrecompile {
    match handler {
        HandlerConfig::Pipeline { handlers }
        | HandlerConfig::Handle { handlers }
        | HandlerConfig::HandlePath { handlers, .. } => MatcherPrecompile {
            element_matcher: None,
            children: handlers.iter().map(precompile_element).collect(),
        },
        _ => MatcherPrecompile::default(),
    }
}

/// 🧭 Builds one element's node, recursing into its container handler.
fn precompile_element(element: &HandlerElement) -> MatcherPrecompile {
    MatcherPrecompile {
        element_matcher: element.matcher.as_ref().map(CompiledMatcher::compile),
        children: match &element.handler {
            HandlerConfig::Pipeline { handlers }
            | HandlerConfig::Handle { handlers }
            | HandlerConfig::HandlePath { handlers, .. } => {
                handlers.iter().map(precompile_element).collect()
            }
            HandlerConfig::TryFiles {
                fallback: Some(fallback),
                ..
            } => {
                vec![precompile_handler(fallback)]
            }
            _ => Vec::new(),
        },
    }
}

/// 🧭 Builds a precompile tree for a standalone handler list — the body of an
/// error route, which is a pipeline without a route of its own.
pub fn precompile_handler_list(handlers: &[HandlerElement]) -> MatcherPrecompile {
    MatcherPrecompile {
        element_matcher: None,
        children: handlers.iter().map(precompile_element).collect(),
    }
}

impl Default for Router {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

/// Inner matcher evaluation with access to pre-compiled regexes
fn evaluate_matcher_inner(
    matcher: &Matcher,
    compiled: &CompiledMatcher,
    request: &mut MatcherRequest<'_>,
) -> MatcherVerdict {
    match matcher {
        Matcher::Path { patterns } => bool_verdict(
            patterns
                .iter()
                .any(|pattern| path_matches(request.path, pattern)),
        ),
        Matcher::Header { name, condition } => {
            let header_value = request.headers.get(name).and_then(|v| v.to_str().ok());
            bool_verdict(evaluate_condition(header_value, condition, compiled))
        }
        Matcher::Method { methods } => bool_verdict(
            methods
                .iter()
                .any(|method| method.eq_ignore_ascii_case(request.method)),
        ),
        Matcher::Query { name, condition } => {
            bool_verdict(query_matches(request.path, name, condition, compiled))
        }
        Matcher::Host(hosts) => bool_verdict(
            hosts
                .iter()
                .any(|host| host.eq_ignore_ascii_case(request.host)),
        ),
        Matcher::RemoteIp(ips) => bool_verdict(remote_ip_matches(ips, request.remote_ip)),
        Matcher::Protocol(protocols) => bool_verdict(
            protocols
                .iter()
                .any(|protocol| protocol.eq_ignore_ascii_case(request.protocol)),
        ),
        // 🧰 The `vars` matcher reads a request-scoped variable and matches
        // when its value equals any listed value. A request with no visible
        // variables never matches, which is the fail-closed reading of a
        // variable that has not been set.
        Matcher::Vars { name, values } => bool_verdict(
            request
                .vars
                .as_deref_mut()
                .and_then(|vars| vars.get(name))
                .is_some_and(|value| values.iter().any(|candidate| candidate == value)),
        ),
        // 🔍 A regexp matcher records its capture groups as `{re.*}`
        // placeholders before answering, exactly like upstream: numeric
        // groups under the matcher's name (or bare when unnamed), and named
        // groups by their group name. A request with no variable map cannot
        // record anything, so it never matches.
        Matcher::PathRegexp { name, pattern } => {
            let Some(regex) = compiled.compiled_regexes.get(pattern) else {
                return MatcherVerdict::NoMatch;
            };
            let Some(vars) = request.vars.as_deref_mut() else {
                return MatcherVerdict::NoMatch;
            };
            bool_verdict(record_regexp_captures(
                vars,
                name.as_deref(),
                regex,
                request.path,
            ))
        }
        Matcher::HeaderRegexp {
            name,
            field,
            pattern,
        } => {
            let Some(regex) = compiled.compiled_regexes.get(pattern) else {
                return MatcherVerdict::NoMatch;
            };
            let Some(value) = request.headers.get(field).and_then(|v| v.to_str().ok()) else {
                return MatcherVerdict::NoMatch;
            };
            let Some(vars) = request.vars.as_deref_mut() else {
                return MatcherVerdict::NoMatch;
            };
            bool_verdict(record_regexp_captures(vars, name.as_deref(), regex, value))
        }
        Matcher::File {
            try_files,
            root,
            try_policy,
            split_path,
        } => evaluate_file_matcher(
            request,
            try_files,
            root.as_deref(),
            try_policy.as_deref(),
            split_path,
        ),
        Matcher::And(left, right) => match evaluate_matcher_inner(left, compiled, request) {
            MatcherVerdict::NoMatch => MatcherVerdict::NoMatch,
            error @ MatcherVerdict::Error(_) => error,
            MatcherVerdict::Match => evaluate_matcher_inner(right, compiled, request),
        },
        Matcher::Or(left, right) => match evaluate_matcher_inner(left, compiled, request) {
            MatcherVerdict::Match => MatcherVerdict::Match,
            MatcherVerdict::NoMatch => evaluate_matcher_inner(right, compiled, request),
            error @ MatcherVerdict::Error(_) => error,
        },
        Matcher::Not(inner) => match evaluate_matcher_inner(inner, compiled, request) {
            MatcherVerdict::Match => MatcherVerdict::NoMatch,
            MatcherVerdict::NoMatch => MatcherVerdict::Match,
            error @ MatcherVerdict::Error(_) => error,
        },
    }
}

/// 🧭 Converts a plain boolean matcher result into a verdict.
fn bool_verdict(matched: bool) -> MatcherVerdict {
    if matched {
        MatcherVerdict::Match
    } else {
        MatcherVerdict::NoMatch
    }
}

// MARK: - File matcher

/// 📂 Evaluates Caddy's `file` matcher against the local filesystem.
///
/// The candidates are URI paths and `root` is a filesystem path, so the join
/// drops the candidate's leading slash. A trailing slash in the candidate
/// demands a directory; a candidate without one demands a regular file.
/// `first_exist_fallback` matches its last candidate without touching the
/// filesystem, which is how `php_fastcgi` treats `index.php` as existing.
/// A reached `=code` candidate raises that status instead of matching.
fn evaluate_file_matcher(
    request: &mut MatcherRequest<'_>,
    try_files: &[String],
    root: Option<&str>,
    try_policy: Option<&str>,
    split_path: &[String],
) -> MatcherVerdict {
    let path = request
        .path
        .split_once('?')
        .map_or(request.path, |(path, _)| path);
    let root = Path::new(root.unwrap_or("."));
    let policy = try_policy.unwrap_or("first_exist");

    #[derive(Clone)]
    struct Candidate {
        full_path: String,
        relative: String,
        remainder: String,
        is_dir: bool,
    }

    let make_candidate = |pattern: &str| -> Option<Candidate> {
        let expanded = expand_file_placeholder(pattern, path);
        let wants_directory = pattern.ends_with('/');
        let mut cleaned = clean_file_path(&expanded);
        if wants_directory && !cleaned.ends_with('/') {
            cleaned.push('/');
        }
        let (before_split, remainder) = first_split(&cleaned, split_path);
        let mut split_path_part = before_split;
        if wants_directory && !split_path_part.ends_with('/') {
            split_path_part.push('/');
        }
        let full_path = join_under_root(root, &split_path_part)?;
        let relative = format!("/{}", split_path_part.trim_start_matches('/'));
        Some(Candidate {
            full_path,
            relative,
            remainder,
            is_dir: wants_directory,
        })
    };

    let set_placeholders = |request: &mut MatcherRequest<'_>, candidate: &Candidate| {
        let Some(vars) = request.vars.as_deref_mut() else {
            return;
        };
        vars.insert(
            "http.matchers.file.relative".to_string(),
            candidate.relative.clone(),
        );
        vars.insert(
            "http.matchers.file.absolute".to_string(),
            candidate.full_path.clone(),
        );
        vars.insert(
            "http.matchers.file.type".to_string(),
            if candidate.is_dir {
                "directory".to_string()
            } else {
                "file".to_string()
            },
        );
        vars.insert(
            "http.matchers.file.remainder".to_string(),
            candidate.remainder.clone(),
        );
    };

    match policy {
        "first_exist" | "first_exist_fallback" | "" => {
            let fallback_last = policy == "first_exist_fallback";
            for (index, pattern) in try_files.iter().enumerate() {
                if let Some(status) = parse_error_code(pattern) {
                    return MatcherVerdict::Error(status);
                }
                let Some(candidate) = make_candidate(pattern) else {
                    continue;
                };
                if fallback_last && index + 1 == try_files.len() {
                    set_placeholders(request, &candidate);
                    return MatcherVerdict::Match;
                }
                if file_exists_strict(&candidate.full_path, candidate.is_dir) {
                    set_placeholders(request, &candidate);
                    return MatcherVerdict::Match;
                }
            }
            MatcherVerdict::NoMatch
        }
        "largest_size" | "smallest_size" | "most_recently_modified" => {
            let mut best: Option<(Candidate, u64)> = None;
            for pattern in try_files {
                let Some(candidate) = make_candidate(pattern) else {
                    continue;
                };
                let Ok(metadata) = Path::new(&candidate.full_path).metadata() else {
                    continue;
                };
                let key = match policy {
                    "largest_size" => metadata.len(),
                    "smallest_size" => u64::MAX - metadata.len(),
                    _ => metadata
                        .modified()
                        .ok()
                        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|duration| duration.as_nanos() as u64)
                        .unwrap_or(0),
                };
                if best.as_ref().is_none_or(|(_, best_key)| key > *best_key) {
                    best = Some((candidate, key));
                }
            }
            match best {
                Some((candidate, _)) => {
                    set_placeholders(request, &candidate);
                    MatcherVerdict::Match
                }
                None => MatcherVerdict::NoMatch,
            }
        }
        _ => MatcherVerdict::NoMatch,
    }
}

/// 🧭 Expands the placeholders the file matcher understands.
fn expand_file_placeholder(pattern: &str, path: &str) -> String {
    pattern
        .replace("{path}", path)
        .replace("{http.request.uri.path}", path)
}

/// 🧹 Cleans `.`/`..` and repeated separators without canonicalizing.
fn clean_file_path(path: &str) -> String {
    if !path.contains("//") && !path.split('/').any(|s| s == "." || s == "..") {
        return path.strip_suffix('/').unwrap_or(path).to_string();
    }
    let mut resolved: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                resolved.pop();
            }
            other => resolved.push(other),
        }
    }
    let mut cleaned = String::with_capacity(path.len());
    for segment in &resolved {
        cleaned.push('/');
        cleaned.push_str(segment);
    }
    cleaned
}

/// 🪚 Splits a cleaned path at the first ASCII case-insensitive delimiter
/// that ends a path segment; the remainder is `PATH_INFO`.
fn first_split(path: &str, split_path: &[String]) -> (String, String) {
    let bytes = path.as_bytes();
    for split in split_path {
        if split.is_empty() || split.len() > bytes.len() {
            continue;
        }
        let needle = split.as_bytes();
        for index in 0..=bytes.len() - needle.len() {
            if bytes[index..index + needle.len()]
                .iter()
                .zip(needle)
                .all(|(left, right)| left.eq_ignore_ascii_case(right))
            {
                let end = index + needle.len();
                if end == bytes.len() || bytes[end] == b'/' {
                    return (path[..end].to_string(), path[end..].to_string());
                }
            }
        }
    }
    (path.to_string(), String::new())
}

/// 📂 Joins a filesystem root with a cleaned URI path, refusing `..` escape.
fn join_under_root(root: &Path, path: &str) -> Option<String> {
    if path.split('/').any(|segment| segment == "..") {
        return None;
    }
    Some(
        root.join(path.trim_start_matches('/'))
            .to_string_lossy()
            .into_owned(),
    )
}

/// 📏 Strict existence: a trailing slash demands a directory, otherwise a
/// regular file, exactly like the upstream matcher.
fn file_exists_strict(full_path: &str, wants_directory: bool) -> bool {
    let Ok(metadata) = Path::new(full_path).metadata() else {
        return false;
    };
    metadata.is_dir() == wants_directory
}

/// 🚨 Reads a `=404`-style fallback candidate as a status code.
fn parse_error_code(candidate: &str) -> Option<u16> {
    let code = candidate.strip_prefix('=')?;
    let status = code.parse::<u16>().ok()?;
    (100..=999).contains(&status).then_some(status)
}

/// 🔍 Writes one regex match's captures into the request's variable map.
///
/// Keys mirror Caddy's replacer: `{re.<name>.<index>}` (index 0 is the whole
/// match) or `{re.<index>}` for an unnamed matcher, plus
/// `{re.<name>.<group>}` / `{re.<group>}` for named groups.
fn record_regexp_captures(
    vars: &mut std::collections::BTreeMap<String, String>,
    name: Option<&str>,
    regex: &regex::Regex,
    text: &str,
) -> bool {
    let Some(captures) = regex.captures(text) else {
        return false;
    };
    for (index, value) in captures.iter().enumerate() {
        let Some(value) = value else {
            continue;
        };
        if let Some(name) = name {
            vars.insert(format!("re.{name}.{index}"), value.as_str().to_string());
        }
        vars.insert(format!("re.{index}"), value.as_str().to_string());
    }
    for (index, group_name) in regex.capture_names().enumerate() {
        if let Some(group_name) = group_name
            && let Some(value) = captures.get(index)
        {
            if let Some(name) = name {
                vars.insert(
                    format!("re.{name}.{group_name}"),
                    value.as_str().to_string(),
                );
            }
            vars.insert(format!("re.{group_name}"), value.as_str().to_string());
        }
    }
    true
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
        evaluate_condition(Some(value), condition, compiled)
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
        MatcherCondition::EndsWith(suffix) => value.map(|v| v.ends_with(suffix)).unwrap_or(false),
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
    glob_match(pattern, path)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::HandlerConfig;
    use http::HeaderMap;
    use std::collections::BTreeMap;

    fn make_route(path: &str) -> RouteConfig {
        RouteConfig {
            path: path.to_string(),
            handler: HandlerConfig::Respond {
                status: 200,
                body: None,
                headers: BTreeMap::new(),
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
                .match_request(
                    path,
                    "GET",
                    &headers,
                    "example.com",
                    "10.0.0.1",
                    "https",
                    None,
                )
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
                .match_request(
                    path,
                    "GET",
                    &headers,
                    "example.com",
                    "10.0.0.1",
                    "https",
                    None,
                )
                .is_some()
        };

        // An `and` of two disjoint paths can never match anything, which is
        // what this config silently became before.
        assert!(matches("/a/one"));
        assert!(matches("/b/two"));
        assert!(!matches("/c/three"));
    }

    /// 🧭 The public `evaluate` primitive answers the same question the
    /// router answers for a route-level matcher, so C2 can reuse it for
    /// pipeline-element matchers without reimplementing evaluation.
    #[test]
    fn the_public_evaluate_primitive_matches_like_the_router() {
        let matcher = Matcher::And(
            Box::new(Matcher::Path {
                patterns: vec!["/api/*".to_string()],
            }),
            Box::new(Matcher::Header {
                name: "x-tenant".to_string(),
                condition: MatcherCondition::Equals("acme".to_string()),
            }),
        );
        let compiled = CompiledMatcher::compile(&matcher);
        let mut matching = HeaderMap::new();
        matching.insert("x-tenant", "acme".parse().unwrap());
        let empty = HeaderMap::new();
        fn request(headers: &HeaderMap) -> MatcherRequest<'_> {
            MatcherRequest {
                path: "/api/users",
                method: "GET",
                headers,
                host: "example.com",
                remote_ip: "10.0.0.1",
                protocol: "https",
                vars: None,
            }
        }

        assert!(evaluate(&compiled, &mut request(&matching)));
        assert!(!evaluate(&compiled, &mut request(&empty)));
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
                headers: BTreeMap::new(),
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
                .match_request(
                    path,
                    "GET",
                    &headers,
                    "example.com",
                    "10.0.0.1",
                    "https",
                    None,
                )
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
                headers: BTreeMap::new(),
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
                    "https",
                    None
                )
                .is_some()
        );
        assert!(
            suffix
                .match_request(
                    "/site.js", "GET", &headers, "e.com", "10.0.0.1", "https", None
                )
                .is_none()
        );

        let prefix = Router::new(vec![route_for("/api/*")]);
        assert!(
            prefix
                .match_request(
                    "/api/users",
                    "GET",
                    &headers,
                    "e.com",
                    "10.0.0.1",
                    "https",
                    None
                )
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
                    "https",
                    None
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
                    "https",
                    None
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
                    "https",
                    None
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
                headers: BTreeMap::new(),
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
                    "https",
                    None
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
                    "https",
                    None
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
                headers: BTreeMap::new(),
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
                None,
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
                None,
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
                headers: BTreeMap::new(),
            },
            methods: None,
            matcher: Some(Matcher::RemoteIp(vec!["10.0.0.0/8".to_string()])),
        };
        let router = Router::new(vec![route]);
        let headers = HeaderMap::new();

        assert!(
            router
                .match_request("/", "GET", &headers, "e.com", "10.1.2.3", "https", None)
                .is_some()
        );
        assert!(
            router
                .match_request("/", "GET", &headers, "e.com", "192.168.1.1", "https", None)
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
                headers: BTreeMap::new(),
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
                .match_request("/", "GET", &headers, "e.com", "10.0.0.1", "https", None)
                .is_some()
        );
        headers.insert("Foo", "bar".parse().unwrap());
        assert!(
            router
                .match_request("/", "GET", &headers, "e.com", "10.0.0.1", "https", None)
                .is_none()
        );
    }

    /// 📂 The `file` matcher finds an existing file and publishes the
    /// `{http.matchers.file.*}` placeholders `php_fastcgi` rewrites to.
    #[test]
    fn file_matcher_matches_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.php"), "<?php").unwrap();
        let root = dir.path().to_str().unwrap();
        let compiled = CompiledMatcher::compile(&Matcher::File {
            try_files: vec![
                "{path}".to_string(),
                "{path}/index.php".to_string(),
                "index.php".to_string(),
            ],
            root: Some(root.to_string()),
            try_policy: Some("first_exist_fallback".to_string()),
            split_path: vec![".php".to_string()],
        });
        let headers = HeaderMap::new();
        let mut vars = BTreeMap::new();
        let mut request = MatcherRequest {
            path: "/index.php",
            method: "GET",
            headers: &headers,
            host: "example.com",
            remote_ip: "10.0.0.1",
            protocol: "http",
            vars: Some(&mut vars),
        };
        assert_eq!(
            evaluate_verdict(&compiled, &mut request),
            MatcherVerdict::Match
        );
        assert_eq!(
            vars.get("http.matchers.file.relative").unwrap(),
            "/index.php"
        );
        assert_eq!(
            vars.get("http.matchers.file.absolute").unwrap(),
            &format!("{root}/index.php")
        );
        assert_eq!(vars.get("http.matchers.file.type").unwrap(), "file");
        assert_eq!(vars.get("http.matchers.file.remainder").unwrap(), "");
    }

    /// 🪚 `split_path` publishes the remainder as `PATH_INFO`.
    #[test]
    fn file_matcher_split_path_publishes_the_remainder() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("api.php"), "<?php").unwrap();
        let root = dir.path().to_str().unwrap();
        let compiled = CompiledMatcher::compile(&Matcher::File {
            try_files: vec!["{path}".to_string()],
            root: Some(root.to_string()),
            try_policy: None,
            split_path: vec![".php".to_string()],
        });
        let headers = HeaderMap::new();
        let mut vars = BTreeMap::new();
        let mut request = MatcherRequest {
            path: "/api.php/extra",
            method: "GET",
            headers: &headers,
            host: "example.com",
            remote_ip: "10.0.0.1",
            protocol: "http",
            vars: Some(&mut vars),
        };
        assert_eq!(
            evaluate_verdict(&compiled, &mut request),
            MatcherVerdict::Match
        );
        assert_eq!(vars.get("http.matchers.file.relative").unwrap(), "/api.php");
        assert_eq!(vars.get("http.matchers.file.remainder").unwrap(), "/extra");
    }

    /// 🎲 `first_exist_fallback` treats its last candidate as existing,
    /// which is how `php_fastcgi` assumes `index.php` exists.
    #[test]
    fn file_matcher_first_exist_fallback_needs_no_io_for_the_last_candidate() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_str().unwrap();
        let compiled = CompiledMatcher::compile(&Matcher::File {
            try_files: vec!["{path}".to_string(), "index.php".to_string()],
            root: Some(root.to_string()),
            try_policy: Some("first_exist_fallback".to_string()),
            split_path: vec![".php".to_string()],
        });
        let headers = HeaderMap::new();
        let mut vars = BTreeMap::new();
        let mut request = MatcherRequest {
            path: "/missing.php",
            method: "GET",
            headers: &headers,
            host: "example.com",
            remote_ip: "10.0.0.1",
            protocol: "http",
            vars: Some(&mut vars),
        };
        assert_eq!(
            evaluate_verdict(&compiled, &mut request),
            MatcherVerdict::Match
        );
        assert_eq!(
            vars.get("http.matchers.file.relative").unwrap(),
            "/index.php"
        );
    }

    /// 🚨 A reached `=404` candidate raises the status instead of matching.
    #[test]
    fn file_matcher_error_candidate_raises_the_status() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_str().unwrap();
        let compiled = CompiledMatcher::compile(&Matcher::File {
            try_files: vec!["{path}".to_string(), "=404".to_string()],
            root: Some(root.to_string()),
            try_policy: None,
            split_path: Vec::new(),
        });
        let headers = HeaderMap::new();
        let mut vars = BTreeMap::new();
        let mut request = MatcherRequest {
            path: "/missing.php",
            method: "GET",
            headers: &headers,
            host: "example.com",
            remote_ip: "10.0.0.1",
            protocol: "http",
            vars: Some(&mut vars),
        };
        assert_eq!(
            evaluate_verdict(&compiled, &mut request),
            MatcherVerdict::Error(404)
        );
    }

    /// 📁 A trailing slash demands a directory, matching upstream exactly.
    #[test]
    fn file_matcher_distinguishes_directories_from_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("assets")).unwrap();
        std::fs::write(dir.path().join("file.txt"), "x").unwrap();
        let root = dir.path().to_str().unwrap();
        let compiled = CompiledMatcher::compile(&Matcher::File {
            try_files: vec!["{path}/".to_string()],
            root: Some(root.to_string()),
            try_policy: None,
            split_path: Vec::new(),
        });
        let headers = HeaderMap::new();

        let mut vars = BTreeMap::new();
        let mut request = MatcherRequest {
            path: "/assets",
            method: "GET",
            headers: &headers,
            host: "example.com",
            remote_ip: "10.0.0.1",
            protocol: "http",
            vars: Some(&mut vars),
        };
        assert_eq!(
            evaluate_verdict(&compiled, &mut request),
            MatcherVerdict::Match
        );
        assert_eq!(vars.get("http.matchers.file.type").unwrap(), "directory");

        let mut vars = BTreeMap::new();
        let mut request = MatcherRequest {
            path: "/file.txt",
            method: "GET",
            headers: &headers,
            host: "example.com",
            remote_ip: "10.0.0.1",
            protocol: "http",
            vars: Some(&mut vars),
        };
        assert_eq!(
            evaluate_verdict(&compiled, &mut request),
            MatcherVerdict::NoMatch
        );
    }
}
