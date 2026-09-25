// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! High-performance route matcher using radix tree
//!
//! Provides O(log n) path matching with support for wildcards and parameters.

use crate::config::{
    HandlerConfig, HandlerElement, IpRanges, Matcher, MatcherCondition, RouteConfig,
};
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
    pub addresses: RequestAddresses,
    pub protocol: &'a str,
    /// 🧰 Request-scoped variables and regexp captures, written and read by
    /// the `vars` and regexp matchers. `None` means nothing is visible,
    /// which matches nothing.
    pub vars: Option<&'a mut std::collections::BTreeMap<String, String>>,
}

/// 🌐 The two addresses a request is known by, which the `client_ip` and
/// `remote_ip` matchers deliberately read differently.
///
/// Behind a trusted load balancer they differ: the connection comes from the
/// balancer (`remote_ip`), and the balancer vouches for the real client in a
/// forwarded header (`client_ip`). Without a trusted proxy in front they are
/// the same address. `None` means the address is not known at that point of
/// the request, and a matcher that needs it matches nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestAddresses {
    /// 🛡️ The client after `trusted_proxies` has been applied: the forwarded
    /// address when the immediate peer is trusted, the peer otherwise.
    pub client_ip: Option<std::net::IpAddr>,
    /// 🔌 The immediate peer of the connection, whatever any header claims. A
    /// PROXY-protocol listener's declared source counts as the peer, because
    /// that header replaces the connection's address rather than forwarding it.
    pub remote_ip: Option<std::net::IpAddr>,
}

impl RequestAddresses {
    /// 🔌 A request with no proxy in front, so both addresses are the peer.
    pub fn direct(peer: std::net::IpAddr) -> Self {
        Self {
            client_ip: Some(peer),
            remote_ip: Some(peer),
        }
    }
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

/// 🧭 Picks the route that answers a request: the **first** route in list
/// order whose path and matcher accept it (issue #18).
///
/// The radix tree only narrows the list. Each node holds, in list order, the
/// indices of every route that can match a path landing there (see
/// `route_candidates`), so a lookup is one tree walk and a scan of a short
/// slice — never a scan of the whole site and never a sort.
pub struct Router {
    /// Candidate indices per radix node, ascending.
    path_router: RadixRouter<Box<[usize]>>,
    /// Routes with no path constraint, ascending: the candidates for a path
    /// that lands on no node.
    default_routes: Box<[usize]>,
    /// All routes for iteration
    all_routes: Vec<RouteConfig>,
    /// Compiled routes, indexed like `all_routes`; list order is index order.
    compiled_routes: Vec<CompiledRoute>,
}

impl Router {
    /// 🏗️ Compiles the routes and precomputes every node's candidate list.
    pub fn new(routes: Vec<RouteConfig>) -> Self {
        let compiled_routes: Vec<CompiledRoute> = routes
            .iter()
            .enumerate()
            .map(|(index, config)| CompiledRoute {
                config: config.clone(),
                index,
                compiled_matcher: config.matcher.as_ref().map(CompiledMatcher::compile),
                matcher_precompile: precompile_handler(&config.handler),
            })
            .collect();

        let candidates = super::route_candidates::build(&routes);
        let mut path_router = RadixRouter::new();
        for (pattern, indices) in candidates.nodes {
            if let Err(e) = path_router.insert(&pattern, indices) {
                tracing::warn!("🧭 Failed to insert route {}: {}", pattern, e);
            }
        }

        Self {
            path_router,
            default_routes: candidates.any,
            all_routes: routes,
            compiled_routes,
        }
    }

    /// 🔎 Returns the compiled route at `index`, matching the index the
    /// runtime uses for its per-route tables.
    pub fn compiled_route(&self, index: usize) -> Option<&CompiledRoute> {
        self.compiled_routes.get(index)
    }

    /// 🔎 The routes a path could match, in the order they would be tried.
    pub fn match_path(&self, path: &str) -> Vec<&CompiledRoute> {
        self.candidates(path)
            .iter()
            .map(|&index| &self.compiled_routes[index])
            .collect()
    }

    /// 🌲 The precomputed candidate slice for a path: its node's list, or the
    /// catch-alls when it lands on no node.
    fn candidates(&self, path: &str) -> &[usize] {
        match self.path_router.at(path) {
            Ok(matched) => matched.value,
            Err(_) => &self.default_routes,
        }
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
        addresses: RequestAddresses,
        protocol: &str,
        vars: Option<&mut std::collections::BTreeMap<String, String>>,
    ) -> Option<&CompiledRoute> {
        let normalized_path = Self::normalize_request_path(path);
        self.match_normalized_request(
            &normalized_path,
            method,
            headers,
            host,
            addresses,
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
        addresses: RequestAddresses,
        protocol: &str,
        vars: Option<&mut std::collections::BTreeMap<String, String>>,
    ) -> Option<&CompiledRoute> {
        let mut request = MatcherRequest {
            path,
            method,
            headers,
            host,
            addresses,
            protocol,
            vars,
        };

        // 🌲 One tree walk, then the first candidate that agrees. The slice
        // already holds catch-alls in their list position, so nothing is
        // merged, sorted, or allocated here.
        self.candidates(path)
            .iter()
            .map(|&index| &self.compiled_routes[index])
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

    /// Get all routes
    pub fn routes(&self) -> &[RouteConfig] {
        &self.all_routes
    }
}

/// 🧭 Builds the precompiled matcher tree for one handler.
fn precompile_handler(handler: &HandlerConfig) -> MatcherPrecompile {
    match handler {
        HandlerConfig::Pipeline { handlers }
        | HandlerConfig::FirstMatch { handlers }
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
            | HandlerConfig::FirstMatch { handlers }
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
        // 🌐 Same ranges, different address: see `RequestAddresses`.
        Matcher::RemoteIp(ranges) => bool_verdict(ip_matches(ranges, request.addresses.remote_ip)),
        Matcher::ClientIp(ranges) => bool_verdict(ip_matches(ranges, request.addresses.client_ip)),
        Matcher::Protocol(protocols) => bool_verdict(
            protocols
                .iter()
                .any(|protocol| protocol.eq_ignore_ascii_case(request.protocol)),
        ),
        // 🧰 The `vars` matcher matches when one request-scoped value equals any
        // listed value. Which value is asked for depends on how the key is
        // spelled, and the two spellings read from different places — this is
        // Caddy's rule, written down at `modules/caddyhttp/vars.go:187-193` and
        // in the type's own doc comment there: a key surrounded by braces is a
        // *placeholder*, resolved against the request, while a bare key is a
        // name looked up in the request's variable map.
        //
        // 📌 The count matters: `{a}{b}` has two braces and is therefore a
        // variable name, not a placeholder. Caddy spells the test out
        // (`strings.Count(key, "{") == 1`) because the alternative reading —
        // "strip the outer braces and resolve what is left" — would silently
        // turn a name nobody can set into a lookup nobody intended.
        //
        // 🚫 A request with no visible variables never matches on the bare
        // spelling, which is the fail-closed reading of a variable that has not
        // been set.
        Matcher::Vars { name, values } => {
            let placeholder = name
                .strip_prefix('{')
                .and_then(|rest| rest.strip_suffix('}'))
                .filter(|rest| !rest.contains('{') && !rest.contains('}'));
            let value = match placeholder {
                Some(placeholder) => {
                    resolve_matcher_placeholder(placeholder, request, request.path)
                }
                None => request
                    .vars
                    .as_deref()
                    .and_then(|vars| vars.get(name))
                    .cloned()
                    .unwrap_or_default(),
            };
            bool_verdict(values.iter().any(|candidate| candidate == &value))
        }
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
///
/// 📌 This is also what the `try_files` directive is: upstream expands it into
/// this matcher plus a rewrite to `{http.matchers.file.relative}`, and since
/// 2026-08-11 so does the Pingclairfile adapter. There is deliberately no
/// second implementation of "find the first candidate that exists" — the one
/// that existed until then disagreed with this one about policies, globs, and
/// every placeholder except `{path}`.
pub fn evaluate_file_matcher(
    request: &mut MatcherRequest<'_>,
    try_files: &[String],
    root: Option<&str>,
    try_policy: Option<&str>,
    split_path: &[String],
) -> MatcherVerdict {
    // 🍃 `request.path` is a borrow of the request *text*, not of the request
    // struct, so this survives the `&mut request` the placeholder writes need.
    let path: &str = request
        .path
        .split_once('?')
        .map_or(request.path, |(path, _)| path);
    let root = Path::new(root.unwrap_or("."));
    let policy = try_policy.unwrap_or("first_exist");

    match policy {
        "first_exist" | "first_exist_fallback" | "" => {
            let fallback_last = policy == "first_exist_fallback";
            for (index, pattern) in try_files.iter().enumerate() {
                if let Some(status) = parse_error_code(pattern) {
                    return MatcherVerdict::Error(status);
                }
                let candidates = file_candidates(request, pattern, path, root, split_path);
                for candidate in candidates.as_slice() {
                    // 🎲 The fallback policy claims its last candidate without
                    // asking the filesystem, which is how `php_fastcgi` treats
                    // `index.php` as present even before it is written.
                    if fallback_last && index + 1 == try_files.len() {
                        set_file_placeholders(request, candidate);
                        return MatcherVerdict::Match;
                    }
                    if file_exists_strict(&candidate.full_path, candidate.is_dir) {
                        set_file_placeholders(request, candidate);
                        return MatcherVerdict::Match;
                    }
                }
            }
            MatcherVerdict::NoMatch
        }
        "largest_size" | "smallest_size" | "most_recently_modified" => {
            let mut best: Option<(FileCandidate, u64)> = None;
            for pattern in try_files {
                let candidates = file_candidates(request, pattern, path, root, split_path);
                for candidate in candidates.as_slice() {
                    let Ok(metadata) = candidate.full_path.metadata() else {
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
                        best = Some((candidate.clone(), key));
                    }
                }
            }
            match best {
                Some((candidate, _)) => {
                    set_file_placeholders(request, &candidate);
                    MatcherVerdict::Match
                }
                None => MatcherVerdict::NoMatch,
            }
        }
        _ => MatcherVerdict::NoMatch,
    }
}

/// 📂 One resolved `file` matcher candidate.
#[derive(Clone)]
struct FileCandidate {
    /// 📁 Kept as a path, not text: on Unix a filename is bytes, and the
    /// existence probe has to ask about the same bytes the directory holds.
    full_path: std::path::PathBuf,
    relative: String,
    remainder: String,
    is_dir: bool,
}

/// 📂 The candidates one configured pattern produced.
///
/// A pattern without glob metacharacters yields at most one candidate and
/// never allocates a `Vec` — which is every candidate in the documented
/// single-page-application and `php_fastcgi` shapes.
enum FileCandidates {
    Single(Option<FileCandidate>),
    Globbed(Vec<FileCandidate>),
}

impl FileCandidates {
    fn as_slice(&self) -> &[FileCandidate] {
        match self {
            FileCandidates::Single(one) => one.as_slice(),
            FileCandidates::Globbed(many) => many.as_slice(),
        }
    }
}

/// 🛡️ Most glob expansions a single candidate may produce.
///
/// Upstream has no ceiling here. This one exists because the expansion reads
/// directories on a request path: `try_files /cache/*` pointed at a directory
/// holding a hundred thousand entries would otherwise build a hundred thousand
/// candidate structs before answering one request. The limit is far above any
/// plausible configuration, so reaching it means the pattern was pointed
/// somewhere it should not have been.
const MAX_GLOB_CANDIDATES: usize = 1_024;

/// 📂 Expands one configured pattern into the candidates it names.
fn file_candidates(
    request: &MatcherRequest<'_>,
    pattern: &str,
    path: &str,
    root: &Path,
    split_path: &[String],
) -> FileCandidates {
    let expanded = expand_file_pattern(pattern, request, path);
    let wants_directory = pattern.ends_with('/');
    let mut cleaned = clean_file_path(&expanded);
    if wants_directory && !cleaned.ends_with('/') {
        cleaned.push('/');
    }
    // 🪚 The split has to happen before globbing, or the `PATH_INFO` tail
    // would be part of the filename the filesystem is asked about.
    let (before_split, remainder) = first_split(&cleaned, split_path);
    let mut split_path_part = before_split;
    if wants_directory && !split_path_part.ends_with('/') {
        split_path_part.push('/');
    }
    let globs = pattern_globs(pattern);
    if !globs {
        // 🔤 This is the second place a URL becomes a filename — the first is
        // the static file server's `resolve_path` — so it decodes escapes with
        // the rule `templates` and FastCGI share. Only the path the filesystem
        // is *asked about* is decoded; `relative` stays encoded because it goes
        // back into the request line, where a raw space is a malformed request.
        //
        // 📁 The result is a path, never text: on Unix a filename is bytes, so
        // `/caf%E9.txt` probes exactly the name `caf\xE9.txt` holds on disk.
        // A `..` before or after decoding names nothing.
        let Some(full_path) = crate::percent::resolve_under_root(root, &split_path_part) else {
            return FileCandidates::Single(None);
        };
        let relative = format!("/{}", split_path_part.trim_start_matches('/'));
        return FileCandidates::Single(Some(FileCandidate {
            full_path,
            relative,
            remainder,
            is_dir: wants_directory,
        }));
    }

    // 🔍 A glob only ever names paths that already exist, so the results are
    // whatever the filesystem holds; the strict directory-or-file check still
    // runs on each of them afterwards. Escapes are *not* decoded here: `%2A`
    // becoming `*` would let a request choose which files the pattern matches.
    let matches = super::file_glob::expand(root, &split_path_part, MAX_GLOB_CANDIDATES);
    // 🔗 Each match is a name read from disk, so it stays a path and its
    // relative form is percent-encoded from the raw bytes. Converting it to
    // text lossily turned a name that is not valid UTF-8 into U+FFFD, and the
    // probe and the rewrite then asked about a file that does not exist.
    let mut expanded = Vec::new();
    for entry in matches {
        let Some(below_root) = entry
            .strip_prefix(root)
            .ok()
            .and_then(crate::percent::path_bytes)
        else {
            continue;
        };
        let mut relative = String::with_capacity(below_root.len() + 1);
        relative.push('/');
        crate::percent::push_encoded_path(&mut relative, below_root);
        expanded.push(FileCandidate {
            full_path: entry,
            relative,
            remainder: remainder.clone(),
            is_dir: wants_directory,
        });
    }
    FileCandidates::Globbed(expanded)
}

/// 🧰 Publishes `{http.matchers.file.*}` for the candidate that matched.
fn set_file_placeholders(request: &mut MatcherRequest<'_>, candidate: &FileCandidate) {
    let Some(vars) = request.vars.as_deref_mut() else {
        return;
    };
    vars.insert(
        "http.matchers.file.relative".to_string(),
        candidate.relative.clone(),
    );
    // 📌 Placeholders are text. A filesystem path that is not valid UTF-8 has
    // no faithful text spelling, so it is left unpublished rather than
    // published as a different, U+FFFD-bearing path.
    if let Some(absolute) = candidate.full_path.to_str() {
        vars.insert(
            "http.matchers.file.absolute".to_string(),
            absolute.to_string(),
        );
    }
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
}

/// 🧭 The placeholder names a matcher may resolve.
///
/// Every name here is answerable from [`MatcherRequest`] alone. That is the
/// whole rule, and it is why the list is short: a matcher runs in this crate,
/// which knows nothing about the proxy's request type, so a name that needs
/// the listener's scheme or the process environment cannot be resolved here at
/// all. `validate_config` refuses any other name rather than letting it stand
/// as a literal — a candidate spelled `{env.HOME}` would otherwise be looked up
/// as a file whose name contains braces, find nothing, and fall through, which
/// is indistinguishable from a missing file.
///
/// 📌 Two matchers read this list, and they read it for the same reason. A
/// `file` matcher's candidates interpolate it (`expand_file_pattern`), and a
/// `vars` matcher's `{placeholder}` key is resolved through it. The failure a
/// name outside the list produces is identical in both: something that
/// compiles, loads, and silently never matches.
///
/// 🤔 Evaluated and rejected on 2026-08-11: sharing
/// `pingclair_proxy::server::resolve_single_placeholder`, which understands a
/// wider set. It takes a `pingora_http::RequestHeader`, so sharing it means
/// either this crate depending on the proxy (a cycle) or the proxy's request
/// type moving into the router. The second is the right end state and is worth
/// its own session; doing it here would have put a hot-path type change inside
/// a `try_files` commit.
pub const MATCHER_PLACEHOLDERS: &[&str] = &[
    "path",
    "uri",
    "query",
    "?query",
    "host",
    "hostport",
    "port",
    "method",
    "remote_ip",
    "remote_host",
    "client_ip",
    "http.request.uri.path",
    "http.request.uri",
    "http.request.uri.query",
    "http.request.host",
    "http.request.hostport",
    "http.request.port",
    "http.request.method",
    "http.request.remote.host",
    "http.request.client_ip",
];

/// 🧭 The placeholder prefixes a matcher may resolve.
///
/// These are open-ended families rather than single names: any header, any
/// `vars` entry, any regexp capture.
pub const MATCHER_PLACEHOLDER_PREFIXES: &[&str] = &[
    "http.request.header.",
    "http.vars.",
    "http.request.orig_uri.",
    "re.",
    "labels.",
    "http.request.host.labels.",
];

/// 🧭 Expands the placeholders the file matcher understands.
///
/// 🛡️ Substituted values are glob-escaped, so a request can never introduce a
/// metacharacter into a pattern. Without that, `try_files /files/{path}` under
/// a request for `/*` would expand to a glob and list the directory — the
/// client would be choosing which file the pattern matches. Upstream escapes
/// for the same reason (`fileserver/matcher.go`, `globSafeRepl`, `ff6da121`).
/// The escaping happens whether or not this pattern globs, because whether it
/// globs is decided by the *configured* text, and that decision has to hold
/// after substitution too.
fn expand_file_pattern(pattern: &str, request: &MatcherRequest<'_>, path: &str) -> String {
    if !pattern.contains('{') {
        return pattern.to_string();
    }
    let mut out = String::with_capacity(pattern.len());
    let mut rest = pattern;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        let Some(end) = rest[start..].find('}') else {
            // 🚫 An unterminated brace is not a placeholder; keep it verbatim.
            break;
        };
        let name = &rest[start + 1..start + end];
        push_glob_safe(&mut out, &resolve_matcher_placeholder(name, request, path));
        rest = &rest[start + end + 1..];
    }
    out.push_str(rest);
    out
}

/// 🧭 Resolves one matcher placeholder from the request.
///
/// 📌 `path` is the caller's notion of the request's path, and the two callers
/// mean different things by it. A `file` matcher passes the candidate it is
/// testing, because `{path}` there is the part of the request path that
/// candidate was built from. The `vars` matcher passes the request's own path,
/// because it is naming the request and not a candidate.
///
/// An unknown name resolves to the empty string, matching every other
/// placeholder site in this project. It is not reachable from a Pingclairfile,
/// because `validate_config` refuses names outside
/// [`MATCHER_PLACEHOLDERS`], but a JSON configuration can still get here.
fn resolve_matcher_placeholder(name: &str, request: &MatcherRequest<'_>, path: &str) -> String {
    if let Some(header) = name.strip_prefix("http.request.header.") {
        return request
            .headers
            .get(header)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_string();
    }
    if let Some(var) = name.strip_prefix("http.vars.") {
        return request
            .vars
            .as_deref()
            .and_then(|vars| vars.get(var))
            .cloned()
            .unwrap_or_default();
    }
    if name.starts_with("http.request.orig_uri.") || name == "re" || name.starts_with("re.") {
        return request
            .vars
            .as_deref()
            .and_then(|vars| vars.get(name))
            .cloned()
            .unwrap_or_default();
    }
    // 🧭 `{host}` is the hostname without its port; `{hostport}` keeps it.
    // A bracketed IPv6 literal has colons of its own, so only a colon after
    // the closing bracket is a port separator.
    fn host_without_port(host: &str) -> &str {
        match host.rsplit_once(':') {
            Some((name, _)) if !host.starts_with('[') || host.contains("]:") => name,
            _ => host,
        }
    }
    let query = || {
        request
            .path
            .split_once('?')
            .map(|(_, query)| query)
            .unwrap_or_default()
    };
    if let Some(raw) = name
        .strip_prefix("http.request.host.labels.")
        .or_else(|| name.strip_prefix("labels."))
    {
        let host = host_without_port(request.host);
        let labels: Vec<&str> = host.split('.').collect();
        return raw
            .parse::<usize>()
            .ok()
            .and_then(|index| labels.len().checked_sub(index + 1))
            .and_then(|index| labels.get(index))
            .unwrap_or(&"")
            .to_string();
    }
    match name {
        "path" | "http.request.uri.path" => path.to_string(),
        "uri" | "http.request.uri" => request.path.to_string(),
        "query" | "http.request.uri.query" => query().to_string(),
        "?query" => {
            let query = query();
            if query.is_empty() {
                String::new()
            } else {
                format!("?{query}")
            }
        }
        "host" | "http.request.host" => host_without_port(request.host).to_string(),
        "hostport" | "http.request.hostport" => request.host.to_string(),
        "port" | "http.request.port" => request
            .host
            .rsplit_once(':')
            .filter(|_| !request.host.starts_with('[') || request.host.contains("]:"))
            .map(|(_, port)| port.to_string())
            .unwrap_or_default(),
        "method" | "http.request.method" => request.method.to_string(),
        // 🛡️ `{client_ip}` is the client after `trusted_proxies`, and
        // `{remote_ip}` is our older spelling of it.
        "client_ip" | "http.request.client_ip" | "remote_ip" => request
            .addresses
            .client_ip
            .map(|ip| ip.to_string())
            .unwrap_or_default(),
        // 🔌 `{remote_host}` is the socket peer, the same split the
        // `remote_ip` and `client_ip` matchers make.
        "remote_host" | "http.request.remote.host" => request
            .addresses
            .remote_ip
            .map(|ip| ip.to_string())
            .unwrap_or_default(),
        _ => String::new(),
    }
}

/// 🛡️ Appends a placeholder value with every glob metacharacter escaped.
fn push_glob_safe(out: &mut String, value: &str) {
    for character in value.chars() {
        if matches!(character, '*' | '?' | '[' | ']') {
            out.push('[');
            out.push(character);
            out.push(']');
        } else {
            out.push(character);
        }
    }
}

/// 🔍 Reports whether a *configured* candidate asks to be expanded as a glob.
///
/// The answer depends only on the configuration text, never on the request, so
/// a candidate without a metacharacter never reaches the filesystem walk —
/// which matters, because that walk reads directories and the common candidate
/// (`{path}`, `/index.html`) is a single `stat`. It is a byte scan over a
/// short configured string with no allocation, which is why it is not hoisted
/// into the compiled matcher: the surrounding candidate construction allocates
/// several times over, and hoisting this would be the smaller half of that job.
///
/// 📌 Characters *inside* a `{…}` span do not count. `index.php?{query}` asks
/// for a query string, not a single-character wildcard, and `{?query}` names a
/// placeholder. Upstream reaches the same answer from the other direction — it
/// decides after substitution, and substitution escapes every metacharacter a
/// value could contribute — so the only text that can turn on globbing is
/// literal configuration text either way.
fn pattern_globs(pattern: &str) -> bool {
    let mut depth = 0usize;
    for character in pattern.chars() {
        match character {
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            '*' | '?' | '[' if depth == 0 => return true,
            _ => {}
        }
    }
    false
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

/// 📏 Strict existence: a trailing slash demands a directory, otherwise a
/// regular file, exactly like the upstream matcher.
fn file_exists_strict(full_path: &Path, wants_directory: bool) -> bool {
    let Ok(metadata) = full_path.metadata() else {
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

/// 🌐 Matches an address against ranges parsed when the configuration
/// loaded, as Caddy's `remote_ip`/`client_ip` matchers do. An unknown address
/// matches nothing.
fn ip_matches(ranges: &IpRanges, address: Option<std::net::IpAddr>) -> bool {
    address.is_some_and(|address| ranges.contains(address))
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

    /// 🔌 A request straight from `ip`, with no proxy in front.
    fn peer(ip: &str) -> RequestAddresses {
        RequestAddresses::direct(ip.parse().expect("test address parses"))
    }

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
                    peer("10.0.0.1"),
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
                    peer("10.0.0.1"),
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
                addresses: peer("10.0.0.1"),
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
                    peer("10.0.0.1"),
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
                    peer("10.0.0.1"),
                    "https",
                    None
                )
                .is_some()
        );
        assert!(
            suffix
                .match_request(
                    "/site.js",
                    "GET",
                    &headers,
                    "e.com",
                    peer("10.0.0.1"),
                    "https",
                    None
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
                    peer("10.0.0.1"),
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
                    peer("10.0.0.1"),
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
                    peer("10.0.0.1"),
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
                    peer("10.0.0.1"),
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
                    peer("10.0.0.1"),
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
                    peer("10.0.0.1"),
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
                peer("10.0.0.1"),
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
                peer("10.0.0.1"),
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
            matcher: Some(Matcher::RemoteIp(
                crate::config::IpRanges::parse(["10.0.0.0/8"]).unwrap(),
            )),
        };
        let router = Router::new(vec![route]);
        let headers = HeaderMap::new();

        assert!(
            router
                .match_request(
                    "/",
                    "GET",
                    &headers,
                    "e.com",
                    peer("10.1.2.3"),
                    "https",
                    None
                )
                .is_some()
        );
        assert!(
            router
                .match_request(
                    "/",
                    "GET",
                    &headers,
                    "e.com",
                    peer("192.168.1.1"),
                    "https",
                    None
                )
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
                .match_request(
                    "/",
                    "GET",
                    &headers,
                    "e.com",
                    peer("10.0.0.1"),
                    "https",
                    None
                )
                .is_some()
        );
        headers.insert("Foo", "bar".parse().unwrap());
        assert!(
            router
                .match_request(
                    "/",
                    "GET",
                    &headers,
                    "e.com",
                    peer("10.0.0.1"),
                    "https",
                    None
                )
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
            addresses: peer("10.0.0.1"),
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
            addresses: peer("10.0.0.1"),
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
            addresses: peer("10.0.0.1"),
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

    // MARK: - try_files, through the matcher it expands into
    //
    // 🧭 These cases were written against a second `try_files` lookup that
    // lived in the proxy crate until 2026-08-11. The lookup is gone — the
    // directive expands into this matcher now — but the cases are the reason
    // its behaviour is known to be right, so they moved here rather than
    // being deleted with it.

    /// 🗂️ A site root with a shell page and one real asset, which is the
    /// smallest fixture that can tell the two `try_files` outcomes apart.
    fn spa_root() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("index.html"), "shell").unwrap();
        std::fs::create_dir(root.path().join("assets")).unwrap();
        std::fs::write(root.path().join("assets/app.js"), "asset").unwrap();
        root
    }

    /// 🗂️ Runs the matcher the way `try_files` does and reports the path it
    /// would rewrite to, so each case reads as the behaviour it is about.
    fn try_files_target(files: &[&str], root: Option<&str>, request_path: &str) -> Option<String> {
        let candidates: Vec<String> = files.iter().map(|file| file.to_string()).collect();
        let headers = HeaderMap::new();
        let mut vars = BTreeMap::new();
        let mut request = MatcherRequest {
            path: request_path,
            method: "GET",
            headers: &headers,
            host: "example.com",
            addresses: peer("10.0.0.1"),
            protocol: "https",
            vars: Some(&mut vars),
        };
        match evaluate_file_matcher(&mut request, &candidates, root, None, &[]) {
            MatcherVerdict::Match => vars.get("http.matchers.file.relative").cloned(),
            MatcherVerdict::NoMatch | MatcherVerdict::Error(_) => None,
        }
    }

    /// 🔤 The `file` matcher stats a request-derived path, so it has to spell the
    /// name the way the filesystem does.
    ///
    /// `try_files {path} /index.html` is the canonical static configuration, and
    /// without decoding here an encoded name never matched the first candidate —
    /// so a file that plainly existed fell through to the shell, which looks
    /// exactly like the file being missing.
    #[test]
    fn an_escaped_name_matches_the_file_it_spells() {
        let root = spa_root();
        std::fs::write(root.path().join("hello world.txt"), "spaced").unwrap();
        std::fs::write(root.path().join("文件.txt"), "chinese").unwrap();

        // 🎯 The rewrite target stays the *encoded* spelling, because it is a URI
        // and goes back into the request line. Only the existence probe decodes.
        assert_eq!(
            try_files_target(
                &["{path}", "/index.html"],
                root.path().to_str(),
                "/hello%20world.txt"
            ),
            Some("/hello%20world.txt".to_string())
        );
        assert_eq!(
            try_files_target(
                &["{path}", "/index.html"],
                root.path().to_str(),
                "/%E6%96%87%E4%BB%B6.txt"
            ),
            Some("/%E6%96%87%E4%BB%B6.txt".to_string())
        );
    }

    /// 🚫 An escaped separator does not become one, and an escaped traversal is
    /// still refused after decoding.
    #[test]
    fn escaped_structure_is_refused_by_the_file_matcher() {
        let root = spa_root();
        for request in [
            "/a%2fb",
            "/%2e%2e%2findex.html",
            "/sub%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "/a%00b",
        ] {
            assert_eq!(
                try_files_target(&["{path}"], root.path().to_str(), request),
                None,
                "{request} must not match a file"
            );
        }
    }

    #[test]
    fn an_existing_file_is_returned_unchanged() {
        let root = spa_root();
        assert_eq!(
            try_files_target(
                &["{path}", "/index.html"],
                root.path().to_str(),
                "/assets/app.js"
            ),
            Some("/assets/app.js".to_string()),
            "a request for a real file must resolve to itself, not to the shell"
        );
    }

    #[test]
    fn a_missing_file_falls_to_the_next_candidate() {
        let root = spa_root();
        assert_eq!(
            try_files_target(
                &["{path}", "/index.html"],
                root.path().to_str(),
                "/deep/client/route"
            ),
            Some("/index.html".to_string())
        );
    }

    /// 🤡 The defect the original handler was rewritten for: candidates used to
    /// be treated as filesystem paths, so `/index.html` was looked up at the
    /// filesystem root instead of under the site root. Every application route
    /// answered 404 while the configuration looked exactly right.
    #[test]
    fn candidates_resolve_under_the_root_not_the_filesystem_root() {
        let root = spa_root();
        assert_eq!(
            try_files_target(&["/index.html"], root.path().to_str(), "/x"),
            Some("/index.html".to_string())
        );
        assert_eq!(
            try_files_target(&["/index.html"], Some("/nonexistent"), "/x"),
            None,
            "a candidate must not be found by accident at the filesystem root"
        );
    }

    #[test]
    fn nothing_matching_leaves_the_request_alone() {
        let root = spa_root();
        assert_eq!(
            try_files_target(&["{path}"], root.path().to_str(), "/missing"),
            None
        );
    }

    /// 📏 The trailing slash in the *configured pattern* is what selects a
    /// directory, so `{path}/` matches a directory whether or not the request
    /// carried a slash of its own.
    #[test]
    fn a_slashed_candidate_matches_only_a_directory() {
        let root = spa_root();
        for request in ["/assets", "/assets/"] {
            assert_eq!(
                try_files_target(&["{path}/"], root.path().to_str(), request),
                Some("/assets/".to_string()),
                "`{{path}}/` must match the directory for {request}"
            );
        }
        assert_eq!(
            try_files_target(&["{path}/"], root.path().to_str(), "/index.html"),
            None,
            "`{{path}}/` must not match a regular file"
        );
    }

    /// 🤡 The case a runtime comparison against Caddy v2.11.4 caught on
    /// 2026-08-07, and reading the file matcher's source then explained: an
    /// unslashed candidate must *not* match a directory. Treating "exists" as
    /// "either kind" made `try_files {path} /index.html` rewrite a request for
    /// `/assets/` to the directory itself, which the file server then answered
    /// 404 for — where the format serves the application shell.
    #[test]
    fn an_unslashed_candidate_does_not_match_a_directory() {
        let root = spa_root();
        assert_eq!(
            try_files_target(&["{path}", "/index.html"], root.path().to_str(), "/assets/"),
            Some("/index.html".to_string()),
            "a directory must fall through to the shell, not be rewritten to"
        );
    }

    /// 🍃 On HTTP/3 the caller's path still carries its query, and a query is
    /// not part of any filename.
    #[test]
    fn the_query_string_is_not_part_of_the_lookup() {
        let root = spa_root();
        assert_eq!(
            try_files_target(&["{path}"], root.path().to_str(), "/assets/app.js?v=2"),
            Some("/assets/app.js".to_string())
        );
    }

    // MARK: - Placeholders and globs

    /// 🧭 A candidate may name any placeholder the request can answer, not
    /// only `{path}`. `try_files {uri}` was refused outright until 2026-08-11.
    #[test]
    fn file_matcher_expands_more_than_the_path_placeholder() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("example.com")).unwrap();
        std::fs::write(dir.path().join("example.com/home.html"), "host page").unwrap();
        std::fs::write(dir.path().join("GET.html"), "method page").unwrap();
        let root = dir.path().to_str();

        assert_eq!(
            try_files_target(&["/{host}{path}"], root, "/home.html"),
            Some("/example.com/home.html".to_string()),
            "{{host}} must resolve to the request host"
        );
        assert_eq!(
            try_files_target(&["/{method}.html"], root, "/whatever"),
            Some("/GET.html".to_string())
        );
        assert_eq!(
            try_files_target(&["{uri}"], root, "/GET.html?v=1"),
            None,
            "{{uri}} keeps the query, so it names no file here"
        );
    }

    /// 🔍 A configured glob expands against the filesystem; the first result
    /// that satisfies the file-or-directory demand is the match.
    #[test]
    fn file_matcher_expands_a_configured_glob() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("build")).unwrap();
        std::fs::write(dir.path().join("build/app.9f3c2a.js"), "bundle").unwrap();
        let root = dir.path().to_str();

        assert_eq!(
            try_files_target(&["/build/app.*.js"], root, "/anything"),
            Some("/build/app.9f3c2a.js".to_string())
        );
        assert_eq!(
            try_files_target(&["/build/style.*.css"], root, "/anything"),
            None,
            "a glob that matches nothing must fall through, not match itself"
        );
    }

    /// 🔗 A globbed match is a name read from disk, and its relative form goes
    /// back into the request line, so it is percent-encoded rather than pasted
    /// in raw. A raw space there is a malformed request, not a path.
    #[test]
    fn a_globbed_match_is_published_as_an_encoded_uri() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("build")).unwrap();
        std::fs::write(dir.path().join("build/app 1.js"), "bundle").unwrap();

        assert_eq!(
            try_files_target(&["/build/app*.js"], dir.path().to_str(), "/anything"),
            Some("/build/app%201.js".to_string())
        );
    }

    /// 📁 A globbed name that is not valid UTF-8 is still the file on disk.
    ///
    /// The glob results used to go through `to_string_lossy`, so this name
    /// became `caf\u{FFFD}.js`: the existence probe asked about a file that
    /// does not exist and the candidate never matched. 🐧 Linux only, because
    /// APFS refuses to create a name that is not valid UTF-8.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_globbed_non_utf8_name_matches_the_file_on_disk() {
        use std::os::unix::ffi::OsStrExt as _;
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("build")).unwrap();
        let name = std::ffi::OsStr::from_bytes(b"caf\xe9.js");
        std::fs::write(dir.path().join("build").join(name), "bundle").unwrap();

        assert_eq!(
            try_files_target(&["/build/caf*.js"], dir.path().to_str(), "/anything"),
            Some("/build/caf%E9.js".to_string())
        );
    }

    /// 📁 An escape that decodes to bytes that are not valid UTF-8 still yields
    /// a candidate, rather than no candidate at all.
    ///
    /// `first_exist_fallback` claims its last candidate without touching the
    /// filesystem, so this runs anywhere. Until the matcher worked in paths the
    /// join gave up on `0xE9` and there was nothing to claim, which is also why
    /// `try_files {path}` could never match such a file on disk.
    #[cfg(unix)]
    #[test]
    fn a_non_utf8_escape_still_yields_a_candidate() {
        let headers = HeaderMap::new();
        let mut vars = BTreeMap::new();
        let mut request = MatcherRequest {
            path: "/caf%E9.php",
            method: "GET",
            headers: &headers,
            host: "example.com",
            addresses: peer("10.0.0.1"),
            protocol: "http",
            vars: Some(&mut vars),
        };
        let candidates = ["{path}".to_string()];
        assert_eq!(
            evaluate_file_matcher(
                &mut request,
                &candidates,
                Some("/nonexistent-root"),
                Some("first_exist_fallback"),
                &[],
            ),
            MatcherVerdict::Match
        );
        assert_eq!(
            vars.get("http.matchers.file.relative").map(String::as_str),
            Some("/caf%E9.php"),
            "the rewrite target keeps the request's own encoded spelling"
        );
    }

    /// 📁 `try_files {path}` matches a file whose name is not valid UTF-8, and
    /// publishes the request's own encoded spelling for the rewrite.
    /// 🐧 Linux only, because APFS refuses to create such a name.
    #[cfg(target_os = "linux")]
    #[test]
    fn try_files_matches_a_non_utf8_name() {
        use std::os::unix::ffi::OsStrExt as _;
        let root = spa_root();
        let name = std::ffi::OsStr::from_bytes(b"caf\xe9.txt");
        std::fs::write(root.path().join(name), "latin-1").unwrap();

        assert_eq!(
            try_files_target(
                &["{path}", "/index.html"],
                root.path().to_str(),
                "/caf%E9.txt"
            ),
            Some("/caf%E9.txt".to_string())
        );
    }

    /// 🛡️ A request must never be able to introduce a glob metacharacter.
    ///
    /// Without escaping, `try_files /build/{path}` under a request for `/*`
    /// would list the directory and rewrite to whatever came first — the
    /// client choosing the file. The escaped form looks for a file whose name
    /// really does contain an asterisk, which is what was asked for.
    #[test]
    fn a_request_cannot_inject_a_glob_metacharacter() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("build")).unwrap();
        std::fs::write(dir.path().join("build/secret.txt"), "secret").unwrap();
        let root = dir.path().to_str();

        assert_eq!(
            try_files_target(&["/build{path}"], root, "/*"),
            None,
            "a wildcard from the request must not expand"
        );
        assert_eq!(
            try_files_target(&["/build{path}"], root, "/secret.txt"),
            Some("/build/secret.txt".to_string()),
            "the ordinary case still resolves"
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
            addresses: peer("10.0.0.1"),
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
            addresses: peer("10.0.0.1"),
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
            addresses: peer("10.0.0.1"),
            protocol: "http",
            vars: Some(&mut vars),
        };
        assert_eq!(
            evaluate_verdict(&compiled, &mut request),
            MatcherVerdict::NoMatch
        );
    }
}
