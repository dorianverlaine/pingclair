//! High-performance route matcher using radix tree
//!
//! Provides O(log n) path matching with support for wildcards and parameters.

use crate::config::{RouteConfig, Matcher, MatcherCondition};
use matchit::Router as RadixRouter;
use std::collections::HashMap;
use std::sync::Arc;

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
                if let MatcherCondition::Regex(pattern) = condition {
                    if let Ok(re) = regex::Regex::new(pattern) {
                        regexes.insert(pattern.clone(), Arc::new(re));
                    }
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
                path_groups
                    .entry(path)
                    .or_default()
                    .push(compiled);
            }
        }
        
        // Insert path groups into radix router
        for (path, routes) in path_groups {
            // Convert glob patterns to matchit format
            let matchit_path = Self::glob_to_matchit(&path);
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
    
    /// Match request with full context (path, headers, method)
    pub fn match_request(
        &self,
        path: &str,
        method: &str,
        headers: &http::HeaderMap,
        host: &str,
        remote_ip: &str,
        protocol: &str,
    ) -> Option<&CompiledRoute> {
        let candidates = self.match_path(path);
        
        for route in candidates {
            // Check method constraint
            if let Some(methods) = &route.config.methods {
                if !methods.iter().any(|m| m.eq_ignore_ascii_case(method)) {
                    continue;
                }
            }
            
            // Check additional matchers (using pre-compiled version)
            if let Some(compiled) = &route.compiled_matcher {
                if !Self::evaluate_matcher_compiled(compiled, path, method, headers, host, remote_ip, protocol) {
                    continue;
                }
            }
            
            return Some(route);
        }
        
        None
    }
    
    /// Evaluate a pre-compiled matcher against request context
    fn evaluate_matcher_compiled(
        compiled: &CompiledMatcher,
        path: &str,
        method: &str,
        headers: &http::HeaderMap,
        host: &str,
        remote_ip: &str,
        protocol: &str,
    ) -> bool {
        Self::evaluate_matcher_inner(&compiled.matcher, compiled, path, method, headers, host, remote_ip, protocol)
    }
    
    /// Inner matcher evaluation with access to pre-compiled regexes
    fn evaluate_matcher_inner(
        matcher: &Matcher,
        compiled: &CompiledMatcher,
        path: &str,
        method: &str,
        headers: &http::HeaderMap,
        host: &str,
        remote_ip: &str,
        protocol: &str,
    ) -> bool {
        match matcher {
            Matcher::Path { patterns } => {
                patterns.iter().any(|p| Self::path_matches(path, p))
            }
            Matcher::Header { name, condition } => {
                let header_value = headers.get(name)
                    .and_then(|v| v.to_str().ok());
                Self::evaluate_condition(header_value, condition, compiled)
            }
            Matcher::Method { methods } => {
                methods.iter().any(|m| m.eq_ignore_ascii_case(method))
            }
            Matcher::Query { name: _, condition: _ } => {
                // Query matching would need query string parsing
                true
            }
            Matcher::Host(hosts) => {
                hosts.iter().any(|h| h.eq_ignore_ascii_case(host))
            }
            Matcher::RemoteIp(ips) => {
                ips.iter().any(|ip| remote_ip == ip)
            }
            Matcher::Protocol(protocols) => {
                protocols.iter().any(|p| p.eq_ignore_ascii_case(protocol))
            }
            Matcher::And(left, right) => {
                Self::evaluate_matcher_inner(left, compiled, path, method, headers, host, remote_ip, protocol)
                    && Self::evaluate_matcher_inner(right, compiled, path, method, headers, host, remote_ip, protocol)
            }
            Matcher::Or(left, right) => {
                Self::evaluate_matcher_inner(left, compiled, path, method, headers, host, remote_ip, protocol)
                    || Self::evaluate_matcher_inner(right, compiled, path, method, headers, host, remote_ip, protocol)
            }
            Matcher::Not(inner) => {
                !Self::evaluate_matcher_inner(inner, compiled, path, method, headers, host, remote_ip, protocol)
            }
        }
    }
    
    /// Evaluate a condition against a value (using pre-compiled regex)
    fn evaluate_condition(value: Option<&str>, condition: &MatcherCondition, compiled: &CompiledMatcher) -> bool {
        match condition {
            MatcherCondition::Exists => value.is_some(),
            MatcherCondition::Equals(expected) => {
                value.map(|v| v == expected).unwrap_or(false)
            }
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
    
    /// Check if path matches a glob pattern
    fn path_matches(path: &str, pattern: &str) -> bool {
        if pattern.ends_with("/*") {
            let prefix = &pattern[..pattern.len() - 2];
            path.starts_with(prefix)
        } else if pattern.ends_with("*") {
            let prefix = &pattern[..pattern.len() - 1];
            path.starts_with(prefix)
        } else {
            path == pattern
        }
    }
    
    /// Normalize path for consistent matching
    fn normalize_path(path: &str) -> String {
        let path = if path.is_empty() { "/" } else { path };
        path.to_string()
    }
    
    /// Convert glob pattern to matchit format
    fn glob_to_matchit(path: &str) -> String {
        if path.ends_with("/*") {
            format!("{}/{{*rest}}", &path[..path.len() - 2])
        } else if path.ends_with("*") {
            format!("{}{{*rest}}", &path[..path.len() - 1])
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
        let routes = vec![
            make_route("/api/users"),
            make_route("/api/posts"),
        ];
        let router = Router::new(routes);
        
        let matched = router.match_path("/api/users");
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].config.path, "/api/users");
    }
    
    #[test]
    fn test_wildcard_match() {
        let routes = vec![
            make_route("/api/*"),
            make_route("/static/*"),
        ];
        let router = Router::new(routes);
        
        let matched = router.match_path("/api/users/123");
        assert!(!matched.is_empty());
    }
    
    #[test]
    fn test_default_route() {
        let routes = vec![
            make_route("/api/*"),
            make_route("/*"),
        ];
        let router = Router::new(routes);
        
        let matched = router.match_path("/unknown");
        assert!(!matched.is_empty());
    }
}
