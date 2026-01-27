//! High-performance route matcher using radix tree
//!
//! Provides O(log n) path matching with support for wildcards and parameters.

use crate::config::{RouteConfig, Matcher, MatcherCondition};
use matchit::Router as RadixRouter;
use std::collections::HashMap;

/// Route entry with precompiled matchers
#[derive(Debug, Clone)]
pub struct CompiledRoute {
    /// Original route configuration
    pub config: RouteConfig,
    /// Route index for handler lookup
    pub index: usize,
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
            let compiled = CompiledRoute {
                config: config.clone(),
                index,
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
            
            // Check additional matchers
            if let Some(matcher) = &route.config.matcher {
                if !Self::evaluate_matcher(matcher, path, method, headers, host, remote_ip, protocol) {
                    continue;
                }
            }
            
            return Some(route);
        }
        
        None
    }
    
    /// Evaluate a matcher against request context
    fn evaluate_matcher(
        matcher: &Matcher,
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
                Self::evaluate_condition(header_value, condition)
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
                Self::evaluate_matcher(left, path, method, headers, host, remote_ip, protocol)
                    && Self::evaluate_matcher(right, path, method, headers, host, remote_ip, protocol)
            }
            Matcher::Or(left, right) => {
                Self::evaluate_matcher(left, path, method, headers, host, remote_ip, protocol)
                    || Self::evaluate_matcher(right, path, method, headers, host, remote_ip, protocol)
            }
            Matcher::Not(inner) => {
                !Self::evaluate_matcher(inner, path, method, headers, host, remote_ip, protocol)
            }
        }
    }
    
    /// Evaluate a condition against a value
    fn evaluate_condition(value: Option<&str>, condition: &MatcherCondition) -> bool {
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
                if let Ok(re) = regex::Regex::new(pattern) {
                    value.map(|v| re.is_match(v)).unwrap_or(false)
                } else {
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
