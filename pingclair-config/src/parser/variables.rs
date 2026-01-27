//! Variable resolution for Pingclairfile
//!
//! Handles resolution of ${...} variables at runtime.

use std::collections::HashMap;

/// Resolved variable types
#[derive(Debug, Clone, PartialEq)]
pub enum ResolvedVariable {
    /// String value
    String(String),
    
    /// Not found / null
    Null,
}

/// Variable resolver
#[derive(Debug, Default)]
pub struct VariableResolver {
    /// Request context
    pub request: RequestContext,
    
    /// Custom variables
    pub custom: HashMap<String, String>,
}

/// Request context for variable resolution
#[derive(Debug, Default, Clone)]
pub struct RequestContext {
    /// Request headers
    pub headers: HashMap<String, String>,
    
    /// Request host
    pub host: String,
    
    /// Request path
    pub path: String,
    
    /// Request method
    pub method: String,
    
    /// Query parameters
    pub query: HashMap<String, String>,
    
    /// Remote IP
    pub remote_ip: String,
}

impl VariableResolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create resolver with request context
    pub fn with_request(request: RequestContext) -> Self {
        Self {
            request,
            custom: HashMap::new(),
        }
    }

    /// Resolve a variable path
    /// 
    /// Supports paths like:
    /// - req.header["X-Forwarded-For"]
    /// - req.host
    /// - req.path
    /// - req.method
    /// - req.query["param"]
    /// - req.remote_ip
    pub fn resolve(&self, path: &str) -> ResolvedVariable {
        let parts: Vec<&str> = path.splitn(2, '.').collect();
        
        match parts.as_slice() {
            ["req", rest] => self.resolve_request(rest),
            ["custom", name] => {
                self.custom
                    .get(*name)
                    .map(|s| ResolvedVariable::String(s.clone()))
                    .unwrap_or(ResolvedVariable::Null)
            }
            [name] => {
                self.custom
                    .get(*name)
                    .map(|s| ResolvedVariable::String(s.clone()))
                    .unwrap_or(ResolvedVariable::Null)
            }
            _ => ResolvedVariable::Null,
        }
    }

    fn resolve_request(&self, path: &str) -> ResolvedVariable {
        // Parse header["X-Foo"] or query["param"] syntax
        if let Some(idx) = path.find('[') {
            let prefix = &path[..idx];
            let key_part = &path[idx+1..];
            
            if let Some(end_idx) = key_part.find(']') {
                let key = key_part[..end_idx].trim_matches('"');
                
                match prefix {
                    "header" => {
                        return self.request.headers
                            .get(key)
                            .map(|s| ResolvedVariable::String(s.clone()))
                            .unwrap_or(ResolvedVariable::Null);
                    }
                    "query" => {
                        return self.request.query
                            .get(key)
                            .map(|s| ResolvedVariable::String(s.clone()))
                            .unwrap_or(ResolvedVariable::Null);
                    }
                    _ => {}
                }
            }
        }
        
        // Simple properties
        match path {
            "host" => ResolvedVariable::String(self.request.host.clone()),
            "path" => ResolvedVariable::String(self.request.path.clone()),
            "method" => ResolvedVariable::String(self.request.method.clone()),
            "remote_ip" => ResolvedVariable::String(self.request.remote_ip.clone()),
            _ => ResolvedVariable::Null,
        }
    }

    /// Resolve variables in a template string
    /// 
    /// Replaces ${...} patterns with resolved values
    pub fn resolve_template(&self, template: &str) -> String {
        let mut result = String::with_capacity(template.len());
        let mut chars = template.chars().peekable();
        
        while let Some(c) = chars.next() {
            if c == '$' && chars.peek() == Some(&'{') {
                chars.next(); // consume '{'
                
                // Collect variable path
                let mut path = String::new();
                while let Some(&c) = chars.peek() {
                    if c == '}' {
                        chars.next();
                        break;
                    }
                    path.push(chars.next().unwrap());
                }
                
                // Resolve and append
                match self.resolve(&path) {
                    ResolvedVariable::String(s) => result.push_str(&s),
                    ResolvedVariable::Null => {} // Empty for null
                }
            } else {
                result.push(c);
            }
        }
        
        result
    }

    /// Set a custom variable
    pub fn set(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.custom.insert(name.into(), value.into());
    }
}

impl ResolvedVariable {
    /// Get as string, returning empty string for null
    pub fn as_str(&self) -> &str {
        match self {
            ResolvedVariable::String(s) => s,
            ResolvedVariable::Null => "",
        }
    }

    /// Check if null
    pub fn is_null(&self) -> bool {
        matches!(self, ResolvedVariable::Null)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_header() {
        let mut resolver = VariableResolver::new();
        resolver.request.headers.insert("CF-Connecting-IP".to_string(), "1.2.3.4".to_string());
        
        let result = resolver.resolve(r#"req.header["CF-Connecting-IP"]"#);
        assert_eq!(result, ResolvedVariable::String("1.2.3.4".to_string()));
    }

    #[test]
    fn test_resolve_host() {
        let mut resolver = VariableResolver::new();
        resolver.request.host = "example.com".to_string();
        
        let result = resolver.resolve("req.host");
        assert_eq!(result, ResolvedVariable::String("example.com".to_string()));
    }

    #[test]
    fn test_resolve_query() {
        let mut resolver = VariableResolver::new();
        resolver.request.query.insert("page".to_string(), "42".to_string());
        
        let result = resolver.resolve(r#"req.query["page"]"#);
        assert_eq!(result, ResolvedVariable::String("42".to_string()));
    }

    #[test]
    fn test_resolve_template() {
        let mut resolver = VariableResolver::new();
        resolver.request.headers.insert("X-Real-IP".to_string(), "10.0.0.1".to_string());
        resolver.request.host = "api.example.com".to_string();
        
        let template = r#"Forwarded for ${req.header["X-Real-IP"]} to ${req.host}"#;
        let result = resolver.resolve_template(template);
        
        assert_eq!(result, "Forwarded for 10.0.0.1 to api.example.com");
    }

    #[test]
    fn test_custom_variable() {
        let mut resolver = VariableResolver::new();
        resolver.set("upstream", "backend-1");
        
        let result = resolver.resolve("custom.upstream");
        assert_eq!(result, ResolvedVariable::String("backend-1".to_string()));
    }

    #[test]
    fn test_null_resolution() {
        let resolver = VariableResolver::new();
        
        let result = resolver.resolve("req.header[\"NonExistent\"]");
        assert!(result.is_null());
    }
}
