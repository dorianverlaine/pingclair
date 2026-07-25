//! Request handlers for Pingclair
//!
//! Provides handlers for respond, redirect, and headers operations.

use crate::config::{BasicAuthCredential, HandlerConfig};
use base64::Engine as _;
use http::StatusCode;
use bytes::Bytes;
use std::collections::HashMap;

/// Handler result
pub type HandlerResult = Result<HandlerResponse, HandlerError>;

/// Response from a handler
#[derive(Debug)]
pub struct HandlerResponse {
    pub status: StatusCode,
    pub headers: HashMap<String, String>,
    pub body: Option<Bytes>,
}

/// Handler error
#[derive(Debug, thiserror::Error)]
pub enum HandlerError {
    #[error("Upstream error: {0}")]
    Upstream(String),
    
    #[error("Configuration error: {0}")]
    Config(String),
    
    #[error("Internal error: {0}")]
    Internal(String),
}

impl HandlerResponse {
    /// Create a simple response with status code
    pub fn status(code: u16) -> Self {
        Self {
            status: StatusCode::from_u16(code).unwrap_or(StatusCode::OK),
            headers: HashMap::new(),
            body: None,
        }
    }
    
    /// Create a response with body
    pub fn with_body(code: u16, body: impl Into<Bytes>) -> Self {
        Self {
            status: StatusCode::from_u16(code).unwrap_or(StatusCode::OK),
            headers: HashMap::new(),
            body: Some(body.into()),
        }
    }
    
    /// Add a header
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name.into(), value.into());
        self
    }
    
    /// Create redirect response
    pub fn redirect(to: &str, code: u16) -> Self {
        let status = StatusCode::from_u16(code).unwrap_or(StatusCode::FOUND);
        let mut headers = HashMap::new();
        headers.insert("Location".to_string(), to.to_string());
        
        Self {
            status,
            headers,
            body: None,
        }
    }
    
    /// Create not found response
    pub fn not_found() -> Self {
        Self::with_body(404, "Not Found")
    }
    
    /// Create internal server error response
    pub fn internal_error() -> Self {
        Self::with_body(500, "Internal Server Error")
    }
}

/// Execute a handler configuration against an incoming request.
///
/// `headers` are the request headers; handlers that need request context
/// (currently only `BasicAuth`) read them from here.
pub fn execute_handler(config: &HandlerConfig, headers: &http::HeaderMap) -> HandlerResult {
    match config {
        HandlerConfig::Respond { status, body, headers } => {
            let mut response = if let Some(body_content) = body {
                // Clone the body content to get owned data
                HandlerResponse::with_body(*status, Bytes::from(body_content.clone()))
            } else {
                HandlerResponse::status(*status)
            };
            
            response.headers = headers.clone();
            Ok(response)
        }
        
        HandlerConfig::Redirect { to, code } => {
            Ok(HandlerResponse::redirect(to, *code))
        }
        
        HandlerConfig::Headers { set, add, remove: _ } => {
            // Headers handler modifies existing response
            // Return a passthrough response
            let mut response = HandlerResponse::status(200);
            for (k, v) in set {
                response.headers.insert(k.clone(), v.clone());
            }
            for (k, v) in add {
                response.headers.insert(k.clone(), v.clone());
            }
            Ok(response)
        }
        
        HandlerConfig::FileServer { root, index, browse: _, compress: _ } => {
            // File server would need async file reading
            // Return placeholder for now
            Err(HandlerError::Config(format!(
                "FileServer({:?}, {:?}) not yet implemented", 
                root, index
            )))
        }
        
        HandlerConfig::ReverseProxy(_) => {
            // Reverse proxy is handled separately by Pingora
            Err(HandlerError::Config("ReverseProxy should use Pingora".to_string()))
        }
        
        HandlerConfig::Pipeline(handlers) => {
            // Execute handlers in order, combining results
            let mut final_response = HandlerResponse::status(200);
            
            for handler in handlers {
                match execute_handler(handler, headers) {
                    Ok(response) => {
                        final_response.status = response.status;
                        final_response.headers.extend(response.headers);
                        if response.body.is_some() {
                            final_response.body = response.body;
                        }
                    }
                    Err(e) => return Err(e),
                }
            }
            
            Ok(final_response)
        }

        HandlerConfig::Handle(handlers) => {
            // Treat Handle as a pipeline for now
            execute_handler(&HandlerConfig::Pipeline(handlers.clone()), headers)
        }

        HandlerConfig::Rewrite { strip_prefix, strip_suffix, replace, regex: _, regex_replace: _ } => {
            // Rewrite handler modifies the request path
            // This is a signal to the proxy layer to modify the URI before forwarding
            // We return a special response that indicates a rewrite is needed
            let mut response = HandlerResponse::status(200);
            
            // Set special headers to communicate rewrite intent to proxy layer
            if let Some(prefix) = strip_prefix {
                response.headers.insert("X-Pingclair-Strip-Prefix".to_string(), prefix.clone());
            }
            if let Some(suffix) = strip_suffix {
                response.headers.insert("X-Pingclair-Strip-Suffix".to_string(), suffix.clone());
            }
            if let Some(replacement) = replace {
                response.headers.insert("X-Pingclair-Replace-Path".to_string(), replacement.clone());
            }
            // Note: regex support would need the regex crate here
            // For now, regex rewrites are handled separately
            
            response.headers.insert("X-Pingclair-Rewrite".to_string(), "true".to_string());
            Ok(response)
        }

        HandlerConfig::BasicAuth { realm, credentials } => {
            // Verify the request's Authorization header against the configured
            // credentials. On success the request passes through with a 200
            // (no body), composing like the Headers handler; on any failure
            // the client gets a 401 challenge.
            if verify_basic_auth(headers, credentials) {
                Ok(HandlerResponse::status(200))
            } else {
                let mut response = HandlerResponse::with_body(401, "Unauthorized");
                response.headers.insert(
                    "WWW-Authenticate".to_string(),
                    basic_auth_challenge(realm)
                );
                Ok(response)
            }
        }

        HandlerConfig::RateLimit { requests, window_secs, by_ip: _, burst } => {
            // RateLimit handler - this signals rate limiting is configured for this route
            // The actual rate limit checking is done at the proxy layer
            // Here we return headers that indicate the rate limit config
            let mut response = HandlerResponse::status(429);
            response.headers.insert(
                "X-RateLimit-Limit".to_string(),
                requests.to_string()
            );
            response.headers.insert(
                "X-RateLimit-Window".to_string(),
                window_secs.to_string()
            );
            response.headers.insert(
                "X-RateLimit-Burst".to_string(),
                burst.to_string()
            );
            response.headers.insert(
                "Retry-After".to_string(),
                window_secs.to_string()
            );
            response.body = Some(bytes::Bytes::from("Too Many Requests"));
            Ok(response)
        }

        HandlerConfig::HandleErrors { errors: _ } => {
            // HandleErrors is a configuration directive that attaches error handlers to the route.
            // When executed as part of the normal request flow, it doesn't do anything itself.
            // The proxy/router should inspect this config to set up error trapping.
            Ok(HandlerResponse::status(200))
        }

        HandlerConfig::HandlePath { prefix, handlers } => {
            // execute inner handlers
            let mut response = execute_handler(&HandlerConfig::Pipeline(handlers.clone()), headers)?;
            
            // Add instruction to strip prefix
            // Note: In a real execution engine, we would modify the path before inner execution,
            // but here we are generating instructions/response. 
            // The X-Pingclair-Strip-Prefix hopefully tells the proxy to modify the request *as it processes it*.
            // LIMITATION: This assumes the proxy sees this header and acts on it for *subsequent* or *current* processing.
            response.headers.insert(
                "X-Pingclair-Strip-Prefix".to_string(),
                prefix.clone()
            );
            Ok(response)
        }

        HandlerConfig::Cors { .. } => {
            // CORS is handled at the proxy layer where we have access to the request.
            // Returning a passthrough here.
            Ok(HandlerResponse::status(200))
        }

        HandlerConfig::TryFiles { .. } => {
            // TryFiles requires filesystem access, handled at the proxy layer.
            Ok(HandlerResponse::status(200))
        }

        HandlerConfig::Plugin { name, args: _ } => {
            Err(HandlerError::Config(format!("Plugin {} is not yet implemented", name)))
        }
    }
}

/// Verify a request's HTTP Basic `Authorization` header against configured
/// credentials.
///
/// The header must carry the `Basic` scheme and a base64-encoded
/// `user:password` pair. Every configured credential is checked without an
/// early exit so that a rejected attempt does not reveal whether the
/// username exists. Credentials marked `hashed` are skipped: bcrypt
/// verification is not available in this crate, and silently comparing a
/// hash against a plaintext password would be a false match surface.
///
/// This is shared by the core handler stack and the proxy dispatch paths
/// (H1/H2 and HTTP/3) so all of them enforce identical semantics.
pub fn verify_basic_auth(headers: &http::HeaderMap, credentials: &[BasicAuthCredential]) -> bool {
    let Some(value) = headers
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };

    // Split off the scheme; it is case-insensitive per RFC 9110.
    let mut parts = value.splitn(2, char::is_whitespace);
    match parts.next() {
        Some(scheme) if scheme.eq_ignore_ascii_case("basic") => {}
        _ => return false,
    }
    let Some(encoded) = parts.next() else {
        return false;
    };

    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded.trim()) else {
        return false;
    };
    let Ok(pair) = String::from_utf8(decoded) else {
        return false;
    };
    // The username cannot contain ':', but the password may.
    let Some((user, password)) = pair.split_once(':') else {
        return false;
    };

    let mut matched = false;
    for credential in credentials {
        if credential.hashed {
            continue;
        }
        let user_ok = constant_time_eq(user.as_bytes(), credential.username.as_bytes());
        let password_ok = constant_time_eq(password.as_bytes(), credential.password.as_bytes());
        if user_ok && password_ok {
            matched = true;
        }
    }
    matched
}

/// Build the `WWW-Authenticate` challenge value for a 401 response.
pub fn basic_auth_challenge(realm: &str) -> String {
    format!("Basic realm=\"{}\"", realm)
}

/// Compare two byte strings without an early exit on the first difference,
/// so the comparison time does not depend on where the bytes diverge.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as BASE64;
    
    fn empty_headers() -> http::HeaderMap {
        http::HeaderMap::new()
    }
    
    #[test]
    fn test_respond_handler() {
        let config = HandlerConfig::Respond {
            status: 200,
            body: Some("Hello, World!".to_string()),
            headers: HashMap::new(),
        };
        
        let response = execute_handler(&config, &empty_headers()).unwrap();
        assert_eq!(response.status, StatusCode::OK);
        assert!(response.body.is_some());
    }
    
    #[test]
    fn test_redirect_handler() {
        let config = HandlerConfig::Redirect {
            to: "https://example.com".to_string(),
            code: 301,
        };
        
        let response = execute_handler(&config, &empty_headers()).unwrap();
        assert_eq!(response.status, StatusCode::MOVED_PERMANENTLY);
        assert_eq!(response.headers.get("Location"), Some(&"https://example.com".to_string()));
    }
    
    #[test]
    fn test_headers_handler() {
        let mut headers = HashMap::new();
        headers.insert("X-Custom".to_string(), "value".to_string());
        
        let config = HandlerConfig::Headers {
            set: headers,
            add: HashMap::new(),
            remove: Vec::new(),
        };
        
        let response = execute_handler(&config, &empty_headers()).unwrap();
        assert_eq!(response.headers.get("X-Custom"), Some(&"value".to_string()));
    }
    
    fn basic_auth_config() -> HandlerConfig {
        HandlerConfig::BasicAuth {
            realm: "Restricted".to_string(),
            credentials: vec![
                BasicAuthCredential {
                    username: "alice".to_string(),
                    password: "s3cret".to_string(),
                    hashed: false,
                },
                BasicAuthCredential {
                    username: "bob".to_string(),
                    password: "hunter2".to_string(),
                    hashed: false,
                },
            ],
        }
    }
    
    fn headers_with_basic_auth(user: &str, password: &str) -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        let encoded = BASE64.encode(format!("{}:{}", user, password));
        headers.insert(
            http::header::AUTHORIZATION,
            format!("Basic {}", encoded).parse().unwrap(),
        );
        headers
    }
    
    #[test]
    fn test_basic_auth_correct_credentials_pass() {
        let config = basic_auth_config();
        let headers = headers_with_basic_auth("alice", "s3cret");
        
        let response = execute_handler(&config, &headers).unwrap();
        assert_eq!(response.status, StatusCode::OK);
        assert!(response.body.is_none());
    }
    
    #[test]
    fn test_basic_auth_wrong_password_rejected() {
        let config = basic_auth_config();
        let headers = headers_with_basic_auth("alice", "wrong");
        
        let response = execute_handler(&config, &headers).unwrap();
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    }
    
    #[test]
    fn test_basic_auth_unknown_user_rejected() {
        let config = basic_auth_config();
        let headers = headers_with_basic_auth("mallory", "s3cret");
        
        let response = execute_handler(&config, &headers).unwrap();
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    }
    
    #[test]
    fn test_basic_auth_missing_header_challenges() {
        let config = basic_auth_config();
        
        let response = execute_handler(&config, &empty_headers()).unwrap();
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers.get("WWW-Authenticate"),
            Some(&"Basic realm=\"Restricted\"".to_string())
        );
    }
    
    #[test]
    fn test_basic_auth_malformed_base64_rejected() {
        let config = basic_auth_config();
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            "Basic !!!not-base64!!!".parse().unwrap(),
        );
        
        let response = execute_handler(&config, &headers).unwrap();
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    }
    
    fn plain_credentials() -> Vec<BasicAuthCredential> {
        vec![BasicAuthCredential {
            username: "alice".to_string(),
            password: "s3cret".to_string(),
            hashed: false,
        }]
    }
    
    #[test]
    fn test_verify_basic_auth_accepts_valid_credentials() {
        let headers = headers_with_basic_auth("alice", "s3cret");
        assert!(verify_basic_auth(&headers, &plain_credentials()));
    }
    
    #[test]
    fn test_verify_basic_auth_rejects_non_basic_scheme() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            "Bearer some-token".parse().unwrap(),
        );
        assert!(!verify_basic_auth(&headers, &plain_credentials()));
    }
    
    #[test]
    fn test_verify_basic_auth_password_may_contain_colon() {
        let credentials = vec![BasicAuthCredential {
            username: "alice".to_string(),
            password: "pa:ss:word".to_string(),
            hashed: false,
        }];
        let headers = headers_with_basic_auth("alice", "pa:ss:word");
        assert!(verify_basic_auth(&headers, &credentials));
    }
    
    #[test]
    fn test_verify_basic_auth_skips_hashed_credentials() {
        // Bcrypt verification is not available in this crate; a hashed
        // credential must never match a plaintext password.
        let credentials = vec![BasicAuthCredential {
            username: "alice".to_string(),
            password: "s3cret".to_string(),
            hashed: true,
        }];
        let headers = headers_with_basic_auth("alice", "s3cret");
        assert!(!verify_basic_auth(&headers, &credentials));
    }
    
    #[test]
    fn test_basic_auth_challenge_formats_realm() {
        assert_eq!(basic_auth_challenge("Restricted"), "Basic realm=\"Restricted\"");
    }
}
