//! Request handlers for Pingclair
//!
//! Provides handlers for respond, redirect, and headers operations.

use crate::config::HandlerConfig;
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

/// Execute a handler configuration
pub fn execute_handler(config: &HandlerConfig) -> HandlerResult {
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
                match execute_handler(handler) {
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
            execute_handler(&HandlerConfig::Pipeline(handlers.clone()))
        }

        HandlerConfig::Plugin { name, args: _ } => {
            Err(HandlerError::Config(format!("Plugin {} is not yet implemented", name)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_respond_handler() {
        let config = HandlerConfig::Respond {
            status: 200,
            body: Some("Hello, World!".to_string()),
            headers: HashMap::new(),
        };
        
        let response = execute_handler(&config).unwrap();
        assert_eq!(response.status, StatusCode::OK);
        assert!(response.body.is_some());
    }
    
    #[test]
    fn test_redirect_handler() {
        let config = HandlerConfig::Redirect {
            to: "https://example.com".to_string(),
            code: 301,
        };
        
        let response = execute_handler(&config).unwrap();
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
        
        let response = execute_handler(&config).unwrap();
        assert_eq!(response.headers.get("X-Custom"), Some(&"value".to_string()));
    }
}
