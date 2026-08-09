// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! Request handlers for Pingclair
//!
//! Provides handlers for respond, redirect, and headers operations.

use crate::config::{BasicAuthAlgorithm, BasicAuthCredential, HandlerConfig, HandlerElement};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use base64::Engine as _;
use bcrypt::HashParts;
use bytes::Bytes;
use http::StatusCode;
use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::{Arc, LazyLock};

/// 🔐 The maximum bcrypt work factor accepted from configuration.
pub const MAX_BCRYPT_COST: u32 = 14;

/// 🚦 The semaphore bounds concurrent password-hash verification to available
/// CPU capacity. Both bcrypt and argon2id are expensive on purpose, and an
/// argon2id verification allocates the hash's declared memory budget, so the
/// two share one gate rather than each getting its own unbounded lane.
static HASH_WORKERS: LazyLock<Arc<tokio::sync::Semaphore>> = LazyLock::new(|| {
    let workers = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
        .min(4);
    Arc::new(tokio::sync::Semaphore::new(workers))
});

/// Handler result
pub type HandlerResult = Result<HandlerResponse, HandlerError>;

/// Response from a handler
#[derive(Debug)]
pub struct HandlerResponse {
    pub status: StatusCode,
    pub headers: BTreeMap<String, String>,
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
            headers: BTreeMap::new(),
            body: None,
        }
    }

    /// Create a response with body
    pub fn with_body(code: u16, body: impl Into<Bytes>) -> Self {
        Self {
            status: StatusCode::from_u16(code).unwrap_or(StatusCode::OK),
            headers: BTreeMap::new(),
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
        let mut headers = BTreeMap::new();
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
        HandlerConfig::Respond {
            status,
            body,
            headers,
        } => {
            let mut response = if let Some(body_content) = body {
                // Clone the body content to get owned data
                HandlerResponse::with_body(*status, Bytes::from(body_content.clone()))
            } else {
                HandlerResponse::status(*status)
            };

            response.headers = headers.clone();
            Ok(response)
        }

        // 🚨 A static error is a response with the raised status; when the
        // operator gave no message, the status's canonical text is the body,
        // matching what Caddy's default error handler writes.
        HandlerConfig::Error { status, message } => {
            let body = message.clone().unwrap_or_else(|| {
                http::StatusCode::from_u16(*status)
                    .ok()
                    .and_then(|code| code.canonical_reason().map(str::to_string))
                    .unwrap_or_default()
            });
            Ok(HandlerResponse::with_body(*status, Bytes::from(body)))
        }

        HandlerConfig::Redirect { to, code } => Ok(HandlerResponse::redirect(to, *code)),

        // 🧭 Templates render in the proxy pipeline where file access and
        // response writing live; the pure core handler has nothing to do.
        HandlerConfig::Templates { .. } => Ok(HandlerResponse::status(200)),

        HandlerConfig::Headers {
            set,
            add,
            remove: _,
        } => {
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

        HandlerConfig::FileServer {
            root,
            index,
            browse: _,
            browse_limit: _,
            compress: _,
        } => {
            // File server would need async file reading
            // Return placeholder for now
            Err(HandlerError::Config(format!(
                "FileServer({root:?}, {index:?}) not yet implemented"
            )))
        }

        HandlerConfig::ReverseProxy(_) => {
            // Reverse proxy is handled separately by Pingora
            Err(HandlerError::Config(
                "ReverseProxy should use Pingora".to_string(),
            ))
        }

        HandlerConfig::Pipeline { handlers } => {
            // Execute handlers in order, combining results
            let mut final_response = HandlerResponse::status(200);

            for element in handlers {
                let response = execute_handler(&element.handler, headers)?;
                final_response.status = response.status;
                final_response.headers.extend(response.headers);
                if response.body.is_some() {
                    final_response.body = response.body;
                }
            }

            Ok(final_response)
        }

        HandlerConfig::Handle { handlers } => {
            // Treat Handle as a pipeline for now
            execute_handler(
                &HandlerConfig::Pipeline {
                    handlers: handlers
                        .iter()
                        .map(|element| HandlerElement::plain(element.handler.clone()))
                        .collect(),
                },
                headers,
            )
        }

        HandlerConfig::Rewrite {
            strip_prefix,
            strip_suffix,
            replace,
            regex: _,
            regex_replace: _,
        } => {
            // Rewrite handler modifies the request path
            // This is a signal to the proxy layer to modify the URI before forwarding
            // We return a special response that indicates a rewrite is needed
            let mut response = HandlerResponse::status(200);

            // Set special headers to communicate rewrite intent to proxy layer
            if let Some(prefix) = strip_prefix {
                response
                    .headers
                    .insert("X-Pingclair-Strip-Prefix".to_string(), prefix.clone());
            }
            if let Some(suffix) = strip_suffix {
                response
                    .headers
                    .insert("X-Pingclair-Strip-Suffix".to_string(), suffix.clone());
            }
            if let Some(replacement) = replace {
                response
                    .headers
                    .insert("X-Pingclair-Replace-Path".to_string(), replacement.clone());
            }
            // Note: regex support would need the regex crate here
            // For now, regex rewrites are handled separately

            response
                .headers
                .insert("X-Pingclair-Rewrite".to_string(), "true".to_string());
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
                response
                    .headers
                    .insert("WWW-Authenticate".to_string(), basic_auth_challenge(realm));
                Ok(response)
            }
        }

        HandlerConfig::RateLimit { .. } => {
            // 🚦 Enforcement and exact counters live in the protocol-neutral proxy layer.
            Ok(HandlerResponse::status(200))
        }

        HandlerConfig::LogSkip => Ok(HandlerResponse::status(200)),

        HandlerConfig::HandleErrors { errors: _ } => {
            // HandleErrors is a configuration directive that attaches error handlers to the route.
            // When executed as part of the normal request flow, it doesn't do anything itself.
            // The proxy/router should inspect this config to set up error trapping.
            Ok(HandlerResponse::status(200))
        }

        HandlerConfig::HandlePath { prefix, handlers } => {
            // execute inner handlers
            let mut response = execute_handler(
                &HandlerConfig::Pipeline {
                    handlers: handlers
                        .iter()
                        .map(|element| HandlerElement::plain(element.handler.clone()))
                        .collect(),
                },
                headers,
            )?;

            // Add instruction to strip prefix
            // Note: In a real execution engine, we would modify the path before inner execution,
            // but here we are generating instructions/response.
            // The X-Pingclair-Strip-Prefix hopefully tells the proxy to modify the request *as it processes it*.
            // LIMITATION: This assumes the proxy sees this header and acts on it for *subsequent* or *current* processing.
            response
                .headers
                .insert("X-Pingclair-Strip-Prefix".to_string(), prefix.clone());
            Ok(response)
        }

        HandlerConfig::Cors { .. } => {
            // CORS is handled at the proxy layer where we have access to the request.
            // Returning a passthrough here.
            Ok(HandlerResponse::status(200))
        }

        HandlerConfig::AccessControl(_) => {
            // Access control is evaluated by the proxy before dispatch, where
            // the peer address and request headers are available.
            Ok(HandlerResponse::status(200))
        }

        HandlerConfig::TryFiles { .. } => {
            // TryFiles requires filesystem access, handled at the proxy layer.
            Ok(HandlerResponse::status(200))
        }

        HandlerConfig::Plugin { name, args: _ } => Err(HandlerError::Config(format!(
            "Plugin {name} is not yet implemented"
        ))),
    }
}

/// 🔐 Verifies an HTTP Basic header against the configured hash credentials.
///
/// This synchronous entry point is retained for the core handler evaluator.
/// Network dispatch paths must use [`verify_basic_auth_async`] so hash work
/// cannot block an asynchronous I/O worker.
pub fn verify_basic_auth(headers: &http::HeaderMap, credentials: &[BasicAuthCredential]) -> bool {
    let Some((user, password)) = parse_basic_auth(headers) else {
        return false;
    };
    verify_basic_auth_pair(&user, &password, credentials)
}

/// ⚙️ Verifies Basic Auth without blocking an asynchronous I/O worker.
pub async fn verify_basic_auth_async(
    headers: &http::HeaderMap,
    credentials: &[BasicAuthCredential],
) -> bool {
    let Some((user, password)) = parse_basic_auth(headers) else {
        return false;
    };

    let has_matching_hash = credentials.iter().any(|credential| {
        constant_time_eq(user.as_bytes(), credential.username.as_bytes())
            && match credential.algorithm {
                BasicAuthAlgorithm::Bcrypt => bcrypt_hash_cost(&credential.password)
                    .is_some_and(|cost| cost <= MAX_BCRYPT_COST),
                BasicAuthAlgorithm::Argon2id => true,
            }
    });
    if !has_matching_hash {
        return verify_basic_auth_pair(&user, &password, credentials);
    }

    let Ok(permit) = Arc::clone(&HASH_WORKERS).acquire_owned().await else {
        return false;
    };
    let credentials = credentials.to_vec();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        verify_basic_auth_pair(&user, &password, credentials.as_slice())
    })
    .await
    .unwrap_or(false)
}

/// 🧮 Returns a bcrypt hash's declared cost when its syntax is valid.
pub fn bcrypt_hash_cost(hash: &str) -> Option<u32> {
    HashParts::from_str(hash).ok().map(|parts| parts.get_cost())
}

/// 🧮 Whether `hash` is a valid argon2id PHC string this server can verify.
///
/// The check is structural on purpose: parsing the parameters is cheap, and
/// deriving a key just to test validity would spend the hash's memory budget
/// at configuration load. Verification itself parses again and runs Argon2.
pub fn argon2id_hash_valid(hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    // 📏 Argon2id version 0x13 (19) is the version every current generator
    // emits, including Caddy's; an older version would fail at verification
    // time, so it is refused here instead.
    parsed.algorithm.as_str() == "argon2id" && parsed.version == Some(19)
}

/// 🔒 Verifies one plaintext password against an argon2id PHC hash.
fn verify_argon2id(password: &str, hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// 🔎 Parses the Basic scheme and its base64-encoded `user:password` payload.
fn parse_basic_auth(headers: &http::HeaderMap) -> Option<(String, String)> {
    let value = headers
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())?;

    // 📜 The authentication scheme is case-insensitive under RFC 9110.
    let mut parts = value.splitn(2, char::is_whitespace);
    match parts.next() {
        Some(scheme) if scheme.eq_ignore_ascii_case("basic") => {}
        _ => return None,
    }
    let encoded = parts.next()?;

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .ok()?;
    let pair = String::from_utf8(decoded).ok()?;
    // 🔑 The username cannot contain a colon, while the password may contain one.
    let (user, password) = pair.split_once(':')?;
    Some((user.to_string(), password.to_string()))
}

/// 🛡️ Checks a parsed credential pair, dispatching on the declared algorithm
/// and rejecting unsafe bcrypt costs.
fn verify_basic_auth_pair(user: &str, password: &str, credentials: &[BasicAuthCredential]) -> bool {
    let mut matched = false;
    for credential in credentials {
        let user_ok = constant_time_eq(user.as_bytes(), credential.username.as_bytes());
        let password_ok = user_ok
            && match credential.algorithm {
                // 🛡️ The cost ceiling is enforced here too, at the last line
                // before a hash is spent, so a configuration that slipped
                // past validation cannot burn minutes per attempt.
                BasicAuthAlgorithm::Bcrypt => {
                    bcrypt_hash_cost(&credential.password)
                        .is_some_and(|cost| cost <= MAX_BCRYPT_COST)
                        && bcrypt::verify(password, &credential.password).unwrap_or(false)
                }
                BasicAuthAlgorithm::Argon2id => verify_argon2id(password, &credential.password),
            };
        if user_ok && password_ok {
            matched = true;
        }
    }
    matched
}

/// Build the `WWW-Authenticate` challenge value for a 401 response.
pub fn basic_auth_challenge(realm: &str) -> String {
    format!("Basic realm=\"{realm}\"")
}

/// ⏱️ Compares equal-length byte strings without content-dependent early exits.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
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
            headers: BTreeMap::new(),
        };

        let response = execute_handler(&config, &empty_headers()).unwrap();
        assert_eq!(response.status, StatusCode::OK);
        assert!(response.body.is_some());
    }

    #[test]
    fn test_error_handler_uses_status_and_message() {
        let config = HandlerConfig::Error {
            status: 403,
            message: Some("Unauthorized".to_string()),
        };
        let response = execute_handler(&config, &empty_headers()).unwrap();
        assert_eq!(response.status, StatusCode::FORBIDDEN);
        assert_eq!(response.body.as_deref(), Some(&b"Unauthorized"[..]));
    }

    #[test]
    fn test_error_handler_defaults_to_canonical_status_text() {
        let config = HandlerConfig::Error {
            status: 500,
            message: None,
        };
        let response = execute_handler(&config, &empty_headers()).unwrap();
        assert_eq!(response.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            response.body.as_deref(),
            Some(&b"Internal Server Error"[..])
        );
    }

    #[test]
    fn test_redirect_handler() {
        let config = HandlerConfig::Redirect {
            to: "https://example.com".to_string(),
            code: 301,
        };

        let response = execute_handler(&config, &empty_headers()).unwrap();
        assert_eq!(response.status, StatusCode::MOVED_PERMANENTLY);
        assert_eq!(
            response.headers.get("Location"),
            Some(&"https://example.com".to_string())
        );
    }

    #[test]
    fn test_headers_handler() {
        let mut headers = BTreeMap::new();
        headers.insert("X-Custom".to_string(), "value".to_string());

        let config = HandlerConfig::Headers {
            set: headers,
            add: BTreeMap::new(),
            remove: Vec::new(),
        };

        let response = execute_handler(&config, &empty_headers()).unwrap();
        assert_eq!(response.headers.get("X-Custom"), Some(&"value".to_string()));
    }

    fn basic_auth_config() -> HandlerConfig {
        let alice = bcrypt::hash("s3cret", 4).unwrap();
        let bob = bcrypt::hash("hunter2", 4).unwrap();
        HandlerConfig::BasicAuth {
            realm: "Restricted".to_string(),
            credentials: vec![
                BasicAuthCredential {
                    username: "alice".to_string(),
                    password: alice,
                    algorithm: BasicAuthAlgorithm::Bcrypt,
                },
                BasicAuthCredential {
                    username: "bob".to_string(),
                    password: bob,
                    algorithm: BasicAuthAlgorithm::Bcrypt,
                },
            ],
        }
    }

    fn headers_with_basic_auth(user: &str, password: &str) -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        let encoded = BASE64.encode(format!("{user}:{password}"));
        headers.insert(
            http::header::AUTHORIZATION,
            format!("Basic {encoded}").parse().unwrap(),
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

    fn bcrypt_credentials() -> Vec<BasicAuthCredential> {
        vec![BasicAuthCredential {
            username: "alice".to_string(),
            password: bcrypt::hash("s3cret", 4).unwrap(),
            algorithm: BasicAuthAlgorithm::Bcrypt,
        }]
    }

    #[test]
    fn test_verify_basic_auth_accepts_valid_credentials() {
        let headers = headers_with_basic_auth("alice", "s3cret");
        assert!(verify_basic_auth(&headers, &bcrypt_credentials()));
    }

    #[test]
    fn test_verify_basic_auth_rejects_non_basic_scheme() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            "Bearer some-token".parse().unwrap(),
        );
        assert!(!verify_basic_auth(&headers, &bcrypt_credentials()));
    }

    #[test]
    fn test_verify_basic_auth_password_may_contain_colon() {
        let credentials = vec![BasicAuthCredential {
            username: "alice".to_string(),
            password: bcrypt::hash("pa:ss:word", 4).unwrap(),
            algorithm: BasicAuthAlgorithm::Bcrypt,
        }];
        let headers = headers_with_basic_auth("alice", "pa:ss:word");
        assert!(verify_basic_auth(&headers, &credentials));
    }

    #[test]
    fn test_verify_basic_auth_accepts_bcrypt_credentials() {
        let hash = bcrypt::hash("s3cret", 4).unwrap();
        let credentials = vec![BasicAuthCredential {
            username: "alice".to_string(),
            password: hash,
            algorithm: BasicAuthAlgorithm::Bcrypt,
        }];
        let headers = headers_with_basic_auth("alice", "s3cret");
        assert!(verify_basic_auth(&headers, &credentials));

        let wrong_headers = headers_with_basic_auth("alice", "wrong");
        assert!(!verify_basic_auth(&wrong_headers, &credentials));
    }

    #[test]
    fn test_verify_basic_auth_rejects_invalid_bcrypt_hash() {
        let credentials = vec![BasicAuthCredential {
            username: "alice".to_string(),
            password: "$2b$04$not-a-valid-hash".to_string(),
            algorithm: BasicAuthAlgorithm::Bcrypt,
        }];
        let headers = headers_with_basic_auth("alice", "s3cret");
        assert!(!verify_basic_auth(&headers, &credentials));
    }

    #[test]
    fn test_verify_basic_auth_rejects_excessive_bcrypt_cost() {
        let hash = bcrypt::hash("s3cret", 4)
            .unwrap()
            .replacen("$2b$04$", "$2b$15$", 1);
        assert_eq!(bcrypt_hash_cost(&hash), Some(15));

        let credentials = vec![BasicAuthCredential {
            username: "alice".to_string(),
            password: hash,
            algorithm: BasicAuthAlgorithm::Bcrypt,
        }];
        let headers = headers_with_basic_auth("alice", "s3cret");
        assert!(!verify_basic_auth(&headers, &credentials));
    }

    #[tokio::test]
    async fn test_verify_basic_auth_async_accepts_bcrypt_credentials() {
        let credentials = vec![BasicAuthCredential {
            username: "alice".to_string(),
            password: bcrypt::hash("s3cret", 4).unwrap(),
            algorithm: BasicAuthAlgorithm::Bcrypt,
        }];
        let headers = headers_with_basic_auth("alice", "s3cret");
        assert!(verify_basic_auth_async(&headers, &credentials).await);
    }

    /// 🔒 The hash is Caddy's own argon2id fixture: `antitiming` with
    /// m=47104, t=1, p=1 (from `modules/caddyhttp/caddyauth/argon2id.go`),
    /// so the verifier is exercised against upstream's exact output.
    const CADDY_ARGON2ID_HASH: &str = "$argon2id$v=19$m=47104,t=1,p=1$P2nzckEdTZ3bxCiBCkRTyA$xQL3Z32eo5jKl7u5tcIsnEKObYiyNZQQf5/4sAau6Pg";

    #[test]
    fn argon2id_hash_valid_accepts_upstream_output() {
        assert!(argon2id_hash_valid(CADDY_ARGON2ID_HASH));
        assert!(!argon2id_hash_valid(
            "$2y$04$BjuNmKvAV.mEi7.yFrazX.S6w6OO7H0BzQfyVVFZBq/qbVXCVNX4W"
        ));
        assert!(!argon2id_hash_valid("$argon2id$v=18$m=47104,t=1,p=1$a$b"));
        assert!(!argon2id_hash_valid("not a hash"));
    }

    #[test]
    fn test_verify_basic_auth_accepts_argon2id_credentials() {
        let credentials = vec![BasicAuthCredential {
            username: "alice".to_string(),
            password: CADDY_ARGON2ID_HASH.to_string(),
            algorithm: BasicAuthAlgorithm::Argon2id,
        }];
        let headers = headers_with_basic_auth("alice", "antitiming");
        assert!(verify_basic_auth(&headers, &credentials));

        let wrong_headers = headers_with_basic_auth("alice", "wrong");
        assert!(!verify_basic_auth(&wrong_headers, &credentials));
    }

    #[test]
    fn test_verify_basic_auth_rejects_invalid_argon2id_hash() {
        let credentials = vec![BasicAuthCredential {
            username: "alice".to_string(),
            password: "$argon2id$v=19$m=47104,t=1,p=1$not-a-hash".to_string(),
            algorithm: BasicAuthAlgorithm::Argon2id,
        }];
        let headers = headers_with_basic_auth("alice", "antitiming");
        assert!(!verify_basic_auth(&headers, &credentials));
    }

    #[tokio::test]
    async fn test_verify_basic_auth_async_accepts_argon2id_credentials() {
        let credentials = vec![BasicAuthCredential {
            username: "alice".to_string(),
            password: CADDY_ARGON2ID_HASH.to_string(),
            algorithm: BasicAuthAlgorithm::Argon2id,
        }];
        let headers = headers_with_basic_auth("alice", "antitiming");
        assert!(verify_basic_auth_async(&headers, &credentials).await);
    }

    #[test]
    fn test_basic_auth_challenge_formats_realm() {
        assert_eq!(
            basic_auth_challenge("Restricted"),
            "Basic realm=\"Restricted\""
        );
    }
}
