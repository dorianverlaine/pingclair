// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! Admin API Server

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use parking_lot::RwLock;
use serde_json::Value;
use tokio::net::TcpListener;

use pingclair_core::config::PingclairConfig;

use crate::auth::{ApiKeyAuth, AuthDecision, authorize};
use crate::config_tree::{self, Mode, TreeError};

/// Run the admin server
pub async fn run_admin_server(
    addr: SocketAddr,
    proxies: Arc<
        RwLock<std::collections::HashMap<String, pingclair_proxy::server::PingclairProxy>>,
    >,
    document: Arc<RwLock<Value>>,
    api_key: Option<String>,
) -> pingclair_core::Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| pingclair_core::Error::Server(format!("Failed to bind admin API: {e}")))?;

    let auth = api_key.map(|key| Arc::new(ApiKeyAuth::new(key)));
    if auth.is_none() {
        tracing::warn!(
            "⚠️  Admin API is running WITHOUT authentication: no `api_key` configured. \
             Only loopback clients are allowed; set `admin.api_key` to enable remote access."
        );
    }

    tracing::info!("🔧 Admin API listening on http://{}", addr);

    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("Admin accept error: {}", e);
                continue;
            }
        };

        let io = TokioIo::new(stream);
        let proxies = proxies.clone();
        let document = document.clone();
        let auth = auth.clone();

        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(
                    io,
                    service_fn(move |req| {
                        handle_request(
                            req,
                            proxies.clone(),
                            document.clone(),
                            auth.clone(),
                            peer_addr,
                        )
                    }),
                )
                .await
            {
                tracing::error!("Error serving connection: {:?}", err);
            }
        });
    }
}

async fn handle_request(
    req: Request<hyper::body::Incoming>,
    proxies: Arc<
        RwLock<std::collections::HashMap<String, pingclair_proxy::server::PingclairProxy>>,
    >,
    document: Arc<RwLock<Value>>,
    auth: Option<Arc<ApiKeyAuth>>,
    peer_addr: SocketAddr,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let response = handle_request_inner(req, proxies, document, auth, peer_addr).await?;
    // 📊 Count every admin request by endpoint and status (MT-3).
    let status = response.status().as_u16().to_string();
    pingclair_proxy::metrics::ADMIN_REQUESTS_TOTAL
        .with_label_values(&[&method, &path, &status])
        .inc();
    Ok(response)
}

async fn handle_request_inner(
    req: Request<hyper::body::Incoming>,
    proxies: Arc<
        RwLock<std::collections::HashMap<String, pingclair_proxy::server::PingclairProxy>>,
    >,
    document: Arc<RwLock<Value>>,
    auth: Option<Arc<ApiKeyAuth>>,
    peer_addr: SocketAddr,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let authorization = req
        .headers()
        .get(hyper::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    match authorize(auth.as_deref(), authorization, peer_addr.ip()) {
        AuthDecision::Allowed => {}
        AuthDecision::Unauthorized => {
            return Ok(response(
                StatusCode::UNAUTHORIZED,
                r#"{"error":"unauthorized"}"#,
            ));
        }
        AuthDecision::Forbidden => {
            return Ok(response(StatusCode::FORBIDDEN, r#"{"error":"forbidden"}"#));
        }
    }

    let request_path = req.uri().path().to_string();
    match (req.method(), request_path.as_str()) {
        (&Method::GET, "/health") => Ok(Response::new(Full::new(Bytes::from(
            r#"{"status":"healthy"}"#,
        )))),
        (&Method::GET, "/metrics") => {
            let buffer = pingclair_proxy::metrics::gather();
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "text/plain; version=0.0.4")
                .body(Full::new(Bytes::from(buffer)))
                .unwrap())
        }
        (&Method::GET, path) if path == "/config" || path == "/config/" => {
            // 🧭 Exports the active document so the output can be POSTed back
            // to /load or traversed with /config/<path>.
            let guard = document.read();
            let json = serde_json::to_string_pretty(&*guard).unwrap_or_default();
            Ok(Response::new(Full::new(Bytes::from(json))))
        }
        (&Method::GET, path) if path.starts_with("/config/") => {
            let segments = normalize_config_segments(config_tree::segments_from_path(
                &path["/config/".len()..],
            ));
            let guard = document.read();
            match config_tree::get(&guard, &segments) {
                Ok(node) => {
                    let json = serde_json::to_string_pretty(node).unwrap_or_default();
                    Ok(Response::new(Full::new(Bytes::from(json))))
                }
                Err(error) => Ok(response(
                    StatusCode::NOT_FOUND,
                    &format!(r#"{{"error":"{}"}}"#, error.message()),
                )),
            }
        }
        (&Method::POST, "/load") => {
            let body_bytes = match read_bounded_body(req).await {
                Ok(bytes) => bytes,
                Err(BodyError::TooLarge) => {
                    return Ok(response(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        &format!(
                            r#"{{"error":"config body exceeds {MAX_CONFIG_BODY_BYTES} bytes"}}"#
                        ),
                    ));
                }
                Err(BodyError::Incomplete) => {
                    return Ok(response(
                        StatusCode::BAD_REQUEST,
                        r#"{"error":"could not read the request body"}"#,
                    ));
                }
            };

            // 🛡️ Full-document replacement: parse AND validate everything
            // before touching a single proxy, so a bad document rolls back by
            // never being applied at all.
            let config: PingclairConfig = match serde_json::from_slice(&body_bytes) {
                Ok(c) => c,
                Err(e) => {
                    return Ok(response(
                        StatusCode::BAD_REQUEST,
                        &format!("Invalid config: {e}"),
                    ));
                }
            };
            if let Err(error) = pingclair_config::compiler::validate_config(&config) {
                return Ok(response(
                    StatusCode::BAD_REQUEST,
                    &format!("Invalid config: {error}"),
                ));
            }

            let proxies_guard = proxies.read();
            // 🧭 Resolve every target first: applying inside the loop left a
            // half-updated state when one listener did not exist.
            let mut targets = Vec::new();
            for server in &config.servers {
                if server.listen.is_empty() {
                    return Ok(response(
                        StatusCode::BAD_REQUEST,
                        r#"{"error":"a server declares no listen address"}"#,
                    ));
                }
                for addr in &server.listen {
                    match proxies_guard.get(addr) {
                        Some(proxy) => targets.push((addr, server, proxy)),
                        None => {
                            return Ok(response(
                                StatusCode::NOT_FOUND,
                                &format!(
                                    r#"{{"error":"no listener is bound to {addr}; nothing was applied"}}"#
                                ),
                            ));
                        }
                    }
                }
            }

            for (addr, server, proxy) in targets {
                proxy.add_server(server.clone());
                tracing::info!(listener = %addr, "📤 Loaded server config");
            }
            // 🧭 The traversal endpoints operate on this document, so a
            // successful full replacement must be reflected there too.
            if let Ok(value) = serde_json::to_value(&config) {
                *document.write() = value;
            }
            Ok(response(StatusCode::OK, "Config loaded"))
        }
        (&Method::POST, "/adapt") => {
            let body_bytes = match read_bounded_body(req).await {
                Ok(bytes) => bytes,
                Err(BodyError::TooLarge) => {
                    return Ok(response(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        &format!(
                            r#"{{"error":"config body exceeds {MAX_CONFIG_BODY_BYTES} bytes"}}"#
                        ),
                    ));
                }
                Err(BodyError::Incomplete) => {
                    return Ok(response(
                        StatusCode::BAD_REQUEST,
                        r#"{"error":"could not read the request body"}"#,
                    ));
                }
            };
            let source = match std::str::from_utf8(&body_bytes) {
                Ok(source) => source,
                Err(_) => {
                    return Ok(response(
                        StatusCode::BAD_REQUEST,
                        r#"{"error":"config body is not UTF-8 text"}"#,
                    ));
                }
            };
            let config = match pingclair_config::compile(source) {
                Ok(config) => config,
                Err(error) => {
                    return Ok(response(
                        StatusCode::BAD_REQUEST,
                        &format!("Adapt error: {error}"),
                    ));
                }
            };
            match serde_json::to_string_pretty(&config) {
                Ok(json) => Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/json")
                    .body(Full::new(Bytes::from(json)))
                    .unwrap()),
                Err(error) => Ok(response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("Serialization error: {error}"),
                )),
            }
        }
        (&Method::POST, "/stop") => {
            tracing::info!("🛑 Admin API received /stop, shutting down");
            // TODO(v0.3): coordinate a graceful shutdown through the process
            // supervisor; a hard exit is correct enough for now.
            std::process::exit(0);
        }
        (&Method::POST, path) if path == "/config" || path == "/config/" => {
            // 📤 POST to the root upserts the whole document, like Caddy.
            let value = match read_json_body(req).await {
                Ok(value) => value,
                Err(error_response) => return Ok(error_response),
            };
            apply_full_document(&document, &proxies, value).await
        }
        (&Method::POST, path) if path.starts_with("/config/") => {
            // 🧭 POST traverses into the document: create or replace at the
            // target, append to arrays, and `...` expands array bodies.
            let value = match read_json_body(req).await {
                Ok(value) => value,
                Err(error_response) => return Ok(error_response),
            };
            apply_config_traversal(&document, &proxies, Method::POST, path, Some(value)).await
        }
        (&Method::PUT, path) if path.starts_with("/config") => {
            let value = match read_json_body(req).await {
                Ok(value) => value,
                Err(error_response) => return Ok(error_response),
            };
            apply_config_traversal(&document, &proxies, Method::PUT, path, Some(value)).await
        }
        (&Method::PATCH, path) if path.starts_with("/config") => {
            let value = match read_json_body(req).await {
                Ok(value) => value,
                Err(error_response) => return Ok(error_response),
            };
            apply_config_traversal(&document, &proxies, Method::PATCH, path, Some(value)).await
        }
        (&Method::DELETE, path) if path.starts_with("/config") => {
            apply_config_traversal(&document, &proxies, Method::DELETE, path, None).await
        }
        _ => Ok(response(StatusCode::NOT_FOUND, "Not Found")),
    }
}

/// 📥 Reads a bounded request body and parses it as a JSON config node.
async fn read_json_body(
    req: Request<hyper::body::Incoming>,
) -> Result<Value, Response<Full<Bytes>>> {
    let body_bytes = match read_bounded_body(req).await {
        Ok(bytes) => bytes,
        Err(BodyError::TooLarge) => {
            return Err(response(
                StatusCode::PAYLOAD_TOO_LARGE,
                &format!(r#"{{"error":"config body exceeds {MAX_CONFIG_BODY_BYTES} bytes"}}"#),
            ));
        }
        Err(BodyError::Incomplete) => {
            return Err(response(
                StatusCode::BAD_REQUEST,
                r#"{"error":"could not read the request body"}"#,
            ));
        }
    };
    serde_json::from_slice(&body_bytes)
        .map_err(|error| response(StatusCode::BAD_REQUEST, &format!("Invalid JSON: {error}")))
}

/// 📤 Applies a full replacement document and commits it as the active tree.
async fn apply_full_document(
    document: &Arc<RwLock<Value>>,
    proxies: &Arc<
        RwLock<std::collections::HashMap<String, pingclair_proxy::server::PingclairProxy>>,
    >,
    value: Value,
) -> Result<Response<Full<Bytes>>, Infallible> {
    match commit_document(&value, proxies) {
        Ok(()) => {
            *document.write() = value;
            Ok(response(StatusCode::OK, "Config loaded"))
        }
        Err((status, message)) => Ok(response(status, &message)),
    }
}

/// 🧭 Applies one Caddy-style traversal mutation on a clone, then commits
/// the clone only when the whole document still parses, validates, and
/// applies. A failed commit leaves the active tree untouched.
/// 🧭 A single numeric segment keeps the legacy `/config/<index>` meaning
/// (`servers[index]`, used by the pre-traversal admin API); deeper paths
/// follow the document tree exactly like Caddy.
fn normalize_config_segments(segments: Vec<String>) -> Vec<String> {
    if segments.len() == 1 && segments[0].parse::<usize>().is_ok() {
        vec!["servers".to_string(), segments[0].clone()]
    } else {
        segments
    }
}

async fn apply_config_traversal(
    document: &Arc<RwLock<Value>>,
    proxies: &Arc<
        RwLock<std::collections::HashMap<String, pingclair_proxy::server::PingclairProxy>>,
    >,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let mut next = document.read().clone();
    let raw = path.strip_prefix("/config").unwrap_or(path);
    let mut segments = normalize_config_segments(config_tree::segments_from_path(raw));
    let expand = segments.last().is_some_and(|segment| segment == "...");
    if expand {
        segments.pop();
    }

    let mutation = if method == Method::DELETE {
        config_tree::remove(&mut next, &segments).map(|_| ())
    } else {
        let Some(body) = body else {
            return Ok(response(
                StatusCode::BAD_REQUEST,
                r#"{"error":"this method requires a JSON body"}"#,
            ));
        };
        if expand {
            config_tree::expand_append(&mut next, &segments, &body)
        } else {
            let mode = match method {
                Method::POST => Mode::Upsert,
                Method::PUT => Mode::Create,
                _ => Mode::Replace,
            };
            config_tree::set(&mut next, &segments, body, mode)
        }
    };

    match mutation {
        Err(TreeError::NotFound) => Ok(response(
            StatusCode::NOT_FOUND,
            &format!(r#"{{"error":"{}"}}"#, TreeError::NotFound.message()),
        )),
        Err(TreeError::Conflict) => Ok(response(
            StatusCode::CONFLICT,
            &format!(r#"{{"error":"{}"}}"#, TreeError::Conflict.message()),
        )),
        Err(TreeError::Invalid(reason)) => Ok(response(
            StatusCode::BAD_REQUEST,
            &format!(r#"{{"error":"{}"}}"#, TreeError::Invalid(reason).message()),
        )),
        Ok(()) => match commit_document(&next, proxies) {
            Ok(()) => {
                *document.write() = next;
                Ok(response(StatusCode::OK, "OK"))
            }
            Err((status, message)) => Ok(response(status, &message)),
        },
    }
}

/// 🛡️ Parses, validates, and applies a document to the bound listeners.
///
/// Every server's listen address must already be bound; a document that
/// introduces a new listener is refused wholesale so nothing is half-applied
/// (creating listeners is the `/load` milestone in the Caddy parity plan).
fn commit_document(
    next: &Value,
    proxies: &Arc<
        RwLock<std::collections::HashMap<String, pingclair_proxy::server::PingclairProxy>>,
    >,
) -> Result<(), (StatusCode, String)> {
    let config: PingclairConfig = serde_json::from_value(next.clone())
        .map_err(|error| (StatusCode::BAD_REQUEST, format!("Invalid config: {error}")))?;
    if let Err(error) = pingclair_config::compiler::validate_config(&config) {
        return Err((StatusCode::BAD_REQUEST, format!("Invalid config: {error}")));
    }

    let proxies_guard = proxies.read();
    let mut targets = Vec::new();
    for server in &config.servers {
        if server.listen.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                r#"{"error":"a server declares no listen address"}"#.to_string(),
            ));
        }
        for addr in &server.listen {
            match proxies_guard.get(addr) {
                Some(proxy) => targets.push((addr, server, proxy)),
                None => {
                    return Err((
                        StatusCode::NOT_FOUND,
                        format!(
                            r#"{{"error":"no listener is bound to {addr}; nothing was applied"}}"#
                        ),
                    ));
                }
            }
        }
    }

    for (addr, server, proxy) in targets {
        proxy.add_server(server.clone());
        tracing::info!(listener = %addr, "♻️ Applied config document");
    }
    Ok(())
}

/// 🧱 Largest configuration document the Admin API will read into memory.
///
/// The real production Pingclairfile compiles to a few kilobytes of JSON, so a
/// megabyte is generous. The number matters less than having one: without a
/// limit, an authenticated client can stream forever and the process grows
/// until the box kills it.
const MAX_CONFIG_BODY_BYTES: usize = 1024 * 1024;

/// 🚰 How much of an oversized upload is drained before giving up on manners.
///
/// Answering 413 the instant the limit is passed leaves the client still
/// writing into a socket nobody is reading, and it sees a connection reset
/// instead of the status code explaining what it did wrong. Reading the rest
/// and throwing it away costs nothing but time — the bytes are dropped, not
/// buffered — so memory stays bounded either way. Past this ceiling the upload
/// is not a mistake worth being polite about.
const MAX_DRAIN_BYTES: usize = 8 * 1024 * 1024;

/// 🚫 Why a request body could not be turned into bytes.
enum BodyError {
    /// The client sent more than [`MAX_CONFIG_BODY_BYTES`].
    TooLarge,
    /// The body ended early or the connection failed mid-transfer.
    Incomplete,
}

/// 📥 Reads a request body with a hard ceiling, and without ever panicking.
///
/// This replaces `req.collect().await.unwrap()`, which was a remote kill
/// switch rather than a shortcut. The release profile sets `panic = "abort"`,
/// so that `unwrap` turned any failed body read into an immediate abort of the
/// whole server — every in-flight request on every listener dropped. It did
/// not need an attacker: an authenticated client whose connection blipped
/// mid-upload was enough, because a truncated body is an `Err`, not an empty
/// `Ok`.
///
/// Reading frame by frame rather than with `Limited` keeps the two failure
/// modes distinguishable, so the caller can answer 413 or 400 instead of
/// collapsing both into one confusing error.
async fn read_bounded_body(req: Request<hyper::body::Incoming>) -> Result<Bytes, BodyError> {
    use http_body_util::BodyExt;

    // 🧾 A body so large it is not worth draining is refused without reading a
    // byte. The header is only a hint — it can lie or be missing — so the loop
    // below is what actually enforces both limits.
    if let Some(declared) = req
        .headers()
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        && declared > MAX_DRAIN_BYTES
    {
        return Err(BodyError::TooLarge);
    }

    let mut body = req.into_body();
    let mut collected = Vec::new();
    let mut seen = 0usize;
    let mut too_large = false;

    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| BodyError::Incomplete)?;
        let Ok(chunk) = frame.into_data() else {
            // 🧭 Trailers carry no payload; skip them rather than fail.
            continue;
        };

        seen += chunk.len();
        if seen > MAX_CONFIG_BODY_BYTES {
            // 🚰 Past the limit the request is already refused, so stop keeping
            // the bytes — but keep reading them, so the client can finish
            // writing and actually receive the 413 rather than a reset.
            too_large = true;
            collected = Vec::new();
            if seen > MAX_DRAIN_BYTES {
                break;
            }
            continue;
        }

        collected.extend_from_slice(&chunk);
    }

    if too_large {
        return Err(BodyError::TooLarge);
    }

    Ok(Bytes::from(collected))
}

fn response(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}
