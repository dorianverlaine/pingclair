// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! Admin API Server

use std::collections::HashSet;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::Bytes;
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use parking_lot::RwLock;
use serde_json::Value;
use tokio::net::TcpListener;
use tokio::sync::Notify;

use pingclair_core::config::PingclairConfig;

use crate::auth::{ApiKeyAuth, AuthDecision, OriginPolicy, authorize, origin_allowed};
use crate::config_tree::{self, Mode, TreeError};

/// 🧭 Shared state for one admin server connection.
struct AdminState {
    proxies:
        Arc<RwLock<std::collections::HashMap<String, pingclair_proxy::server::PingclairProxy>>>,
    document: Arc<RwLock<Value>>,
    shutdown: Arc<Notify>,
    autosave: Option<PathBuf>,
    listeners: Option<Arc<dyn pingclair_proxy::server::DynamicListeners>>,
    api_changed: Arc<AtomicBool>,
    auth: Option<Arc<ApiKeyAuth>>,
    origins: Arc<OriginPolicy>,
}

/// 🧭 Everything the admin server needs beyond its socket address.
pub struct AdminServerOptions {
    pub proxies:
        Arc<RwLock<std::collections::HashMap<String, pingclair_proxy::server::PingclairProxy>>>,
    pub document: Arc<RwLock<Value>>,
    pub shutdown: Arc<Notify>,
    pub autosave: Option<PathBuf>,
    pub listeners: Option<Arc<dyn pingclair_proxy::server::DynamicListeners>>,
    pub api_changed: Arc<AtomicBool>,
    pub api_key: Option<String>,
    pub origins: Vec<String>,
    pub enforce_origin: bool,
}

/// 🧭 Read-only context threaded through the config mutation helpers.
struct ApplyContext<'a> {
    document: &'a Arc<RwLock<Value>>,
    proxies:
        &'a Arc<RwLock<std::collections::HashMap<String, pingclair_proxy::server::PingclairProxy>>>,
    autosave: Option<&'a Path>,
    listeners: Option<&'a dyn pingclair_proxy::server::DynamicListeners>,
    changed: &'a AtomicBool,
}

/// Run the admin server
pub async fn run_admin_server(
    addr: SocketAddr,
    options: AdminServerOptions,
) -> pingclair_core::Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| pingclair_core::Error::Server(format!("Failed to bind admin API: {e}")))?;

    let origins = Arc::new(OriginPolicy {
        allowed: options.origins,
        enforce: options.enforce_origin,
        listen: addr.to_string(),
    });
    let auth = options.api_key.map(|key| Arc::new(ApiKeyAuth::new(key)));
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
        let state = Arc::new(AdminState {
            proxies: options.proxies.clone(),
            document: options.document.clone(),
            shutdown: options.shutdown.clone(),
            autosave: options.autosave.clone(),
            listeners: options.listeners.clone(),
            api_changed: options.api_changed.clone(),
            auth: auth.clone(),
            origins: origins.clone(),
        });

        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(
                    io,
                    service_fn(move |req| handle_request(req, state.clone(), peer_addr)),
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
    state: Arc<AdminState>,
    peer_addr: SocketAddr,
) -> Result<Response<Full<Bytes>>, Infallible> {
    // 🍃 Avoid allocating metric labels when collection is disabled.
    let metric_labels = pingclair_proxy::metrics::enabled()
        .then(|| (req.method().to_string(), req.uri().path().to_string()));
    let response = handle_request_inner(req, &state, peer_addr).await?;
    if let Some((method, path)) = metric_labels {
        // 📊 Count every admin request by endpoint and status (MT-3).
        let status = response.status().as_u16().to_string();
        pingclair_proxy::metrics::ADMIN_REQUESTS_TOTAL
            .with_label_values(&[&method, &path, &status])
            .inc();
    }
    Ok(response)
}

async fn handle_request_inner(
    req: Request<hyper::body::Incoming>,
    state: &AdminState,
    peer_addr: SocketAddr,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let proxies = &state.proxies;
    let document = &state.document;
    let shutdown = &state.shutdown;
    let autosave = state.autosave.as_deref();
    let listeners = state.listeners.as_deref();
    let changed = state.api_changed.as_ref();
    let auth = state.auth.as_deref();
    let ctx = ApplyContext {
        document,
        proxies,
        autosave,
        listeners,
        changed,
    };
    let authorization = req
        .headers()
        .get(hyper::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    // 🛡️ The origin check runs before authentication, because it answers a
    // different question: not "who is this" but "should a browser be able to
    // make this request at all". A valid API key embedded in a page on another
    // site is still a cross-site request.
    let origin = req
        .headers()
        .get(hyper::header::ORIGIN)
        .and_then(|v| v.to_str().ok());
    if !origin_allowed(&state.origins, origin, peer_addr.ip()) {
        return Ok(response(
            StatusCode::FORBIDDEN,
            r#"{"error":"origin not allowed"}"#,
        ));
    }

    match authorize(auth, authorization, peer_addr.ip()) {
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
        // 🩺 Liveness: is this process worth keeping? A `no` means restart.
        // It stays true while draining, because a process finishing the
        // connections it already accepted is doing the right thing and killing
        // it would cut them.
        (&Method::GET, "/live") => {
            let phase = pingclair_proxy::readiness::phase();
            Ok(response(
                StatusCode::OK,
                &format!(r#"{{"status":"live","phase":"{}"}}"#, phase.as_str()),
            ))
        }
        // 🚦 Readiness: should traffic come here *now*? A `no` means route
        // around and retry. 503 rather than 200-with-a-body, because every
        // orchestrator and load balancer already understands the status code
        // and most of them never read the body.
        (&Method::GET, "/ready") => {
            let phase = pingclair_proxy::readiness::phase();
            let status = if phase.is_ready() {
                StatusCode::OK
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            };
            Ok(response(
                status,
                &format!(
                    r#"{{"ready":{},"phase":"{}"}}"#,
                    phase.is_ready(),
                    phase.as_str()
                ),
            ))
        }
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
        // 🗄️ Read-only view of the shared response store. Answers the two
        // questions an operator has when caching misbehaves: how full is it,
        // and against what ceiling.
        (&Method::GET, path) if path == "/cache" || path == "/cache/" => {
            let json = serde_json::to_string_pretty(&pingclair_proxy::server::cache_status())
                .unwrap_or_default();
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from(json)))
                .unwrap())
        }
        // 🧹 Drops one stored response, addressed by the same host and target
        // the request path uses. Deliberately not a "purge everything" button:
        // an operator purges because one page changed, and dumping every other
        // route's warm entries turns that into an origin traffic spike.
        //
        // 🔐 Authentication is the gate above this match, so this endpoint is
        // protected on the same terms as `/load` — an unauthenticated purge is
        // a free cache-busting denial-of-service against the origin.
        (&Method::POST, "/cache/purge") => {
            let body_bytes = match read_bounded_body(req).await {
                Ok(bytes) => bytes,
                Err(BodyError::TooLarge) => {
                    return Ok(response(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        r#"{"error":"request body too large"}"#,
                    ));
                }
                Err(BodyError::Incomplete) => {
                    return Ok(response(
                        StatusCode::BAD_REQUEST,
                        r#"{"error":"could not read request body"}"#,
                    ));
                }
            };
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct PurgeRequest {
                host: String,
                path: String,
            }
            let Ok(purge) = serde_json::from_slice::<PurgeRequest>(&body_bytes) else {
                return Ok(response(
                    StatusCode::BAD_REQUEST,
                    r#"{"error":"expected {\"host\":\"...\",\"path\":\"...\"}"}"#,
                ));
            };
            // 📢 The boolean is reported rather than swallowed. "Purged
            // nothing" and "purged something" look identical from the outside,
            // and an operator who cannot tell them apart cannot tell a working
            // purge from a key that no longer matches.
            let purged =
                pingclair_proxy::server::purge_cached_response(&purge.host, &purge.path).await;
            Ok(response(
                StatusCode::OK,
                &format!(r#"{{"purged":{purged}}}"#),
            ))
        }
        (&Method::POST, "/load") => {
            // 🧭 Like Caddy, the endpoint accepts a Caddyfile when the client
            // says so with Content-Type; capture it before the body consumes
            // the request.
            let content_type = req
                .headers()
                .get(hyper::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("")
                .to_ascii_lowercase();
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
            let config: PingclairConfig = if content_type.contains("caddyfile") {
                let source = match std::str::from_utf8(&body_bytes) {
                    Ok(source) => source,
                    Err(_) => {
                        return Ok(response(
                            StatusCode::BAD_REQUEST,
                            r#"{"error":"config body is not UTF-8 text"}"#,
                        ));
                    }
                };
                match pingclair_config::compile(source) {
                    Ok(config) => config,
                    Err(error) => {
                        return Ok(response(
                            StatusCode::BAD_REQUEST,
                            &format!("Adapt error: {error}"),
                        ));
                    }
                }
            } else {
                match serde_json::from_slice(&body_bytes) {
                    Ok(config) => config,
                    Err(error) => {
                        return Ok(response(
                            StatusCode::BAD_REQUEST,
                            &format!("Invalid config: {error}"),
                        ));
                    }
                }
            };
            if let Err(error) = pingclair_config::compiler::validate_config(&config) {
                return Ok(response(
                    StatusCode::BAD_REQUEST,
                    &format!("Invalid config: {error}"),
                ));
            }

            // 📤 `commit_document` creates listeners named in the document at
            // runtime and applies whole-document replacement semantics, so
            // `/load` behaves like Caddy's endpoint instead of duplicating a
            // narrower apply path.
            let value = serde_json::to_value(&config).unwrap_or_default();
            match commit_document(&value, proxies, listeners) {
                Ok(()) => {
                    changed.store(true, Ordering::SeqCst);
                    *document.write() = value;
                    if let Some(path) = autosave {
                        autosave_document(document, path);
                    }
                    Ok(response(StatusCode::OK, "Config loaded"))
                }
                Err((status, message)) => Ok(response(status, &message)),
            }
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
            // 🛑 Answer the request first, then ask the process supervisor to
            // run the same graceful path as SIGTERM. A hard exit here cut the
            // connection before the client ever saw the response.
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                shutdown.notify_one();
            });
            Ok(response(StatusCode::OK, "Stopping"))
        }
        (&Method::POST, path) if path == "/config" || path == "/config/" => {
            // 📤 POST to the root upserts the whole document, like Caddy.
            let value = match read_json_body(req).await {
                Ok(value) => value,
                Err(error_response) => return Ok(error_response),
            };
            apply_full_document(&ctx, value).await
        }
        (&Method::POST, path) if path.starts_with("/config/") => {
            // 🧭 POST traverses into the document: create or replace at the
            // target, append to arrays, and `...` expands array bodies.
            let value = match read_json_body(req).await {
                Ok(value) => value,
                Err(error_response) => return Ok(error_response),
            };
            apply_config_traversal(&ctx, Method::POST, path, Some(value)).await
        }
        (&Method::PUT, path) if path.starts_with("/config") => {
            let value = match read_json_body(req).await {
                Ok(value) => value,
                Err(error_response) => return Ok(error_response),
            };
            apply_config_traversal(&ctx, Method::PUT, path, Some(value)).await
        }
        (&Method::PATCH, path) if path.starts_with("/config") => {
            let value = match read_json_body(req).await {
                Ok(value) => value,
                Err(error_response) => return Ok(error_response),
            };
            apply_config_traversal(&ctx, Method::PATCH, path, Some(value)).await
        }
        (&Method::DELETE, path) if path.starts_with("/config") => {
            apply_config_traversal(&ctx, Method::DELETE, path, None).await
        }
        (&Method::GET, path) if path.starts_with("/id/") => {
            apply_id_request(&ctx, Method::GET, path, None).await
        }
        (&Method::POST, path) if path.starts_with("/id/") => {
            let value = match read_json_body(req).await {
                Ok(value) => value,
                Err(error_response) => return Ok(error_response),
            };
            apply_id_request(&ctx, Method::POST, path, Some(value)).await
        }
        (&Method::PUT, path) if path.starts_with("/id/") => {
            let value = match read_json_body(req).await {
                Ok(value) => value,
                Err(error_response) => return Ok(error_response),
            };
            apply_id_request(&ctx, Method::PUT, path, Some(value)).await
        }
        (&Method::PATCH, path) if path.starts_with("/id/") => {
            let value = match read_json_body(req).await {
                Ok(value) => value,
                Err(error_response) => return Ok(error_response),
            };
            apply_id_request(&ctx, Method::PATCH, path, Some(value)).await
        }
        (&Method::DELETE, path) if path.starts_with("/id/") => {
            apply_id_request(&ctx, Method::DELETE, path, None).await
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
    ctx: &ApplyContext<'_>,
    value: Value,
) -> Result<Response<Full<Bytes>>, Infallible> {
    match commit_document(&value, ctx.proxies, ctx.listeners) {
        Ok(()) => {
            ctx.changed.store(true, Ordering::SeqCst);
            *ctx.document.write() = value;
            if let Some(path) = ctx.autosave {
                autosave_document(ctx.document, path);
            }
            Ok(response(StatusCode::OK, "Config loaded"))
        }
        Err((status, message)) => Ok(response(status, &message)),
    }
}

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

/// 🧭 Applies one Caddy-style traversal mutation on a clone, then commits
/// the clone only when the whole document still parses, validates, and
/// applies. A failed commit leaves the active tree untouched.
async fn apply_config_traversal(
    ctx: &ApplyContext<'_>,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let raw = path.strip_prefix("/config").unwrap_or(path);
    let segments = normalize_config_segments(config_tree::segments_from_path(raw));
    apply_segments(ctx, method, segments, body).await
}

/// 🏷️ Resolves `/id/<name>[/<tail...>]` to the tagged object's path and
/// applies the requested method there, exactly like a traversal on that path.
async fn apply_id_request(
    ctx: &ApplyContext<'_>,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let rest = &path["/id/".len()..];
    let mut parts = rest.splitn(2, '/');
    let Some(name) = parts.next().filter(|part| !part.is_empty()) else {
        return Ok(response(
            StatusCode::BAD_REQUEST,
            r#"{"error":"expected /id/<name>"}"#,
        ));
    };
    let tail = parts.next().unwrap_or("");

    let base = {
        let guard = ctx.document.read();
        match config_tree::find_id_path(&guard, name) {
            Some(segments) => segments,
            None => {
                return Ok(response(
                    StatusCode::NOT_FOUND,
                    &format!(r#"{{"error":"no @id named {name}"}}"#),
                ));
            }
        }
    };
    let mut segments = base;
    segments.extend(config_tree::segments_from_path(tail));
    if method == Method::GET {
        let guard = ctx.document.read();
        return match config_tree::get(&guard, &segments) {
            Ok(node) => {
                let json = serde_json::to_string_pretty(node).unwrap_or_default();
                Ok(Response::new(Full::new(Bytes::from(json))))
            }
            Err(_) => Ok(response(
                StatusCode::NOT_FOUND,
                &format!(r#"{{"error":"no @id named {name}"}}"#),
            )),
        };
    }
    apply_segments(ctx, method, segments, body).await
}

async fn apply_segments(
    ctx: &ApplyContext<'_>,
    method: Method,
    mut segments: Vec<String>,
    body: Option<Value>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let mut next = ctx.document.read().clone();
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
        Ok(()) => match commit_document(&next, ctx.proxies, ctx.listeners) {
            Ok(()) => {
                ctx.changed.store(true, Ordering::SeqCst);
                *ctx.document.write() = next;
                if let Some(path) = ctx.autosave {
                    autosave_document(ctx.document, path);
                }
                Ok(response(StatusCode::OK, "OK"))
            }
            Err((status, message)) => Ok(response(status, &message)),
        },
    }
}

/// 💾 Persists the active document so `run --resume` can restore it after a
/// restart, matching Caddy's autosave behavior for API-driven configs.
fn autosave_document(document: &Arc<RwLock<Value>>, path: &Path) {
    let Ok(json) = serde_json::to_string_pretty(&*document.read()) else {
        return;
    };
    let temporary = path.with_extension("tmp");
    if let Err(error) =
        std::fs::write(&temporary, json).and_then(|_| std::fs::rename(&temporary, path))
    {
        tracing::warn!(%error, "⚠️ Failed to autosave config document");
    }
}

/// 🛡️ Parses, validates, and applies a document to the listeners.
///
/// Listeners the document names that are not bound yet are created at runtime
/// when a dynamic-listener manager is available, matching Caddy's `/load`.
/// After a successful apply, listeners the new document no longer mentions
/// are stopped (dynamic) or emptied (startup sockets Pingora cannot close).
fn commit_document(
    next: &Value,
    proxies: &Arc<
        RwLock<std::collections::HashMap<String, pingclair_proxy::server::PingclairProxy>>,
    >,
    listeners: Option<&dyn pingclair_proxy::server::DynamicListeners>,
) -> Result<(), (StatusCode, String)> {
    let config: PingclairConfig = serde_json::from_value(next.clone())
        .map_err(|error| (StatusCode::BAD_REQUEST, format!("Invalid config: {error}")))?;
    if let Err(error) = pingclair_config::compiler::validate_config(&config) {
        return Err((StatusCode::BAD_REQUEST, format!("Invalid config: {error}")));
    }

    // 🧭 Whole-document replacement semantics: every address the document
    // names must exist before anything is applied.
    let desired: HashSet<String> = config
        .servers
        .iter()
        .flat_map(|server| server.listen.iter().cloned())
        .collect();
    let mut started: Vec<String> = Vec::new();
    for server in &config.servers {
        if server.listen.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                r#"{"error":"a server declares no listen address"}"#.to_string(),
            ));
        }
        for addr in &server.listen {
            if !proxies.read().contains_key(addr) {
                let Some(listeners) = listeners else {
                    return Err((
                        StatusCode::SERVICE_UNAVAILABLE,
                        format!(
                            "listener {addr} is not bound and runtime listener creation is unavailable"
                        ),
                    ));
                };
                if let Err(error) = listeners.start_listener(addr, server) {
                    for started_addr in &started {
                        listeners.stop_listener(started_addr);
                    }
                    return Err((
                        StatusCode::BAD_REQUEST,
                        format!("failed to create listener {addr}: {error}"),
                    ));
                }
                started.push(addr.clone());
            }
        }
    }

    // 🧭 Resolve every target before touching any of them, so a half-applied
    // state is impossible.
    {
        let proxies_guard = proxies.read();
        let mut targets = Vec::new();
        for server in &config.servers {
            for addr in &server.listen {
                match proxies_guard.get(addr) {
                    Some(proxy) => targets.push((addr, server, proxy)),
                    None => {
                        if let Some(listeners) = listeners {
                            for started_addr in &started {
                                listeners.stop_listener(started_addr);
                            }
                        }
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
    }

    // 🧭 Whole-document replacement: remove (dynamic) or empty (startup)
    // listeners the new document no longer mentions.
    if let Some(listeners) = listeners {
        let existing: Vec<String> = proxies.read().keys().cloned().collect();
        for addr in existing {
            if desired.contains(&addr) {
                continue;
            }
            if listeners.is_dynamic(&addr) {
                listeners.stop_listener(&addr);
            } else if let Some(proxy) = proxies.read().get(&addr) {
                proxy.update_config(Vec::new());
                tracing::info!(
                    "🧹 Emptied startup listener {} (a restart is required to close the socket)",
                    addr
                );
            }
        }
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
