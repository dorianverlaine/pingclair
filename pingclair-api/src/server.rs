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
use tokio::net::TcpListener;

use pingclair_core::config::{PingclairConfig, ServerConfig};

use crate::auth::{ApiKeyAuth, AuthDecision, authorize};

/// Run the admin server
pub async fn run_admin_server(
    addr: SocketAddr,
    proxies: Arc<
        RwLock<std::collections::HashMap<String, pingclair_proxy::server::PingclairProxy>>,
    >,
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
        let auth = auth.clone();

        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(
                    io,
                    service_fn(move |req| {
                        handle_request(req, proxies.clone(), auth.clone(), peer_addr)
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

    match (req.method(), req.uri().path()) {
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
        (&Method::GET, "/config") => {
            // 🧭 Exports a document shaped like the config file: one `servers`
            // list, deduplicated, so the output can be POSTed back to /load.
            let mut servers = Vec::new();
            let proxies_guard = proxies.read();
            for proxy in proxies_guard.values() {
                let mut host_configs = Vec::new();
                for host_state in proxy.hosts.load().values() {
                    host_configs.push(host_state.config.as_ref().clone());
                }
                if let Some(def) = (**proxy.default.load()).as_ref() {
                    host_configs.push(def.config.as_ref().clone());
                }
                for config in host_configs {
                    // 🧭 Deduplicate by name + listener set; ServerConfig does
                    // not implement PartialEq.
                    let already_present = servers.iter().any(|existing: &ServerConfig| {
                        existing.name == config.name && existing.listen == config.listen
                    });
                    if !already_present {
                        servers.push(config);
                    }
                }
            }

            let document = PingclairConfig {
                servers,
                ..Default::default()
            };
            let json = serde_json::to_string_pretty(&document).unwrap_or_default();
            Ok(Response::new(Full::new(Bytes::from(json))))
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
        (&Method::POST, path) if path.starts_with("/config") => {
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

            let config: ServerConfig = match serde_json::from_slice(&body_bytes) {
                Ok(c) => c,
                Err(e) => {
                    return Ok(response(
                        StatusCode::BAD_REQUEST,
                        &format!("Invalid config: {e}"),
                    ));
                }
            };

            // 🛡️ The same validator the Pingclairfile path runs. Deserializing
            // into the core types only proves the JSON has the right shape; it
            // says nothing about whether the settings are safe or even
            // implemented. Skipping this is how `plugin` handlers and unsafe
            // retry policies used to enter through the Admin door only.
            if let Err(error) = validate_incoming_server(&config) {
                return Ok(response(
                    StatusCode::BAD_REQUEST,
                    &format!("Invalid config: {error}"),
                ));
            }

            let proxies_guard = proxies.read();

            // 🧭 Resolve every target before touching any of them. Applying
            // inside the loop meant a config naming two listeners where only
            // the first exists left that one live on the new settings and the
            // other on the old — a half-applied state nobody asked for and
            // nothing reported.
            let mut targets = Vec::with_capacity(config.listen.len());
            for addr in &config.listen {
                match proxies_guard.get(addr) {
                    Some(proxy) => targets.push((addr, proxy)),
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

            if targets.is_empty() {
                return Ok(response(
                    StatusCode::BAD_REQUEST,
                    r#"{"error":"config declares no listen address"}"#,
                ));
            }

            for (addr, proxy) in targets {
                proxy.add_server(config.clone());
                tracing::info!(listener = %addr, "♻️ Hot reloaded config");
            }

            Ok(response(StatusCode::OK, "Config updated"))
        }
        _ => Ok(response(StatusCode::NOT_FOUND, "Not Found")),
    }
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

/// 🛡️ Runs one posted server through the canonical validator.
///
/// The validator's subject is a whole `PingclairConfig`, so the incoming
/// server is wrapped in one. Per-server rules — limits, TLS coherence,
/// retry and circuit policy, unimplemented handlers — all apply exactly as
/// they do to a Pingclairfile.
///
/// What this deliberately does not cover: rules that compare servers against
/// each other, such as two listeners disagreeing about PROXY protocol. Those
/// need the live configuration as context, which the Admin API does not
/// currently assemble. Stated here rather than left to be discovered, because
/// the last time this gap was undocumented it was described as closed for a
/// week while it was open.
fn validate_incoming_server(
    config: &ServerConfig,
) -> Result<(), pingclair_config::compiler::CompileError> {
    let document = pingclair_core::config::PingclairConfig {
        servers: vec![config.clone()],
        ..Default::default()
    };
    pingclair_config::compiler::validate_config(&document)
}

fn response(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}
