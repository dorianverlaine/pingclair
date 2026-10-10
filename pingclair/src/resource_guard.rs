// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧱 Listener-side resource guards that must run before HTTP routing.

use async_trait::async_trait;
use pingclair_core::config::ResourceLimitsConfig;
use pingclair_proxy::body_timeout::H2BodyWatch;
use pingclair_proxy::server::PingclairProxy;
use pingora_core::apps::{HttpPersistentSettings, HttpServerApp, HttpServerOptions, ServerApp};
use pingora_core::protocols::http::ServerSession;
use pingora_core::protocols::http::v2::server;
use pingora_core::protocols::{ALPN, Digest, Stream};
use pingora_core::server::ShutdownWatch;
use pingora_proxy::HttpProxy;
use std::future::poll_fn;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::Semaphore;
use tokio::time::Instant;

const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// 🔁 Decides whether a plaintext connection opens with the h2c preface.
///
/// 🛡️ Pingora's `Stream::try_peek` is a `read_exact` of whatever buffer it is
/// given (`pingora-core-0.9.0/src/protocols/l4/stream.rs:648`), so asking it for
/// all 24 preface bytes waits for all 24 of them — and a short request never
/// gets there. `GET / HTTP/1.0\r\n\r\n` is 18 bytes and *complete*: the client
/// waits for a response, this server waits for bytes 19 to 24, and neither side
/// moves until the client gives up. That was #165 — a socket held open in
/// silence for a malformed request or an old HTTP/1.0 one.
///
/// 🌊 Asking for one more byte at a time stops at the first byte that cannot be
/// part of the preface, so the wait is proportional to the evidence rather than
/// to the buffer size. A request that begins `GET`, `POST` or any other method
/// is settled by its second byte at the latest; only a client that really is
/// sending the preface is ever waited on. `try_peek` rewinds what it read, so
/// the HTTP/1 parser and the HTTP/2 handshake each see the connection from its
/// first byte.
///
/// 📌 The cost is up to 24 peeks per *connection* — not per request — and only
/// for a connection whose bytes match the preface so far.
///
/// ⏱️ A peer that sends a matching prefix and then stops is genuinely
/// ambiguous, so the wait is bounded by the connection's header deadline
/// instead, which always applies.
async fn is_h2c_preface(stream: &mut Stream) -> std::io::Result<bool> {
    let mut buffer = [0u8; H2_PREFACE.len()];
    for length in 1..=H2_PREFACE.len() {
        // A transport that cannot peek reports so by returning `false`; the
        // trait's default implementation is exactly that.
        if !stream.try_peek(&mut buffer[..length]).await? {
            return Ok(false);
        }
        if buffer[..length] != H2_PREFACE[..length] {
            return Ok(false);
        }
    }
    Ok(true)
}

/// 🧱 Owns one Pingora proxy while bounding accepted transport connections and H1 headers.
pub struct ResourceGuardedProxy {
    proxy: Arc<HttpProxy<PingclairProxy>>,
    connections: Option<Arc<Semaphore>>,
    /// ⏱️ How long one request header may take to arrive, start to finish:
    /// `limits { header_timeout }`, or [`DEFAULT_HEADER_TIMEOUT`] when unset.
    /// Resolved once here, because no request can change it.
    ///
    /// [`DEFAULT_HEADER_TIMEOUT`]: pingclair_proxy::header_timeout::DEFAULT_HEADER_TIMEOUT
    header_timeout: Duration,
}

impl ResourceGuardedProxy {
    /// 🧱 Wraps one fully initialized proxy with its strictest listener-wide limits.
    pub fn new(
        mut proxy: HttpProxy<PingclairProxy>,
        limits: ResourceLimitsConfig,
        server_options: HttpServerOptions,
    ) -> Self {
        let mut h2_options = server::default_h2_options();
        // 🧾 Deliberately looser than `max_header_bytes`: the h2 library
        // answers an oversized list with its own bodiless 431, before the
        // per-site check that names the field can run. See
        // `protocol_header_list_limit` for the bound that still applies.
        if let Some(list_limit) = pingclair_proxy::protocol_header_list_limit(&limits) {
            h2_options.max_header_list_size(u32::try_from(list_limit).unwrap_or(u32::MAX));
        }
        proxy.server_options = Some(server_options);
        proxy.h2_options = Some(h2_options);
        proxy.handle_init_modules();
        let connections = limits
            .max_connections
            .map(|limit| Arc::new(Semaphore::new(limit)));
        let header_timeout = pingclair_proxy::header_timeout::resolve(&limits);
        Self {
            proxy: Arc::new(proxy),
            connections,
            header_timeout,
        }
    }

    /// 🚫 Rejects an excess HTTP/1 connection immediately with a complete response.
    async fn reject_excess_connection(mut stream: Stream) {
        if !matches!(stream.selected_alpn_proto(), Some(ALPN::H2)) {
            let _ = stream
                .write_all(
                    b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 19\r\nContent-Type: text/plain\r\n\r\nConnection limit\n",
                )
                .await;
            let _ = stream.shutdown().await;
        }
    }

    /// 🌐 Runs Pingora's public H1/H2 dispatch while injecting pre-parse H1 limits.
    async fn process_http(
        self: &Arc<Self>,
        mut stream: Stream,
        shutdown: &ShutdownWatch,
    ) -> Option<Stream> {
        // ⏱️ The header deadline runs from accept for the first request and
        // from the end of the previous one for each keepalive request after.
        let mut header_deadline = Instant::now() + self.header_timeout;
        let options = self.proxy.server_options.as_ref();
        let mut h2c = options.is_some_and(|options| options.h2c);
        let custom = options.is_some_and(|options| options.force_custom);

        if h2c && !custom {
            let peek = is_h2c_preface(&mut stream);
            // 📌 A timeout here abandons a partially read preface, which would
            // lose those bytes for any later parser -- safe only because the
            // `?` below drops the connection instead of reusing the stream.
            h2c = tokio::time::timeout_at(header_deadline, peek)
                .await
                .ok()?
                .ok()?;
        }

        if h2c || matches!(stream.selected_alpn_proto(), Some(ALPN::H2)) {
            let digest = Arc::new(Digest {
                ssl_digest: stream.get_ssl_digest(),
                timing_digest: stream.get_timing_digest(),
                proxy_digest: stream.get_proxy_digest(),
                socket_digest: stream.get_socket_digest(),
            });
            // ⏱️ The handshake reads the client's connection preface and
            // SETTINGS, the HTTP/2 counterpart of a request header, so a client
            // that trickles them gets the same deadline.
            let handshake = server::handshake(stream, self.proxy.h2_options.clone());
            let mut connection = tokio::time::timeout_at(header_deadline, handshake)
                .await
                .ok()?
                .ok()?;
            let mut shutdown = shutdown.clone();
            loop {
                let stream = tokio::select! {
                    _ = shutdown.changed() => {
                        connection.graceful_shutdown();
                        let _ = poll_fn(|cx| connection.poll_closed(cx)).await;
                        return None;
                    }
                    stream = server::HttpSession::from_h2_conn(&mut connection, digest.clone()) => stream,
                };
                let accepted = stream.ok()??;
                let stream = match accepted {
                    // 🛡️ Pingora 0.9 can reject one malformed H2 stream while
                    // keeping sibling streams on the connection alive.
                    server::H2Accept::Session(stream) => stream,
                    server::H2Accept::Rejected => continue,
                };
                let proxy = self.proxy.clone();
                let shutdown = shutdown.clone();
                // ⏱️ Pingora cannot time an HTTP/2 request body it proxies, so
                // each stream runs under a watch that can; see `H2BodyWatch`.
                tokio::spawn(async move {
                    H2BodyWatch::serve(
                        proxy.process_new_http(ServerSession::new_http2(stream), &shutdown),
                    )
                    .await;
                });
            }
        }

        if custom || matches!(stream.selected_alpn_proto(), Some(ALPN::Custom(_))) {
            return self
                .proxy
                .clone()
                .process_custom_session(stream, shutdown)
                .await;
        }

        let mut stream = stream;
        let mut persistent: Option<HttpPersistentSettings> = None;
        let mut shutdown_signal = shutdown.clone();
        loop {
            // ⏱️ The whole header arrives before Pingora sees the connection;
            // see `header_deadline` for why Pingora's own timer cannot do this.
            let mut head = crate::header_deadline::read_request_head(
                &mut stream,
                header_deadline,
                &mut shutdown_signal,
            )
            .await?;
            if let Err(rejection) = crate::h1_request_head::prepare_request_head(&mut head) {
                let _ = stream.write_all(rejection.response()).await;
                let _ = stream.shutdown().await;
                return None;
            }
            let mut session = ServerSession::new_http1(stream);
            let fresh_connection = match persistent.take() {
                Some(persistent) => {
                    // 🔁 Carries the decremented reuse budget; the limit below
                    // is for the fresh session only, or every reuse would
                    // restore it and the bound would never arrive.
                    persistent.apply_to_session(&mut session);
                    false
                }
                None => true,
            };
            // 📌 Pingora carries a prefix of its own only when pipelining is
            // enabled, which this server never does, so this is the only one.
            session.set_pipelined_prefix(head);
            // ⏱️ Normally nothing is left to read for the header; this bounds
            // Pingora if its parser disagrees about where the header ended.
            session.set_read_timeout(Some(
                header_deadline.saturating_duration_since(Instant::now()),
            ));
            // ⏱️ Pingora's keepalive timer overrides its header-read timer.
            // ⏱️ Keepalive therefore begins only after routing accepts the header.
            session.set_keepalive(None);
            if fresh_connection {
                session.set_keepalive_reuses_remaining(
                    options.and_then(|options| options.keepalive_request_limit),
                );
            }

            let reused = self.proxy.process_new_http(session, shutdown).await?;
            (stream, persistent) = reused.consume();
            header_deadline = Instant::now() + self.header_timeout;
        }
    }
}

#[async_trait]
impl ServerApp for ResourceGuardedProxy {
    async fn process_new(
        self: &Arc<Self>,
        stream: Stream,
        shutdown: &ShutdownWatch,
    ) -> Option<Stream> {
        let _permit = match &self.connections {
            Some(connections) => match connections.try_acquire() {
                Ok(permit) => Some(permit),
                Err(_) => {
                    tracing::warn!(
                        "🚫 Rejecting a downstream connection at the connection ceiling"
                    );
                    Self::reject_excess_connection(stream).await;
                    return None;
                }
            },
            None => None,
        };
        self.process_http(stream, shutdown).await
    }

    async fn cleanup(&self) {
        self.proxy.http_cleanup().await;
    }
}
