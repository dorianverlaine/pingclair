// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧱 Listener-side resource guards that must run before HTTP routing.

use async_trait::async_trait;
use pingclair_core::config::ResourceLimitsConfig;
use pingclair_proxy::server::PingclairProxy;
use pingora_core::apps::{HttpServerApp, HttpServerOptions, ServerApp};
use pingora_core::protocols::http::ServerSession;
use pingora_core::protocols::http::v2::server;
use pingora_core::protocols::{ALPN, Digest, Stream};
use pingora_core::server::ShutdownWatch;
use pingora_proxy::HttpProxy;
use std::future::poll_fn;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::sync::Semaphore;

const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// 🧱 Owns one Pingora proxy while bounding accepted transport connections and H1 headers.
pub struct ResourceGuardedProxy {
    proxy: Arc<HttpProxy<PingclairProxy>>,
    limits: ResourceLimitsConfig,
    connections: Option<Arc<Semaphore>>,
}

impl ResourceGuardedProxy {
    /// 🧱 Wraps one fully initialized proxy with its strictest listener-wide limits.
    pub fn new(
        mut proxy: HttpProxy<PingclairProxy>,
        limits: ResourceLimitsConfig,
        server_options: HttpServerOptions,
    ) -> Self {
        let mut h2_options = server::default_h2_options();
        if let Some(max_header_bytes) = limits.max_header_bytes {
            h2_options.max_header_list_size(max_header_bytes as u32);
        }
        proxy.server_options = Some(server_options);
        proxy.h2_options = Some(h2_options);
        proxy.handle_init_modules();
        let connections = limits
            .max_connections
            .map(|limit| Arc::new(Semaphore::new(limit)));
        Self {
            proxy: Arc::new(proxy),
            limits,
            connections,
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
        let mut header_started = Instant::now();
        let options = self.proxy.server_options.as_ref();
        let mut h2c = options.is_some_and(|options| options.h2c);
        let custom = options.is_some_and(|options| options.force_custom);

        if h2c && !custom {
            let mut buffer = [0u8; H2_PREFACE.len()];
            let peek = stream.try_peek(&mut buffer);
            let peeked = match self.limits.header_timeout_ms {
                Some(timeout_ms) => tokio::time::timeout(Duration::from_millis(timeout_ms), peek)
                    .await
                    .ok()?
                    .ok()?,
                None => peek.await.ok()?,
            };
            h2c = peeked && buffer == H2_PREFACE;
        }

        if h2c || matches!(stream.selected_alpn_proto(), Some(ALPN::H2)) {
            let digest = Arc::new(Digest {
                ssl_digest: stream.get_ssl_digest(),
                timing_digest: stream.get_timing_digest(),
                proxy_digest: stream.get_proxy_digest(),
                socket_digest: stream.get_socket_digest(),
            });
            let mut connection = server::handshake(stream, self.proxy.h2_options.clone())
                .await
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
                let stream = stream.ok()??;
                let proxy = self.proxy.clone();
                let shutdown = shutdown.clone();
                tokio::spawn(async move {
                    proxy
                        .process_new_http(ServerSession::new_http2(stream), &shutdown)
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

        let mut session = ServerSession::new_http1(stream);
        loop {
            let header_timeout = self
                .limits
                .header_timeout_ms
                .map(Duration::from_millis)
                .and_then(|timeout| timeout.checked_sub(header_started.elapsed()));
            if self.limits.header_timeout_ms.is_some() && header_timeout.is_none() {
                return None;
            }
            session.set_read_timeout(header_timeout);
            // ⏱️ Pingora's keepalive timer overrides its header-read timer.
            // ⏱️ Keepalive therefore begins only after routing accepts the header.
            session.set_keepalive(None);
            session.set_keepalive_reuses_remaining(
                options.and_then(|options| options.keepalive_request_limit),
            );

            let reused = self.proxy.process_new_http(session, shutdown).await?;
            let (stream, persistent) = reused.consume();
            session = ServerSession::new_http1(stream);
            header_started = Instant::now();
            if let Some(persistent) = persistent {
                persistent.apply_to_session(&mut session);
            }
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
                    tracing::warn!("🚫 Rejecting a downstream connection at the configured limit");
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
