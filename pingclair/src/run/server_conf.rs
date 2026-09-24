// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧮 The Pingora `ServerConf` this process runs with.
//!
//! Every value that Pingora would otherwise default silently — keepalive pool
//! size, worker threads, shutdown grace — is chosen here on purpose and logged,
//! so an operator can read what the process decided instead of discovering it
//! under load or during a restart.

use pingora::server::configuration::ServerConf;

/// 🧮 Builds the server configuration and returns it with the shutdown grace
/// period in seconds, which the drain task needs as well.
pub(super) fn build(config: &pingclair_core::config::PingclairConfig) -> (ServerConf, u64) {
    // 🧮 We build `ServerConf` explicitly (rather than passing `conf: None`
    // and letting Pingora fall back to its own implicit default) so the
    // upstream keepalive connection pool size is always a deliberate,
    // known value — not an invisible one an operator only discovers when
    // a slow upstream under load starts exhausting connections.
    let mut server_conf = ServerConf::default();
    server_conf.upstream_keepalive_pool_size = config
        .global
        .upstream_keepalive_pool_size
        // ⚡ 512, not Pingora's 128: an interleaved t4g.small scan of the
        // reverse-proxy path (2026-08-03) measured 128 → 8.1k req/s, 256 →
        // 8.5k, 512 → 8.9k on 100×20 HTTP/2 streams, then a small decline at
        // 768/1024. The idle pool only caps reusable upstream connections, so
        // the cost is bounded by the FD limit; operators can still override
        // the knob per deployment.
        .unwrap_or_else(|| server_conf.upstream_keepalive_pool_size.max(512));
    // Pingora defaults to ONE thread per service — on a multi-core box that
    // leaves the machine idle while nginx runs one worker per core. Scale
    // with available parallelism instead (still overridable via config).
    server_conf.threads = config.global.worker_threads.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    });
    // 🚰 What happens to a request that is still running when SIGTERM arrives.
    //
    // Pingora's own default gives the runtime five seconds and then stops it,
    // which truncates anything slower than that: measured on 2026-08-05, a
    // 20 MiB download over a rate-limited link arrived as 4.1 MiB, status 200,
    // no error the client could distinguish from a network fault. Every
    // rolling restart did that to every transfer in progress.
    //
    // Caddy waits for them however long they take — its log literally says
    // "eternal grace period" — so that is the default here too, expressed as
    // the largest span Pingora will accept. `grace_period` is how an operator
    // trades that for a bounded restart.
    // ⏱️ 30 seconds, not "forever". The window is an unconditional sleep, so
    // "forever" would mean a process that never exits — and Pingora's own
    // 300-second default means every restart waits five minutes with nothing
    // to drain. 30s is long enough for ordinary requests to land and short
    // enough that a rolling restart still moves.
    const DEFAULT_GRACE_SECS: u64 = 30;
    let grace_period_secs = config
        .global
        .grace_period_secs
        .unwrap_or(DEFAULT_GRACE_SECS);
    // 🕐 Which knob does what, read off pingora-core 0.9.0 `server/mod.rs:803`
    // rather than guessed — the first attempt at this guessed wrong in both
    // directions and shipped a shutdown that hung:
    //
    //   grace_period_seconds          → `thread::sleep(...)` before teardown.
    //                                   Unconditional: an idle server would
    //                                   still wait all of it.
    //   graceful_shutdown_timeout_secs → `rt.shutdown_timeout(t)` *and then*
    //                                   `thread::sleep(t)` again. A large value
    //                                   here does not extend the drain; it just
    //                                   makes the process refuse to exit.
    //
    // 🚰 Neither is what actually ends the process. `crate::shutdown` waits for
    // the running requests themselves and exits as soon as the last one is
    // done, bounded by this same grace period; Pingora's sleep is only the
    // backstop if that task never runs. So the configured grace goes in both
    // places, and the teardown budget stays at Pingora's small default.
    server_conf.grace_period_seconds = Some(grace_period_secs);
    tracing::info!(
        "🚰 Shutdown grace period: {}s{}",
        grace_period_secs,
        if config.global.grace_period_secs.is_some() {
            ""
        } else {
            " (default; set `grace_period` to change it)"
        }
    );
    tracing::info!(
        "🔗 Upstream keepalive pool size: {} connections/thread",
        server_conf.upstream_keepalive_pool_size
    );
    tracing::info!("🧵 Worker threads per service: {}", server_conf.threads);
    tracing::info!(
        "🛡️ Trusted proxy networks: {}",
        config.global.trusted_proxies.len()
    );
    {
        let required: Vec<&str> = config
            .servers
            .iter()
            .flat_map(|server| server.proxy_protocol_listen.iter())
            .map(String::as_str)
            .collect();
        tracing::info!(
            "🧭 PROXY protocol listeners: {}",
            if required.is_empty() {
                "none".to_string()
            } else {
                required.join(", ")
            }
        );
    }

    (server_conf, grace_period_secs)
}
