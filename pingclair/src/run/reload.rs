// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔔 The SIGUSR1 reload listener.
//!
//! A reload re-reads the configuration file the process started from and hands
//! the result to the same publisher the Admin API uses, so a signal and a
//! `/load` can never disagree about what "the running configuration" means.
//! The whole reload either lands or leaves the previous generation serving;
//! every outcome is logged, printed, and reported to systemd, because the
//! operator who sent the signal has no other way to learn what happened.

use crate::systemd::notify_systemd_status;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

/// 🔔 The reload signals, claimed before readiness.
///
/// Claiming a stream is what registers the process-wide handler: the default
/// terminate-on-SIGHUP action is gone the moment [`ReloadSignals::claim`]
/// returns. The caller claims it *before* announcing readiness, because
/// spawning this listener alone orders nothing — the task may first run after
/// READY — and a SIGHUP delivered in that window kills the process with no
/// log line at all (#299).
pub(super) struct ReloadSignals {
    /// SIGHUP: claimed only so the default action retires; never read.
    hup: tokio::signal::unix::Signal,
    usr1: tokio::signal::unix::Signal,
}

impl ReloadSignals {
    /// Claims both streams; must run inside the background runtime's context.
    pub(super) fn claim() -> std::io::Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};
        Ok(Self {
            hup: signal(SignalKind::hangup())?,
            usr1: signal(SignalKind::user_defined1())?,
        })
    }
}

/// 🔔 Waits for SIGUSR1 forever and reloads `config_path` on each one.
///
/// 🚫 Once the Admin API has changed the configuration, `api_changed` is set
/// and a signal is ignored with a warning: the file on disk no longer
/// describes what is running, so reloading it would silently undo the API.
pub(super) async fn listen_for_reload(
    signals: ReloadSignals,
    config_path: String,
    adapter: Option<crate::cli::config::ConfigAdapter>,
    publisher_for_reload: Arc<dyn pingclair_proxy::server::ConfigPublisher>,
    api_changed_for_reload: Arc<AtomicBool>,
) {
    // 🚦 SIGUSR1 is Caddy's reload signal; SIGHUP is deliberately ignored,
    // matching Caddy's signal table. Both streams were claimed before the
    // readiness announcement, so the handler is already installed; holding
    // the HUP stream without polling it is the "ignored" part.
    let ReloadSignals {
        hup: _hup_ignored,
        usr1: mut usr1_stream,
    } = signals;

    tracing::info!(
        "📡 Reload listener active (SIGUSR1, Config: {})",
        config_path
    );

    loop {
        let signal_name = tokio::select! {
            _ = usr1_stream.recv() => "SIGUSR1",
        };
        if api_changed_for_reload.load(std::sync::atomic::Ordering::SeqCst) {
            tracing::warn!(
                "🚫 SIGUSR1 reload disabled: the configuration was changed through \
                 the Admin API after startup (Caddy semantics)"
            );
            // 📣 An operator who sent the signal deserves to know it was
            // ignored rather than inferring it from a status line that
            // never changes.
            notify_systemd_status(
                "Serving (SIGUSR1 reload ignored: the Admin API owns the configuration since it last changed it)",
            );
            continue;
        }
        if config_path.is_empty() {
            tracing::warn!("🚫 SIGUSR1 reload unavailable: startup has no configuration file");
            notify_systemd_status("Serving (SIGUSR1 reload ignored: no configuration file)");
            continue;
        }
        let reload_start = std::time::Instant::now();
        tracing::info!(
            "🔔 Received {signal_name}, reloading configuration from: {}",
            config_path
        );
        // 🧾 Reload through the startup loader so an explicit adapter still wins.
        tracing::info!("📋 Step 1/3: Validating configuration...");
        let result = crate::cli::config::load(&config_path, adapter);

        match result {
            Ok(new_config) => {
                tracing::info!("✅ Step 1/3: Configuration validation successful");
                tracing::info!("📋 Step 2/3: Preparing configuration update...");
                tracing::info!("📋 Step 3/3: Publishing prepared configuration...");
                match publisher_for_reload.publish_config(&new_config, None, None) {
                    Ok(success_count) => {
                        let reload_duration = reload_start.elapsed();
                        tracing::info!(
                            "✅ Configuration reload completed successfully in {:?}",
                            reload_duration
                        );
                        tracing::info!("   📊 {} listener(s) updated", success_count);
                        println!(
                            "✅ Configuration reloaded successfully ({success_count} \
                             listeners updated in {reload_duration:?})"
                        );
                        // 📣 `systemctl reload` only learned that the
                        // signal was delivered; this is where the answer
                        // it can never see gets published.
                        notify_systemd_status(&format!(
                            "Serving (reloaded {success_count} listener(s) in {reload_duration:?})"
                        ));
                    }
                    Err(error) => {
                        let reload_duration = reload_start.elapsed();
                        tracing::error!(
                            kind = ?error.kind,
                            "❌ Configuration reload rejected after {:?}: {}",
                            reload_duration,
                            error
                        );
                        tracing::error!("   💡 Previous configuration remains active, unchanged");
                        eprintln!("❌ Configuration reload rejected: {error}");
                        eprintln!("   💡 Previous configuration remains active, unchanged");
                        notify_systemd_status(&format!("Reload rejected: {error}"));
                    }
                }
            }
            Err(e) => {
                let reload_duration = reload_start.elapsed();
                tracing::error!(
                    "❌ Configuration reload failed after {:?}: {}",
                    reload_duration,
                    e
                );
                tracing::error!("   💡 Previous configuration remains active");
                eprintln!("❌ Configuration reload failed: {e}");
                eprintln!("   💡 Previous configuration remains active");
                notify_systemd_status(&format!("Reload failed: {e}"));
            }
        }
    }
}
