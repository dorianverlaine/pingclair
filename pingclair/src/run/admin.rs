// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔧 Starting the Admin API.
//!
//! The admin port is bound synchronously, like every data-plane listener, so
//! a taken port stops startup with the address in the message. The server
//! itself then runs on its own thread and runtime, sharing the configuration
//! document and publisher with the reload path so `/config` always describes
//! the generation that is actually serving.

use crate::paths::tls_store_dir_with;
use parking_lot::RwLock;
use std::sync::Arc;

/// 🔧 Everything the Admin API shares with the rest of the process.
pub(super) struct AdminShared {
    pub(super) document: Arc<RwLock<serde_json::Value>>,
    pub(super) shutdown: Arc<tokio::sync::Notify>,
    pub(super) publisher: Arc<dyn pingclair_proxy::server::ConfigPublisher>,
    pub(super) policy: Arc<pingclair_api::AdminPolicy>,
}

/// 🔧 Binds and starts the Admin API when the configuration enables it.
pub(super) fn start(
    config: &pingclair_core::config::PingclairConfig,
    shared: AdminShared,
) -> anyhow::Result<()> {
    if let Some(admin_config) = &config.admin
        && admin_config.enabled
    {
        let listen = admin_config.listen.clone();
        let shutdown_for_admin = shared.shutdown;
        let autosave =
            tls_store_dir_with(config.global.storage_path.as_deref()).join("autosave.json");
        // 🧭 The admin traversal endpoints read and write one shared config
        // document; it starts as the exact configuration that was loaded.
        let document = shared.document;
        let publisher_for_admin = shared.publisher;
        let policy_for_admin = shared.policy;

        // 🚫 Bound here, synchronously, like the TCP and UDP listeners before it: a
        // taken admin port stops startup and names the address. Binding inside
        // the admin thread used to log the failure to stdout and carry on, so
        // the server looked healthy while refusing every `/load` and `/config`.
        // `validate_config` already refuses an address that does not parse;
        // this re-checks rather than panicking if one ever reaches here.
        let addr = pingclair_core::config::parse_listen_addr(&listen)
            .ok_or_else(|| anyhow::anyhow!("admin API address `{listen}` is not bindable"))?;
        let admin_listener = std::net::TcpListener::bind(addr)
            .map_err(|error| anyhow::anyhow!("failed to bind admin API on {listen}: {error}"))?;

        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("Failed to create admin runtime");
            rt.block_on(async {
                let options = pingclair_api::AdminServerOptions {
                    document,
                    shutdown: shutdown_for_admin,
                    autosave: Some(autosave),
                    publisher: Some(publisher_for_admin),
                    policy: policy_for_admin,
                };
                if let Err(e) = pingclair_api::run_admin_server(admin_listener, options).await {
                    tracing::error!("🔧 Admin server error: {}", e);
                }
            });
        });
    }
    Ok(())
}
