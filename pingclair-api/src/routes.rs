//! API route definitions

use pingclair_core::config::PingclairConfig;
use std::sync::Arc;
use tokio::sync::RwLock;

/// API Router
pub struct ApiRouter {
    config: Arc<RwLock<PingclairConfig>>,
    listen: String,
}

impl ApiRouter {
    /// Create a new API router
    pub fn new(config: Arc<RwLock<PingclairConfig>>, listen: impl Into<String>) -> Self {
        Self {
            config,
            listen: listen.into(),
        }
    }

    /// Start the API server
    pub async fn start(&self) -> pingclair_core::Result<()> {
        tracing::info!("Starting admin API on {}", self.listen);
        // TODO: Implement HTTP server for admin API
        Ok(())
    }

    /// Get current configuration
    pub async fn get_config(&self) -> PingclairConfig {
        self.config.read().await.clone()
    }

    /// Update configuration
    pub async fn update_config(&self, new_config: PingclairConfig) {
        let mut config = self.config.write().await;
        *config = new_config;
        tracing::info!("Configuration updated");
    }
}
