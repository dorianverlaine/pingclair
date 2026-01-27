#![allow(dead_code)]
//! Plugin traits

use async_trait::async_trait;
use pingclair_core::Result;

/// Plugin information
#[derive(Debug, Clone)]
pub struct PluginInfo {
    /// Plugin name
    pub name: String,
    /// Plugin version
    pub version: String,
    /// Plugin description
    pub description: String,
}

/// Plugin context for accessing server internals
pub struct PluginContext {
    // TODO: Add context fields
}

/// Main plugin trait
#[async_trait]
pub trait Plugin: Send + Sync {
    /// Get plugin information
    fn info(&self) -> PluginInfo;

    /// Initialize the plugin
    async fn init(&mut self, ctx: &PluginContext) -> Result<()>;

    /// Shutdown the plugin
    async fn shutdown(&mut self) -> Result<()>;
}

/// Handler plugin trait
#[async_trait]
pub trait HandlerPlugin: Plugin {
    /// Handle a request
    async fn handle(&self, req: &[u8]) -> Result<Vec<u8>>;
}

/// Middleware plugin trait
#[async_trait]
pub trait MiddlewarePlugin: Plugin {
    /// Process request before handler
    async fn before(&self, req: &mut Vec<u8>) -> Result<()>;

    /// Process response after handler
    async fn after(&self, res: &mut Vec<u8>) -> Result<()>;
}
