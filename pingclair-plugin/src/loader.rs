//! Plugin loader

use pingclair_core::error::{Error, Result};

/// Plugin loader
pub struct PluginLoader;

impl PluginLoader {
    /// Load plugins from a directory
    pub fn load_from_dir(_path: &str) -> Result<Vec<Box<dyn crate::traits::Plugin>>> {
        // TODO: Implement plugin loading
        Err(Error::Plugin("Plugin loading not yet implemented".to_string()))
    }
}
