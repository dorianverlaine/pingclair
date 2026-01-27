//! Pingclair Plugin System
//!
//! Extensible plugin architecture for adding custom functionality.

mod loader;
mod registry;
mod traits;

pub use loader::PluginLoader;
pub use registry::PluginRegistry;
pub use traits::{Plugin, PluginContext, PluginInfo};
