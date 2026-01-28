//! Configuration adapters

pub mod caddyfile;
pub mod json;

pub use caddyfile::{adapt, AdapterError};
pub use json::JsonAdapter;
