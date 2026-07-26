//! Configuration adapters

pub mod caddyfile;
pub mod json;

pub use caddyfile::{AdapterError, adapt};
pub use json::JsonAdapter;
