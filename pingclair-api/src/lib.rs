//! Pingclair Admin API
//!
//! RESTful API for dynamic configuration management.

mod auth;
mod handlers;
pub mod server;

pub use server::run_admin_server;
