// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! Pingclair Admin API
//!
//! RESTful API for dynamic configuration management.

mod auth;
mod config_tree;
pub mod server;

pub use server::{AdminPolicy, AdminServerOptions, PreparedAdminPolicy, run_admin_server};
