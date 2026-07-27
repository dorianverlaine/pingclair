// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! Pingclair Admin API
//!
//! RESTful API for dynamic configuration management.

mod auth;
pub mod server;

pub use server::run_admin_server;
