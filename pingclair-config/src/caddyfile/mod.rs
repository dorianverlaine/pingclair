// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🥞 The Caddyfile frontend: its own lexer, parser, adapter, and imports.
//!
//! Everything Caddyfile-shaped lives here. The Pingclair language frontend is
//! the crate's top-level [`crate::frontend`]; this module is the compatibility
//! layer that keeps running an existing Pingclairfile unchanged.

pub mod adapter;
mod json;
pub mod parser;

pub use adapter::registry::{is_implemented_directive, recognised_but_unimplemented};
pub use adapter::{AdapterError, adapt, expand_upstream_port_ranges};
pub use json::JsonAdapter;
