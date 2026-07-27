// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! Configuration adapters

pub mod caddyfile;
pub mod json;

pub use caddyfile::{AdapterError, adapt};
pub use json::JsonAdapter;
