// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! Configuration types and management

mod ip_ranges;
mod loader;
pub mod secret;
mod types;

pub use ip_ranges::{InvalidIpRange, IpRanges};
pub use loader::ConfigLoader;
pub use secret::SecretString;
pub use types::*;
