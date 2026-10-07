// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! Configuration types and management

mod bind;
mod ip_ranges;
mod layer4;
mod loader;
pub mod secret;
mod shared_ports;
mod types;

pub use bind::bind_listeners;
pub use ip_ranges::{InvalidIpRange, IpRanges};
pub use layer4::{Layer4Matcher, Layer4Route, Layer4Server, Layer4TlsMatcher};
pub use loader::ConfigLoader;
pub use secret::SecretString;
pub use shared_ports::{FoldedListener, SharedPortConflict, SharedPortFold, covering_wildcard};
pub use types::*;
