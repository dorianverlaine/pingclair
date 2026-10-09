// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! Configuration types and management

mod bind;
mod ip_ranges;
mod layer4;
mod layer4_dynamic;
mod loader;
pub mod secret;
mod shared_ports;
mod text;
mod types;

pub use bind::{bind_listeners, bind_socket_host};
pub use ip_ranges::{InvalidIpRange, IpRanges, PRIVATE_RANGES};
pub use layer4::{Layer4Matcher, Layer4Route, Layer4Server, Layer4TlsMatcher};
pub use layer4_dynamic::{Layer4Dns, Layer4Dynamic, Layer4IpVersions};
pub use loader::ConfigLoader;
pub use secret::SecretString;
pub use shared_ports::{FoldedListener, SharedPortConflict, SharedPortFold, covering_wildcard};
pub use text::ConfigText;
pub use types::*;
