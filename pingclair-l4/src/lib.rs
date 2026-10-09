// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔌 TCP routing primitives independent of the HTTP proxy.

mod hello;
pub use hello::{Classification, ClientHello, classify};

mod relay;
pub use relay::{RelayOptions, relay};

#[cfg(test)]
mod dns;

mod metrics;
mod observation;
mod session;
mod upstream;
pub use session::PreparedListener;
