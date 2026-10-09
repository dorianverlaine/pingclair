// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! ⚡ Benchmarks the private production source path without exporting a testing API.

// 🧪 Cargo sets cfg(test), but the Divan harness omits libtest functions in these modules.
// Their test-only imports and helpers remain compiled; production targets keep both lints.
#![allow(
    dead_code,
    unused_imports,
    reason = "custom harness compiles private modules and their unused libtest support"
)]

#[path = "../src/hello.rs"]
mod hello;
pub use hello::{Classification, ClientHello, classify};
#[path = "../src/relay.rs"]
mod relay;
pub use relay::{RelayOptions, relay};
#[path = "../src/dns/mod.rs"]
mod dns;
pub use dns::{DnsPreparation, DnsRuntime};
#[path = "../src/metrics.rs"]
mod metrics;
#[path = "../src/observation.rs"]
mod observation;
#[path = "../src/session.rs"]
mod session;
pub use session::PreparedListener;
#[path = "../src/upstream.rs"]
mod upstream;

#[global_allocator]
static ALLOCATOR: divan::AllocProfiler = divan::AllocProfiler::system();

fn main() {
    divan::main();
}
