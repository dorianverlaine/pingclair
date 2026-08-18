// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! ⚡ Microbenchmarks for the hot percent-decoding path.
//!
//! `decode_path_component` runs on every static-file and `file`-matcher hit,
//! so CI keeps a smoke benchmark to prove the target still compiles and
//! starts. Divan's harness runs once per input under `--test` mode.

use divan::black_box;
use pingclair_core::percent::decode_path_component;

fn main() {
    divan::main();
}

#[divan::bench]
fn plain_component() -> bool {
    let mut out = Vec::with_capacity(64);
    decode_path_component(black_box("index.html"), &mut out)
}

#[divan::bench]
fn escaped_component() -> bool {
    let mut out = Vec::with_capacity(64);
    decode_path_component(black_box("%E4%BD%A0%E5%A5%BD.txt"), &mut out)
}
