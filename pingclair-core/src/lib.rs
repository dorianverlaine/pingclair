// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! Pingclair Core Library
//!
//! This crate provides the core functionality for the Pingclair web server,
//! including configuration management, HTTP server, and error handling.

/// 🔐 Writing a secret to disk, re-exported from `pingclair-tls`.
///
/// The implementation lives there because that is the crate that needed it
/// first and `pingclair-core` already depends on it; the re-export is here so
/// that everything above core reaches the writer by one name instead of
/// growing a direct TLS dependency to save a secret.
pub mod secure_file {
    pub use pingclair_tls::secure_file::write_private_file;
}

pub mod config;
// 🗜️ Shared because two crates negotiate content coding and having two
// implementations already shipped a defect — see the module's own header.
pub mod encoding;
pub mod error;
pub mod percent;
pub mod server;

pub use error::{Error, Result};

/// 🏷️ Whether this is a build of the default branch rather than a release.
///
/// The default branch always carries version 0.0.0 and only a release commit
/// sets a real one, so "0.0.0" is how a build knows it is not a release.
const IS_DEV_BUILD: bool = str_eq(env!("CARGO_PKG_VERSION"), "0.0.0");

/// 🏷️ The version this library reports: the release version, or `0.0.0-dev`
/// for a build of the default branch.
///
/// 📌 The binary's own `--version` adds the commit sha on top; this constant
/// cannot, because naming the commit here would rebuild every crate after
/// every commit.
pub const VERSION: &str = if IS_DEV_BUILD {
    "0.0.0-dev"
} else {
    env!("CARGO_PKG_VERSION")
};

/// 🏷️ The `Pingclair/<version>` token for CGI's `SERVER_SOFTWARE`.
///
/// ⚡ A constant so the FastCGI path does not format it on every request.
pub const SERVER_SOFTWARE: &str = if IS_DEV_BUILD {
    "Pingclair/0.0.0-dev"
} else {
    concat!("Pingclair/", env!("CARGO_PKG_VERSION"))
};

const fn str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}
