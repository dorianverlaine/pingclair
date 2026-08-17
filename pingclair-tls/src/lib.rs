// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! Pingclair TLS Module
//!
//! TLS/HTTPS automation including:
//! - ACME protocol (Let's Encrypt)
//! - Certificate storage and management
//! - Automatic HTTPS
//! - HTTP/3 (QUIC) support

pub mod account_store;
pub mod acme;
pub mod auto_https;
pub mod cert_store;
pub mod dns01;
pub mod internal_ca;
pub mod manager;
pub mod persistent_challenge_handler;
/// 🔐 The owner-only atomic writer, shared with everything that puts a
/// secret on disk. See the module docs for why there is exactly one.
pub mod secure_file;

pub use acme::{
    AcmeClient, AcmeError, Certificate, ChallengeHandler, ChallengeResponse, ChallengeType,
};
pub use auto_https::{AutoHttps, AutoHttpsConfig, AutoHttpsError};
pub use cert_store::{CertStore, CertStoreError};
pub use internal_ca::{InternalCa, InternalCaError};
pub use manager::TlsManager;
