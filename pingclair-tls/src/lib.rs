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
pub mod manager;
pub mod persistent_challenge_handler;
mod secure_file;

pub use acme::{
    AcmeClient, AcmeError, Certificate, ChallengeHandler, ChallengeResponse, ChallengeType,
};
pub use auto_https::{AutoHttps, AutoHttpsConfig, AutoHttpsError};
pub use cert_store::{CertStore, CertStoreError};
pub use manager::TlsManager;
