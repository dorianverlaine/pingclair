//! Pingclair TLS Module
//!
//! TLS/HTTPS automation including:
//! - ACME protocol (Let's Encrypt)
//! - Certificate storage and management
//! - Automatic HTTPS
//! - HTTP/3 (QUIC) support

pub mod acme;
pub mod auto_https;
pub mod cert_store;
pub mod manager;

pub use acme::{AcmeClient, AcmeError, Certificate, ChallengeHandler, ChallengeType, ChallengeResponse};
pub use auto_https::{AutoHttps, AutoHttpsConfig, AutoHttpsError};
pub use cert_store::{CertStore, CertStoreError};
pub use manager::TlsManager;
