// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔎 Compare the policy loaded for a reload with the one that admitted clients.

use super::{ClientAuthTable, CompiledClientAuth};
use boring::error::ErrorStack;
use boring::x509::X509;
use boring::x509::store::{X509Store, X509StoreBuilder};

/// 🏛️ A store and the certificates actually used to build it.
pub(super) struct CompiledTrust {
    pub(super) store: X509Store,
    pub(super) roots: Option<Vec<Vec<u8>>>,
}

/// 📸 Capture certificates while loading them, never by reopening their paths.
///
/// System directories are lazy BoringSSL lookups. Their complete contents are
/// not captured here, so a policy using them must still invalidate connections.
pub(super) struct TrustStoreBuilder {
    builder: X509StoreBuilder,
    roots: Option<Vec<Vec<u8>>>,
}

impl TrustStoreBuilder {
    pub(super) fn new() -> Result<Self, ErrorStack> {
        Ok(Self {
            builder: X509StoreBuilder::new()?,
            roots: Some(Vec::new()),
        })
    }

    pub(super) fn add_cert(&mut self, certificate: X509) -> Result<(), ErrorStack> {
        if let Some(roots) = &mut self.roots {
            roots.push(certificate.to_der()?);
        }
        self.builder.add_cert(certificate)
    }

    pub(super) fn set_default_paths(&mut self) -> Result<(), ErrorStack> {
        self.roots = None;
        self.builder.set_default_paths()
    }

    pub(super) fn build(mut self) -> CompiledTrust {
        if let Some(roots) = &mut self.roots {
            roots.sort_unstable();
            roots.dedup();
        }
        CompiledTrust {
            store: self.builder.build(),
            roots: self.roots,
        }
    }
}

impl CompiledClientAuth {
    fn same_policy(&self, other: &Self) -> bool {
        self.verify_mode == other.verify_mode
            && self.trust.is_some() == other.trust.is_some()
            && self.trust_roots.is_some()
            && self.trust_roots == other.trust_roots
            && self.pinned_leaves == other.pinned_leaves
    }
}

impl ClientAuthTable {
    /// 🗺️ Include open rows: removing one can expose a stricter wildcard.
    pub(super) fn same_policy(&self, other: &Self) -> bool {
        let same_row = |left: &Option<std::sync::Arc<CompiledClientAuth>>,
                        right: &Option<std::sync::Arc<CompiledClientAuth>>| {
            match (left, right) {
                (Some(left), Some(right)) => left.same_policy(right),
                (None, None) => true,
                (Some(_), None) | (None, Some(_)) => false,
            }
        };
        self.enforcing == other.enforcing
            && self.exact.len() == other.exact.len()
            && self.exact.iter().all(|(name, policy)| {
                other
                    .exact
                    .get(name)
                    .is_some_and(|row| same_row(policy, row))
            })
            && self.wildcards.len() == other.wildcards.len()
            && self.wildcards.iter().all(|(name, policy)| {
                other
                    .wildcards
                    .iter()
                    .find(|(candidate, _)| candidate == name)
                    .is_some_and(|(_, row)| same_row(policy, row))
            })
            && same_row(&self.fallback, &other.fallback)
    }
}
