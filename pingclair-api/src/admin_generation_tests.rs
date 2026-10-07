// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

use pingclair_proxy::server::{ConfigApplyError, ConfigPublisher};

#[test]
fn retained_generations_bind_document_to_authorization() {
    let old_document = serde_json::json!({"debug": false, "admin": {
        "enabled": true, "listen": "127.0.0.1:2019", "api_key": "old-key"
    }});
    let old_admin: AdminConfig = serde_json::from_value(old_document["admin"].clone()).unwrap();
    let policy = AdminPolicy::new(
        "127.0.0.1:2019".into(),
        Some(&old_admin),
        true,
        old_document.clone(),
    );
    let retained = policy.snapshot();
    let new_document = serde_json::json!({"debug": true, "admin": {
        "enabled": true, "listen": "127.0.0.1:2019", "api_key": "new-key"
    }});
    let new_admin: AdminConfig = serde_json::from_value(new_document["admin"].clone()).unwrap();
    let prepared = policy
        .prepare(Some(&new_admin), new_document.clone())
        .unwrap();
    assert_eq!(policy.snapshot().document, old_document);
    policy.publish(prepared);
    let current = policy.snapshot();
    assert_eq!(current.document, new_document);
    assert_eq!(retained.document, old_document);
    assert_eq!((retained.revision, current.revision), (0, 1));
    let peer = "127.0.0.1".parse().unwrap();
    assert!(matches!(
        authorize(retained.auth.as_deref(), Some("Bearer old-key"), peer),
        AuthDecision::Allowed
    ));
    assert!(matches!(
        authorize(current.auth.as_deref(), Some("Bearer old-key"), peer),
        AuthDecision::Unauthorized
    ));
    assert!(matches!(
        authorize(current.auth.as_deref(), Some("Bearer new-key"), peer),
        AuthDecision::Allowed
    ));
}

/// 🧪 A publisher that reproduces the real revision guard without a live proxy.
///
/// 📌 `RuntimeListeners::prepare_admin` compares `admin_policy.revision()` with
/// the writer's expected revision under its publication lock and refuses a
/// mismatch as `StaleAuthorization`. This stub performs that one decision so
/// the Admin API's refusal — and its shape on the wire — can be pinned without
/// racing a real rotation.
struct RevisionGuardPublisher {
    revision: AtomicU64,
}

impl ConfigPublisher for RevisionGuardPublisher {
    fn publish_config(
        &self,
        _config: &pingclair_core::config::PingclairConfig,
        expected_admin_revision: Option<u64>,
        _document: Option<&Value>,
    ) -> Result<usize, ConfigApplyError> {
        if let Some(expected) = expected_admin_revision
            && self.revision.load(Ordering::SeqCst) != expected
        {
            return Err(ConfigApplyError::stale_authorization(
                "the Admin access policy changed; authenticate again before retrying",
            ));
        }
        Ok(0)
    }
}

/// 🔐 A write authorized by a generation the publisher has since replaced is
/// refused, and the refusal tells the client to authenticate again.
///
/// 📌 This is the concrete answer to "does authorization validation invalidate
/// a writer on revocation": it is not the API key that is re-checked at
/// publication time but the *generation* the write was authorized under. A key
/// rotation publishes a newer generation, so a writer still holding the old
/// one fails the revision comparison under the publication lock. An
/// unconditional write reports `409 Conflict`; a conditional write reports
/// `412 Precondition Failed` because its `If-Match` no longer names the
/// generation it read.
#[test]
fn a_write_authorized_by_a_replaced_generation_is_refused_as_stale() {
    let running = serde_json::json!({"admin": {
        "listen": "127.0.0.1:2019", "api_key": "old-key"
    }});
    let next = serde_json::json!({"admin": {
        "listen": "127.0.0.1:2019", "api_key": "new-key"
    }});

    // 🕰️ The rotation already published: revision 1 is current, the writer
    // that authenticated against the old policy still holds revision 0.
    let rotated = RevisionGuardPublisher {
        revision: AtomicU64::new(1),
    };
    let refused = commit_document(&next, &running, Some(&rotated), 0, None)
        .expect_err("a write authorized by a replaced generation must be refused");
    assert_eq!(refused.0, StatusCode::CONFLICT);
    assert!(
        refused.1.contains(r#""reauthenticate":true"#),
        "the refusal must tell the client to authenticate again: {}",
        refused.1
    );

    // ✅ The same write lands while the publisher is still on the writer's
    // generation, so the guard refuses only the stale case.
    let current = RevisionGuardPublisher {
        revision: AtomicU64::new(0),
    };
    commit_document(&next, &running, Some(&current), 0, None)
        .expect("a write authorized by the current generation must be accepted");
}
