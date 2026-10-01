// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

use super::*;

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
