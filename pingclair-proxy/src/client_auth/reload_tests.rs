// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔁 Security revisions follow loaded policy content, independently of routes.

use super::*;

fn table(config: &ClientAuthConfig) -> Arc<ClientAuthTable> {
    let mut table = ClientAuthTable::default();
    table.insert(
        &["secure.test", "*.secure.test", "_"],
        Arc::new(CompiledClientAuth::compile(config).unwrap()),
    );
    table.insert_without_client_auth(&["open.secure.test", "*.open.test"]);
    Arc::new(table)
}

fn config(mode: ClientAuthMode) -> ClientAuthConfig {
    ClientAuthConfig {
        mode,
        ..Default::default()
    }
}

#[test]
fn unchanged_policy_publishes_routes_without_invalidating_connections() {
    let config = config(ClientAuthMode::Request);
    let policy = PublishedListenerPolicy::new(table(&config));
    let before = policy.handshake_snapshot();
    let routes = Arc::new(RouteTable::default());
    policy.publish(table(&config), Arc::clone(&routes));
    assert_eq!(policy.revision(), before.revision());
    assert!(Arc::ptr_eq(policy.generation().routes(), &routes));
}

#[test]
fn every_mode_transition_invalidates_connections() {
    let (ca, _) = super::tests::ca_and_leaf();
    let modes = [
        ClientAuthMode::Request,
        ClientAuthMode::Require,
        ClientAuthMode::VerifyIfGiven,
        ClientAuthMode::RequireAndVerify,
    ];
    for before in &modes {
        for after in &modes {
            let make = |mode: &ClientAuthMode| ClientAuthConfig {
                mode: *mode,
                trusted_ca_certs: vec![super::tests::der_base64(&ca)],
                ..Default::default()
            };
            let policy = PublishedListenerPolicy::new(table(&make(before)));
            policy.publish(table(&make(after)), Arc::default());
            assert_eq!(policy.revision(), u64::from(before != after));
        }
    }
}

#[test]
fn certificate_content_not_paths_or_pem_layout_decides_the_revision() {
    let (ca, leaf) = super::tests::ca_and_leaf();
    let (other_ca, other_leaf) = super::tests::ca_and_leaf();
    let directory = tempfile::tempdir().unwrap();
    let roots = directory.path().join("roots.pem");
    let leaves = directory.path().join("leaves");
    std::fs::create_dir(&leaves).unwrap();
    let pinned = leaves.join("leaf.pem");
    std::fs::write(&roots, &ca).unwrap();
    std::fs::write(&pinned, &leaf).unwrap();
    let config = ClientAuthConfig {
        mode: ClientAuthMode::RequireAndVerify,
        trust_pool: Some(TrustPool::Combined {
            sources: vec![TrustPool::File {
                pem_files: vec![roots.display().to_string()],
            }],
        }),
        trusted_leaf_cert_folders: vec![leaves.display().to_string()],
        ..Default::default()
    };
    let policy = PublishedListenerPolicy::new(table(&config));
    std::fs::write(&roots, format!("\n{ca}\n{ca}")).unwrap();
    policy.publish(table(&config), Arc::default());
    assert_eq!(
        policy.revision(),
        0,
        "PEM layout and duplicates are irrelevant"
    );
    std::fs::write(&roots, &other_ca).unwrap();
    policy.publish(table(&config), Arc::default());
    assert_eq!(
        policy.revision(),
        1,
        "same-path CA rotation is a new policy"
    );
    std::fs::write(&pinned, &other_leaf).unwrap();
    policy.publish(table(&config), Arc::default());
    assert_eq!(
        policy.revision(),
        2,
        "same-path pinned leaf rotation is a new policy"
    );
    policy.publish(table(&config), Arc::default());
    assert_eq!(policy.revision(), 2);
}

#[test]
fn table_comparison_preserves_name_precedence_and_ignores_insertion_order() {
    let compiled = Arc::new(CompiledClientAuth::compile(&config(ClientAuthMode::Request)).unwrap());
    let mut first = ClientAuthTable::default();
    first.insert(
        &["*.secure.test", "secure.test", "_"],
        Arc::clone(&compiled),
    );
    first.insert_without_client_auth(&["open.secure.test", "*.open.test"]);
    let mut second = ClientAuthTable::default();
    second.insert_without_client_auth(&["*.open.test", "open.secure.test"]);
    second.insert(
        &["_", "SECURE.TEST", "*.secure.test"],
        Arc::clone(&compiled),
    );
    assert!(first.same_policy(&second));
    second.exact.remove("open.secure.test");
    assert!(!first.same_policy(&second), "an open exception was removed");
    second.insert_without_client_auth(&["open.secure.test"]);
    second.fallback = None;
    assert!(!first.same_policy(&second), "the fallback policy changed");
    second.fallback = Some(compiled);
    second.wildcards.retain(|(name, _)| &**name != ".open.test");
    assert!(!first.same_policy(&second), "an open wildcard was removed");
}

#[test]
fn lazy_system_trust_still_invalidates_connections() {
    let config = config(ClientAuthMode::VerifyIfGiven);
    let policy = PublishedListenerPolicy::new(table(&config));
    policy.publish(table(&config), Arc::default());
    assert_eq!(policy.revision(), 1);
}
