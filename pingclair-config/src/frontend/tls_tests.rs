// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔐 Contract tests for the `.tls(...)` surface: Caddyfile twins for the
//! shared capabilities, native-only refusals, and the one secret-accepting
//! field family (the DNS-01 provider arguments).

use super::*;

/// 🏠 One HTTPS listener with one site — the scaffolding every case shares.
const SITE: &str = "HTTPListener(on: \":8443\") {\n    Site(host: \"example.test\") {\n        Fallback { Respond(body: \"hi\") }\n    }\n}";

fn native(source: &str) -> PingclairConfig {
    crate::adapt(source).expect("the native source adapts")
}

fn legacy(source: &str) -> PingclairConfig {
    crate::adapt(source).expect("the Caddyfile source adapts")
}

/// 🔐 The TLS subtree of the first server, which is what these tests compare.
///
/// 📌 The comparison is scoped to TLS on purpose: the response body differs
/// between the two languages by encoding (`ConfigText`), and that difference
/// is asserted where it belongs, not here.
fn tls_of(config: &PingclairConfig) -> serde_json::Value {
    serde_json::to_value(&config.servers[0].tls).expect("tls serialises")
}

#[test]
fn tls_settings_lower_like_their_caddyfile_twins() {
    let cases: Vec<(String, &str)> = vec![
        (
            format!("{SITE}\n.tls(.internal, defaultSNI: \"fallback.test\")"),
            "https://example.test:8443 {\n\ttls internal {\n\t\tdefault_sni fallback.test\n\t}\n\trespond \"hi\"\n}\n",
        ),
        (
            format!(
                "{SITE}\n.tls(.automatic(email: \"admin@example.com\"), renewalWindow: .ratio(0.1))"
            ),
            "https://example.test:8443 {\n\ttls admin@example.com {\n\t\trenewal_window_ratio 0.1\n\t}\n\trespond \"hi\"\n}\n",
        ),
        (
            format!(
                "{SITE}\n.tls(clientAuth: .requireAndVerify(trust: .files([\"/tmp/clients.pem\"])))"
            ),
            "https://example.test:8443 {\n\ttls {\n\t\tclient_auth {\n\t\t\tmode require_and_verify\n\t\t\ttrust_pool file {\n\t\t\t\tpem_file /tmp/clients.pem\n\t\t\t}\n\t\t}\n\t}\n\trespond \"hi\"\n}\n",
        ),
        (
            format!(
                "{SITE}\n.tls(clientAuth: .request(verifier: .leaf(.files([\"/tmp/client.pem\", \"/tmp/other.pem\"]))))"
            ),
            "https://example.test:8443 {\n\ttls {\n\t\tclient_auth {\n\t\t\tmode request\n\t\t\tverifier leaf file /tmp/client.pem /tmp/other.pem\n\t\t}\n\t}\n\trespond \"hi\"\n}\n",
        ),
        (
            format!(
                "{SITE}\n.tls(.automatic(email: \"admin@example.com\", challenge: .dns(.cloudflare(\"token\"))), resolvers: [\"1.1.1.1\"], dnsTTL: .minutes(2), propagationDelay: .seconds(5), propagationTimeout: .seconds(60), overrideDomain: \"_acme.example.com\")"
            ),
            "https://example.test:8443 {\n\ttls admin@example.com {\n\t\tdns cloudflare token\n\t\tresolvers 1.1.1.1\n\t\tdns_ttl 2m\n\t\tpropagation_delay 5s\n\t\tpropagation_timeout 60s\n\t\tdns_challenge_override_domain _acme.example.com\n\t}\n\trespond \"hi\"\n}\n",
        ),
    ];
    for (native_source, legacy_source) in cases {
        assert_eq!(
            tls_of(&native(&native_source)),
            tls_of(&legacy(legacy_source)),
            "{native_source}"
        );
    }
}

#[test]
fn http3_and_ocsp_lower_like_their_caddyfile_twins() {
    let native_source = "HTTPListener(on: \":8443\") {\n    Site(host: \"example.test\") {\n        Fallback { Respond(body: \"hi\") }\n    }\n    .http3(enabled: false)\n}\n.tls(.internal, ocspStapling: .off)";
    let legacy_source = "{\n\tocsp_stapling off\n}\nhttps://example.test:8443 {\n\ttls internal {\n\t\thttp3 off\n\t}\n\trespond \"hi\"\n}\n";

    let native = native(native_source);
    let legacy = legacy(legacy_source);
    assert_eq!(tls_of(&native), tls_of(&legacy), "{native_source}");
    assert!(native.global.ocsp_stapling_off);
    assert_eq!(
        native.global.ocsp_stapling_off,
        legacy.global.ocsp_stapling_off
    );
}

#[test]
fn a_site_tls_modifier_overrides_its_listener_field_by_field() {
    let config = native(
        "HTTPListener(on: \":8443\") {\n    Site(host: \"example.test\") {\n        Fallback { Respond(body: \"hi\") }\n    }\n    .tls(defaultSNI: \"fallback.test\")\n}\n.tls(.automatic(email: \"admin@example.com\"))",
    );
    let tls = config.servers[0].tls.as_ref().expect("the site keeps TLS");
    assert!(tls.auto);
    assert_eq!(tls.acme_email.as_deref(), Some("admin@example.com"));
    assert_eq!(tls.default_sni.as_deref(), Some("fallback.test"));

    // 🗂️ A site that changes the acquisition mode replaces it wholesale:
    // keeping the listener's ACME account beside manual files would ask for
    // two certificates for one name.
    let replaced = native(
        "HTTPListener(on: \":8443\") {\n    Site(host: \"example.test\") {\n        Fallback { Respond(body: \"hi\") }\n    }\n    .tls(.files(certificate: \"/tmp/c.pem\", key: \"/tmp/k.pem\"))\n}\n.tls(.automatic(email: \"admin@example.com\"))",
    );
    let tls = replaced.servers[0]
        .tls
        .as_ref()
        .expect("the site keeps TLS");
    assert!(!tls.auto);
    assert!(!tls.internal);
    assert_eq!(tls.cert.as_deref(), Some("/tmp/c.pem"));
    assert_eq!(tls.key.as_deref(), Some("/tmp/k.pem"));
    assert_eq!(tls.acme_email, None);
}

#[test]
fn http3_needs_a_tls_site() {
    let error = crate::compile(
        "HTTPListener(on: \":8080\") {\n    Site(host: \"*\") {\n        Fallback { Respond(body: \"hi\") }\n    }\n    .http3(enabled: false)\n}",
    )
    .expect_err("a plaintext site cannot opt out of HTTP/3");
    assert!(
        error
            .to_string()
            .contains("http3 exists only on a TLS site"),
        "{error}"
    );
}

#[test]
fn a_secret_flows_into_dns_arguments_and_nowhere_else() {
    let config = native(&format!(
        "@Secret\nlet token = \"dns-token-sentinel\"\n{SITE}\n.tls(.automatic(email: \"admin@example.com\", challenge: .dns(.cloudflare(token))))"
    ));
    let provider = config.servers[0]
        .tls
        .as_ref()
        .unwrap()
        .dns_challenge
        .as_ref()
        .unwrap()
        .provider
        .as_ref()
        .unwrap();
    assert_eq!(provider.name, "cloudflare");
    assert_eq!(provider.arguments.len(), 1);
    assert_eq!(provider.arguments[0].expose(), "dns-token-sentinel");
    // 🙈 The value reached the configuration because the runtime needs it,
    // and it still does not appear in anything that formats the config.
    assert!(!format!("{:?}", config.servers[0].tls).contains("dns-token-sentinel"));

    // 🚫 Anywhere else the write itself would break the attribute's promise.
    let error = crate::adapt(&format!(
        "@Secret\nlet name = \"secret-default-sni\"\n{SITE}\n.tls(defaultSNI: name)"
    ))
    .expect_err("a secret must not reach defaultSNI");
    assert!(!error.to_string().contains("secret-default-sni"), "{error}");
}

#[test]
fn the_accepted_tls_shapes_compile() {
    for modifier in [
        ".tls(.internal, defaultSNI: \"fallback.test\", ocspStapling: .off)",
        ".tls(.automatic(email: \"admin@example.com\"), renewalWindow: .ratio(0.3333))",
        ".tls(clientAuth: .requireAndVerify(trust: .files([\"/tmp/clients.pem\"])))",
        ".tls(clientAuth: .verifyIfGiven(trust: .system))",
        ".tls(.automatic(email: \"admin@example.com\", challenge: .dns(.cloudflare(\"token\"))), resolvers: [\"1.1.1.1\"], dnsTTL: .seconds(60))",
    ] {
        let source = format!("{SITE}\n{modifier}");
        assert!(crate::compile(&source).is_ok(), "refused {source:?}");
    }
}

#[test]
fn tls_mistakes_fail_closed() {
    for modifier in [
        ".tls()",
        ".tls(defaultSNI: \"a\", defaultSNI: \"b\")",
        ".tls(unknown: \"a\")",
        ".tls(.files(certificate: \"/tmp/c.pem\"))",
        ".tls(.automatic(email: \"a@example.com\"), challenge: .dns(.cloudflare(\"t\")))",
        ".tls(resolvers: [\"1.1.1.1\"])",
        ".tls(.internal, resolvers: [\"1.1.1.1\"])",
        ".tls(renewalWindow: .ratio(1))",
        ".tls(renewalWindow: .ratio(0.0))",
        ".tls(renewalWindow: .ratio(1.0))",
        ".tls(renewalWindow: .ratio(0.5, 0.6))",
        ".tls(renewalWindow: 0.5)",
        ".tls(ocspStapling: .on)",
        ".tls(ocspStapling: true)",
        ".tls(clientAuth: .request(trust: .files([\"/tmp/clients.pem\"])))",
        ".tls(clientAuth: .requireAndVerify(trust: .files([])))",
        ".tls(clientAuth: .requireAndVerify(trust: .combined([])))",
        ".tls(clientAuth: .requireAndVerify(verifier: .leaf(.files([]))))",
        ".tls(clientAuth: .requireAndVerify(verifier: .leaf(.directory(\"\"))))",
        ".tls(clientAuth: .requireAndVerify(verifier: .unknown))",
        ".tls(clientAuth: .requireAndVerify(trust: .pkiRoot))",
        ".tls(.automatic(challenge: .dns))",
    ] {
        let source = format!("{SITE}\n{modifier}");
        assert!(crate::compile(&source).is_err(), "accepted {source:?}");
    }
}

#[test]
fn the_formatter_round_trips_the_new_value_shapes() {
    let source = format!(
        "{SITE}\n.tls(.automatic(email: \"admin@example.com\", challenge: .dns(.cloudflare(\"token\"))), renewalWindow: .ratio(0.1), defaultSNI: \"fallback.test\")\n"
    );
    let formatted = crate::format::format(&source).expect("the source formats");
    assert!(formatted.contains(".ratio(0.1)"), "{formatted}");
    assert!(
        formatted.contains("challenge: .dns(.cloudflare(\"token\"))"),
        "{formatted}"
    );
    assert_eq!(
        crate::format::format(&formatted).expect("idempotent"),
        formatted
    );
}
