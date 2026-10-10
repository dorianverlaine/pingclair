// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🌐 Contract tests for the global declarations: `TrustedProxies`,
//! `BlockedIPs`, `Storage`, `Log` and `AutomaticTLS` — twins for the shared
//! capabilities and native-only refusals for the rest.

use super::*;

fn native(source: &str) -> PingclairConfig {
    crate::adapt(source).expect("the native source adapts")
}

fn legacy(source: &str) -> PingclairConfig {
    crate::adapt(source).expect("the Caddyfile source adapts")
}

/// 🌐 A file may hold nothing but globals: these declarations are options of
/// the server, not of a listener, and that is what makes `adapt` useful for a
/// split configuration.
#[test]
fn trusted_proxies_lowers_like_its_caddyfile_twin() {
    let native = native(
        "TrustedProxies(ranges: [\"10.0.0.0/8\", .privateRanges], headers: [.xForwardedFor, .xRealIP, .cfConnectingIP])\n",
    );
    let legacy = legacy(
        "{\n\ttrusted_proxies static 10.0.0.0/8 private_ranges\n\tclient_ip_headers X-Forwarded-For X-Real-IP CF-Connecting-IP\n}\n",
    );
    assert_eq!(native.global.trusted_proxies, legacy.global.trusted_proxies);
    assert_eq!(
        native.global.client_ip_headers,
        legacy.global.client_ip_headers
    );
    assert_eq!(
        native.global.trusted_proxies,
        std::iter::once("10.0.0.0/8".to_string())
            .chain(PRIVATE_RANGES.iter().map(|range| (*range).to_string()))
            .collect::<Vec<_>>()
    );
}

/// 🛡️ `BlockedIPs([…])` is the native spelling of the shared deny list.
///
/// The list existed in the configuration model and the compiler validated it,
/// but no language could set it until this declaration (pingclair #325); it
/// takes the same values `TrustedProxies(ranges:)` does.
#[test]
fn blocked_ips_are_spellable_and_reach_the_shared_list() {
    let config = native("BlockedIPs([\"192.0.2.0/24\", \"203.0.113.7\", .privateRanges])\n");
    assert_eq!(config.global.blocked_ips[0], "192.0.2.0/24");
    assert_eq!(config.global.blocked_ips[1], "203.0.113.7");
    assert_eq!(
        config.global.blocked_ips.len(),
        2 + PRIVATE_RANGES.len(),
        "`.privateRanges` expands like it does everywhere else"
    );

    let listener = r#"BlockedIPs(["192.0.2.0/24"])
HTTPListener(on: ":8080") {
    Site(host: "*") { Fallback { Respond(body: "hi") } }
}"#;
    assert!(crate::compile(listener).is_ok());
}

#[test]
fn blocked_ips_mistakes_fail_closed() {
    let listener = r#"
        HTTPListener(on: ":8080") {
            Site(host: "*") { Fallback { Respond(body: "hi") } }
        }
    "#;
    for declaration in [
        "BlockedIPs([])",
        "BlockedIPs(\"192.0.2.1\")",
        "BlockedIPs([\"nope\"])",
        "BlockedIPs([\"192.0.2.1\"], [\"203.0.113.7\"])",
        "BlockedIPs(ips: [\"192.0.2.1\"])",
        "BlockedIPs([\"192.0.2.1\"]) { }",
        "BlockedIPs([\"192.0.2.1\"]).unknown(1)",
    ] {
        assert!(
            crate::compile(&format!("{declaration}\n{listener}")).is_err(),
            "accepted {declaration}"
        );
    }
    // 📍 The entry is refused where it was written, not at startup.
    let error = crate::adapt("BlockedIPs([\"192.0.2.0/24\", \"nope\"])")
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("contains invalid IP or CIDR `nope`"),
        "{error}"
    );
}

#[test]
fn storage_log_and_automatic_tls_lower_like_their_caddyfile_twins() {
    let native = native(
        "Storage(root: \"/var/lib/pingclair\")\nLog(output: .file(\"/var/log/pingclair/run.log\"), level: .debug)\nAutomaticTLS(mode: .off, httpPort: 8080, httpsPort: 8443, skipInstallTrust: true)\n",
    );
    let legacy = legacy(
        "{\n\tstorage file_system /var/lib/pingclair\n\tlog {\n\t\toutput file /var/log/pingclair/run.log\n\t\tlevel debug\n\t}\n\tauto_https off\n\thttp_port 8080\n\thttps_port 8443\n\tskip_install_trust\n}\n",
    );
    assert_eq!(native.global.storage_path, legacy.global.storage_path);
    assert_eq!(native.logging.default, legacy.logging.default);
    assert_eq!(native.global.auto_https, legacy.global.auto_https);
    assert_eq!(native.global.http_port, legacy.global.http_port);
    assert_eq!(native.global.https_port, legacy.global.https_port);
    assert_eq!(
        native.global.skip_install_trust,
        legacy.global.skip_install_trust
    );
}

#[test]
fn one_trusted_header_escape_hatch_names_any_header() {
    let config = native("TrustedProxies(headers: [.header(\"X-Custom-Client\")])\n");
    assert_eq!(config.global.client_ip_headers, ["X-Custom-Client"]);
    // 🛡️ With no ranges the list is a policy about *names*, not about who is
    // believed: the runtime still trusts nobody until `ranges:` says so.
    assert!(config.global.trusted_proxies.is_empty());
}

#[test]
fn the_accepted_global_shapes_compile() {
    for source in [
        "TrustedProxies(ranges: [\"10.0.0.0/8\"])\n",
        "TrustedProxies(headers: [.forwarded])\n",
        "Storage(root: \"/var/lib/pingclair\")\n",
        "Log(output: .stderr)\n",
        "Log(level: .info)\n",
        "AutomaticTLS(mode: .automatic)\n",
        "AutomaticTLS(httpPort: 80, httpsPort: 443)\n",
        "AutomaticTLS(skipInstallTrust: true)\n",
    ] {
        assert!(crate::compile(source).is_ok(), "refused {source:?}");
    }
}

#[test]
fn the_globals_refuse_what_they_cannot_mean() {
    for source in [
        "TrustedProxies()\n",
        "TrustedProxies(ranges: [])\n",
        "TrustedProxies(ranges: [\"not-a-network\"])\n",
        "TrustedProxies(ranges: [.unknown])\n",
        "TrustedProxies(headers: [])\n",
        "TrustedProxies(headers: [.unknown])\n",
        "TrustedProxies(headers: [.header(\"not a header\")])\n",
        "TrustedProxies(ranges: \"10.0.0.0/8\")\n",
        "Storage(root: \"\")\n",
        "Log()\n",
        "Log(output: .socket)\n",
        "Log(output: .file(\"\"))\n",
        "Log(level: .verbose)\n",
        "AutomaticTLS()\n",
        "AutomaticTLS(mode: .on)\n",
        "AutomaticTLS(mode: .disableCerts)\n",
        "AutomaticTLS(httpPort: 0)\n",
        "AutomaticTLS(httpsPort: 70000)\n",
        "AutomaticTLS(skipInstallTrust: false)\n",
    ] {
        assert!(crate::compile(source).is_err(), "accepted {source:?}");
    }
}

#[test]
fn a_second_declaration_in_one_file_is_refused() {
    let error = crate::compile("Storage(root: \"/a\")\nStorage(root: \"/b\")\n")
        .expect_err("a second declaration of one global is a mistake, not a merge");
    assert!(error.to_string().contains("duplicate"), "{error}");
}
