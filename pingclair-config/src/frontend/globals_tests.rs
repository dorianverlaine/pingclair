// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🌐 Contract tests for the global declarations: `TrustedProxies`, `Storage`,
//! `Log` and `AutomaticTLS` — Caddyfile twins for the shared capabilities and
//! native-only refusals.

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
