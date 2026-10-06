// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🛡️ A client behind a trusted proxy is named by the forwarding headers, and a
//! client anywhere else cannot name itself.

use super::trusted_proxy::{MAX_FORWARDED_HOPS, is_undisclosed_node};
use super::*;

#[test]
fn untrusted_peer_cannot_spoof_forwarded_identity() {
    let proxy = PingclairProxy::new();
    let peer = "198.51.100.4".parse().unwrap();
    let mut headers = http::HeaderMap::new();
    headers.insert("x-forwarded-for", "203.0.113.7".parse().unwrap());
    headers.insert("x-real-ip", "203.0.113.8".parse().unwrap());

    assert_eq!(proxy.verified_client_ip(peer, &headers), peer);
    assert_eq!(proxy.forwarded_for(peer, &headers), "198.51.100.4");
}

#[test]
fn untrusted_peer_cannot_spoof_rfc_forwarded_identity() {
    let proxy = PingclairProxy::new();
    let peer = "198.51.100.4".parse().unwrap();
    let mut headers = http::HeaderMap::new();
    headers.insert("forwarded", "for=203.0.113.7;proto=https".parse().unwrap());

    assert_eq!(proxy.verified_client_ip(peer, &headers), peer);
}

#[test]
fn conflicting_xff_and_rfc_forwarded_fail_closed_to_peer() {
    let proxy = PingclairProxy::with_trusted_proxies(&["10.0.0.0/8".to_string()]);
    let peer = "10.0.0.5".parse().unwrap();
    let mut headers = http::HeaderMap::new();
    headers.insert("x-forwarded-for", "203.0.113.7".parse().unwrap());
    headers.insert("forwarded", "for=198.51.100.9".parse().unwrap());

    assert_eq!(proxy.verified_client_ip(peer, &headers), peer);
}

#[test]
fn trusted_rfc_forwarded_chain_supports_quoted_ipv6_and_ports() {
    let proxy = PingclairProxy::with_trusted_proxies(&[
        "10.0.0.0/8".to_string(),
        "2001:db8:ffff::/48".to_string(),
    ]);
    let peer = "10.0.0.5".parse().unwrap();
    let mut headers = http::HeaderMap::new();
    headers.insert(
        "forwarded",
        "for=\"[2001:db8::7]:4567\";proto=https, for=\"[2001:db8:ffff::1]\""
            .parse()
            .unwrap(),
    );

    assert_eq!(
        proxy.verified_client_ip(peer, &headers),
        "2001:db8::7".parse::<IpAddr>().unwrap()
    );
}

/// 🧹 RFC 9110 §5.6.1.2: a recipient must ignore empty list elements, so
/// a merge mistake in either header does not cost the client identity.
#[test]
fn empty_list_elements_are_skipped_in_both_headers() {
    let proxy = PingclairProxy::with_trusted_proxies(&["10.0.0.0/8".to_string()]);
    let peer: IpAddr = "10.0.0.5".parse().unwrap();
    let client: IpAddr = "203.0.113.7".parse().unwrap();
    for (name, value) in [
        ("x-forwarded-for", "203.0.113.7,"),
        ("x-forwarded-for", ", 203.0.113.7, , 10.1.2.3"),
        ("forwarded", "for=203.0.113.7,"),
        ("forwarded", ",for=203.0.113.7;;proto=https, ,for=10.1.2.3"),
    ] {
        let mut headers = http::HeaderMap::new();
        headers.insert(name, value.parse().unwrap());
        assert_eq!(
            proxy.verified_client_ip(peer, &headers),
            client,
            "{name}: {value}"
        );
    }
}

/// 🙈 RFC 7239 §6 nodes that name no address are recognised, and only
/// those: any other non-address `for=` value is still malformed.
#[test]
fn undisclosed_nodes_follow_the_rfc_7239_grammar() {
    let accepted: Vec<bool> = [
        "unknown",
        "UNKNOWN",
        "_hidden",
        "_a.b-c_d",
        "_hidden:_port",
        "unknown:8080",
        "_",
        "hidden",
        "_bad!",
        "_hidden:",
        "unknown:123456",
        "",
    ]
    .iter()
    .map(|node| is_undisclosed_node(node))
    .collect();
    assert_eq!(
        accepted,
        [
            true, true, true, true, true, true, false, false, false, false, false, false
        ]
    );
}

/// 🛡️ The empty-element allowance is bounded, so a field of nothing but
/// commas is malformed rather than walked at any length.
#[test]
fn a_field_of_only_commas_fails_closed() {
    let proxy = PingclairProxy::with_trusted_proxies(&["10.0.0.0/8".to_string()]);
    let peer: IpAddr = "10.0.0.5".parse().unwrap();
    let commas = format!("203.0.113.7{}", ",".repeat(MAX_FORWARDED_HOPS + 1));
    for name in ["x-forwarded-for", "forwarded"] {
        let mut headers = http::HeaderMap::new();
        let value = if name == "forwarded" {
            format!("for={commas}")
        } else {
            commas.clone()
        };
        headers.insert(name, value.parse().unwrap());
        assert_eq!(proxy.verified_client_ip(peer, &headers), peer, "{name}");
    }
}

// ---- CF-Connecting-IP (Cloudflare Tunnel deployments) ----

/// The security boundary: an untrusted client sending CF-Connecting-IP
/// must be ignored entirely. If this ever regresses, any client on the
/// internet can forge its own identity for access control, rate limits
/// and logs.
#[test]
fn untrusted_peer_cannot_spoof_cf_connecting_ip() {
    let proxy = PingclairProxy::new();
    let peer: IpAddr = "198.51.100.4".parse().unwrap();
    let mut headers = http::HeaderMap::new();
    headers.insert("cf-connecting-ip", "203.0.113.7".parse().unwrap());

    assert_eq!(
        proxy.verified_client_ip(peer, &headers),
        peer,
        "untrusted CF-Connecting-IP must be ignored"
    );
}

/// 🛡️ A trusted peer is not necessarily Cloudflare, so by default the
/// header names nobody: the peer is the client unless a chain says otherwise.
#[test]
fn trusted_peer_cf_connecting_ip_is_ignored_unless_configured() {
    let proxy = PingclairProxy::with_trusted_proxies(&["10.0.0.0/8".to_string()]);
    let peer: IpAddr = "10.0.0.5".parse().unwrap();
    let mut headers = http::HeaderMap::new();
    headers.insert("cf-connecting-ip", "203.0.113.7".parse().unwrap());
    assert_eq!(proxy.verified_client_ip(peer, &headers), peer);

    headers.insert("x-forwarded-for", "198.51.100.9".parse().unwrap());
    assert_eq!(
        proxy.verified_client_ip(peer, &headers),
        "198.51.100.9".parse::<IpAddr>().unwrap()
    );
}

/// ☁️ Listed headers are the only sources, consulted in the listed order.
#[test]
fn configured_client_ip_headers_decide_in_order() {
    let proxy = PingclairProxy::with_trusted_proxies(&["10.0.0.0/8".to_string()])
        .reading_client_ip_from(&["CF-Connecting-IP".into(), "X-Forwarded-For".into()]);
    let peer: IpAddr = "10.0.0.5".parse().unwrap();
    let resolve = |pairs: &[(&'static str, &'static str)]| {
        let mut headers = http::HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(*name, value.parse().unwrap());
        }
        proxy.verified_client_ip(peer, &headers).to_string()
    };

    assert_eq!(
        [
            // ☁️ The first listed header wins over the second.
            resolve(&[
                ("cf-connecting-ip", "203.0.113.7"),
                ("x-forwarded-for", "198.51.100.9, 10.1.2.3"),
            ]),
            // 🔁 A malformed first header passes to the next one.
            resolve(&[
                ("cf-connecting-ip", "not-an-ip"),
                ("x-forwarded-for", "198.51.100.9"),
            ]),
            // 🚫 An unlisted header is not a source, even as a fallback.
            resolve(&[("x-real-ip", "198.51.100.10")]),
            resolve(&[("cf-connecting-ip", "2001:db8::1")]),
        ],
        [
            "203.0.113.7".to_string(),
            "198.51.100.9".to_string(),
            "10.0.0.5".to_string(),
            "2001:db8::1".to_string(),
        ]
    );
}

#[test]
fn trusted_peer_walks_the_chain_from_right_to_left() {
    let proxy = PingclairProxy::with_trusted_proxies(&["10.0.0.0/8".to_string()]);
    let peer = "10.0.0.5".parse().unwrap();
    let mut headers = http::HeaderMap::new();
    headers.insert("x-forwarded-for", "203.0.113.7, 10.1.2.3".parse().unwrap());

    assert_eq!(
        proxy.verified_client_ip(peer, &headers),
        "203.0.113.7".parse::<IpAddr>().unwrap()
    );
    assert_eq!(
        proxy.forwarded_for(peer, &headers),
        "203.0.113.7, 10.1.2.3, 10.0.0.5"
    );
}

#[test]
fn trusted_peer_uses_x_real_ip_only_when_xff_is_absent() {
    let proxy = PingclairProxy::with_trusted_proxies(&["127.0.0.1".to_string()]);
    let peer = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
    let mut headers = http::HeaderMap::new();
    headers.insert("x-real-ip", "203.0.113.9".parse().unwrap());

    assert_eq!(
        proxy.verified_client_ip(peer, &headers),
        "203.0.113.9".parse::<IpAddr>().unwrap()
    );
    assert_eq!(
        proxy.forwarded_for(peer, &headers),
        "203.0.113.9, 127.0.0.1"
    );
}

#[test]
fn malformed_or_oversized_chain_fails_closed_to_peer() {
    let proxy = PingclairProxy::with_trusted_proxies(&["127.0.0.1".to_string()]);
    let peer = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
    let mut malformed = http::HeaderMap::new();
    malformed.insert(
        "x-forwarded-for",
        "203.0.113.7, definitely-not-an-ip".parse().unwrap(),
    );
    assert_eq!(proxy.verified_client_ip(peer, &malformed), peer);
    assert_eq!(proxy.forwarded_for(peer, &malformed), "127.0.0.1");

    let mut oversized = http::HeaderMap::new();
    oversized.insert(
        "x-forwarded-for",
        std::iter::repeat_n("203.0.113.7", MAX_FORWARDED_HOPS + 1)
            .collect::<Vec<_>>()
            .join(", ")
            .parse()
            .unwrap(),
    );
    assert_eq!(proxy.verified_client_ip(peer, &oversized), peer);
}
