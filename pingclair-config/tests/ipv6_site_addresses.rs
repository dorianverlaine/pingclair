// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🌐 Bracketed IPv6 site addresses (RFC 3986 §3.2.2).
//!
//! An IPv6 literal carries its own colons, so only the brackets say where the
//! host ends and the port begins. `http://[::1]` used to be split on its last
//! colon — inside the brackets — and parsed to nothing, which made the block the
//! unnamed catch-all for every `Host` on the port, with no listener and, for
//! `https://`, no TLS (pingclair#267).

use pingclair_config::compile;

/// 🧾 The first compiled site of a one-site configuration.
fn first_server(source: &str) -> pingclair_core::config::ServerConfig {
    compile(source)
        .expect("config must compile")
        .servers
        .into_iter()
        .next()
        .expect("at least one server")
}

/// 🌐 A bracketed IPv6 site address without a port keeps its name, takes its
/// scheme's global port, and keeps TLS — exactly as an IPv4 literal does.
#[test]
fn bracketed_ipv6_without_a_port_is_named_like_an_ipv4_literal() {
    let shape = |address: &str| {
        let server = first_server(&format!(
            "{{\n http_port 8080\n https_port 8443\n}}\n{address} {{\n respond \"x\"\n}}"
        ));
        (
            server.name,
            server.names,
            server.listen,
            server.tls.is_some(),
        )
    };
    let cases = [
        ("http://[::1]", ("[::1]", "[::1]:8080", false)),
        ("https://[::1]", ("[::1]", "[::1]:8443", true)),
        ("[::1]", ("[::1]", "[::1]:8080", true)),
        ("http://[::1]:9090", ("[::1]", "[::1]:9090", false)),
        ("https://[::1]:9443", ("[::1]", "[::1]:9443", true)),
        ("http://127.0.0.1", ("127.0.0.1", "127.0.0.1:8080", false)),
        ("https://127.0.0.1", ("127.0.0.1", "127.0.0.1:8443", true)),
        ("127.0.0.1", ("127.0.0.1", "127.0.0.1:8080", true)),
    ];
    let got: Vec<_> = cases.iter().map(|(address, _)| shape(address)).collect();
    let expected: Vec<_> = cases
        .iter()
        .map(|(_, (name, listen, tls))| {
            (
                Some(name.to_string()),
                vec![name.to_string()],
                vec![listen.to_string()],
                *tls,
            )
        })
        .collect();
    assert_eq!(got, expected);
}

/// 🚫 A bracket that does not hold an IPv6 address, or is followed by anything
/// but `:port`, is refused rather than parsed to nothing — which is what made a
/// site the catch-all for every `Host`.
#[test]
fn malformed_bracketed_addresses_are_refused() {
    for address in [
        "http://[::1]x",
        "http://[::1",
        "http://[example.com]",
        "[nope]:80",
    ] {
        let error = compile(&format!("{address} {{\n respond \"x\"\n}}"))
            .expect_err(address)
            .to_string();
        assert!(error.contains("bracketed IPv6"), "{address}: {error}");
    }
}
