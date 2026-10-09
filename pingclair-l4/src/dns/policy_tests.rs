// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

use super::*;

#[test]
fn special_purpose_addresses_and_global_exceptions_are_classified() {
    let policy = Policy::prepare(None, &[]).unwrap();
    for (ip, allowed) in [
        ("8.8.8.8", true),
        ("1.1.1.1", true),
        ("192.0.0.9", true),
        ("192.0.0.10", true),
        ("192.31.196.1", true),
        ("192.52.193.1", true),
        ("192.175.48.1", true),
        ("2001:4860:4860::8888", true),
        ("2001:1::1", true),
        ("2001:1::3", true),
        ("2001:3::1", true),
        ("2001:4:112::1", true),
        ("2001:20::1", true),
        ("2001:30::1", true),
        ("64:ff9b::808:808", true),
        ("2620:4f:8000::1", true),
        ("0.0.0.0", false),
        ("0.1.2.3", false),
        ("10.0.0.1", false),
        ("100.64.0.1", false),
        ("127.0.0.1", false),
        ("169.254.1.1", false),
        ("172.16.0.1", false),
        ("192.0.0.8", false),
        ("192.0.2.1", false),
        ("192.88.99.1", false),
        ("192.168.1.1", false),
        ("198.18.0.1", false),
        ("198.51.100.1", false),
        ("203.0.113.1", false),
        ("224.0.0.1", false),
        ("240.0.0.1", false),
        ("255.255.255.255", false),
        ("::", false),
        ("::1", false),
        ("64:ff9b:1::1", false),
        ("100::1", false),
        ("100:0:0:1::1", false),
        ("2001::1", false),
        ("2001:2::1", false),
        ("2001:10::1", false),
        ("2001:db8::1", false),
        ("2002::1", false),
        ("3fff::1", false),
        ("5f00::1", false),
        ("fc00::1", false),
        ("fe80::1", false),
        ("ff02::1", false),
        ("::ffff:127.0.0.1", false),
        ("::ffff:8.8.8.8", true),
    ] {
        assert_eq!(
            policy.permits(SocketAddr::new(ip.parse().unwrap(), 443)),
            allowed,
            "{ip}"
        );
    }
}

#[test]
fn explicit_allowances_cannot_override_hard_denials_or_broaden_sensitive_classes() {
    let allow = [
        "127.0.0.0/8",
        "169.254.0.0/16",
        "10.0.0.0/8",
        "::1/128",
        "fe80::/10",
        "0.0.0.0/32",
        "224.0.0.0/4",
        "::/128",
        "ff00::/8",
    ]
    .map(str::to_owned);
    let own = [
        "0.0.0.0:443",
        "10.0.0.1:2019",
        "[::]:8443",
        "[2001:4860::1]:443",
    ]
    .map(|address| address.parse().unwrap());
    let policy = Policy::prepare(Some(&allow), &own).unwrap();
    for (address, allowed) in [
        ("127.0.0.1:443", false),
        ("127.0.0.1:444", true),
        ("[::ffff:127.0.0.1]:443", false),
        ("[::ffff:127.0.0.1]:444", true),
        ("169.254.1.1:443", true),
        ("10.0.0.1:2019", false),
        ("10.0.0.2:2019", true),
        ("[::1]:8443", false),
        ("[2001:4860::1]:443", false),
        ("[2001:4860::2]:443", true),
        ("8.8.8.8:443", true),
        ("0.0.0.0:53", false),
        ("224.0.0.1:53", false),
        ("[::]:53", false),
        ("[ff02::1]:53", false),
    ] {
        assert_eq!(
            policy.permits(address.parse().unwrap()),
            allowed,
            "{address}"
        );
    }
    for range in [
        "0.0.0.0/0",
        "::/0",
        "::ffff:0:0/96",
        "::fffe:0:0/95",
        "fe00::/8",
    ] {
        assert!(
            Policy::prepare(Some(&[range.into()]), &[]).is_err(),
            "{range}"
        );
    }
    let policy = Policy::prepare(Some(&["::ffff:127.0.0.1/128".into()]), &[]).unwrap();
    assert!(policy.permits("127.0.0.1:53".parse().unwrap()));
    assert!(policy.permits("[::ffff:127.0.0.1]:53".parse().unwrap()));
}
