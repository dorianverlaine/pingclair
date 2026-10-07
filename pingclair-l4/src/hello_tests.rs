// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

use super::*;
use proptest::prelude::*;

fn extension(kind: u16, body: &[u8]) -> Vec<u8> {
    let mut output = kind.to_be_bytes().to_vec();
    output.extend_from_slice(&(body.len() as u16).to_be_bytes());
    output.extend_from_slice(body);
    output
}

fn handshake(extensions: &[u8]) -> Vec<u8> {
    let mut body = vec![3, 3];
    body.extend_from_slice(&[7; 32]);
    body.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0]);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(extensions);
    let mut handshake = vec![1, 0];
    handshake.extend_from_slice(&(body.len() as u16).to_be_bytes());
    handshake.extend(body);
    handshake
}

fn example() -> Vec<u8> {
    let name = b"Example.test";
    let mut sni = ((name.len() + 3) as u16).to_be_bytes().to_vec();
    sni.push(0);
    sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
    sni.extend_from_slice(name);
    let mut extensions = extension(0, &sni);
    extensions.extend(extension(16, b"\x00\x0c\x02h2\x08http/1.1"));
    handshake(&extensions)
}

fn records(parts: &[&[u8]]) -> Vec<u8> {
    let mut wire = Vec::new();
    for part in parts {
        wire.extend_from_slice(&[22, 3, 1]);
        wire.extend_from_slice(&(part.len() as u16).to_be_bytes());
        wire.extend_from_slice(part);
    }
    wire
}

fn assert_metadata(wire: &[u8]) {
    let Classification::Tls(hello) = classify(wire) else {
        panic!("incomplete: {wire:?}");
    };
    assert!(hello.matches_sni("example.TEST"));
    assert!(!hello.matches_sni("example.test.evil"));
    assert!(hello.offers_alpn("h2"));
    assert!(hello.offers_alpn("http/1.1"));
    assert!(!hello.offers_alpn("h"));
    assert!(!hello.offers_alpn("H2"));
}

#[test]
fn every_record_and_transport_split_preserves_metadata() {
    let hello = example();
    for split in 0..=hello.len() {
        let wire = records(&[&hello[..split], &hello[split..]]);
        assert_metadata(&wire);
        for prefix in 0..wire.len() {
            match classify(&wire[..prefix]) {
                Classification::NeedMore(n) => assert!(n > prefix),
                // 📦 A trailing empty record need not arrive to complete the hello.
                Classification::Tls(_) => assert_eq!(split, hello.len()),
                Classification::NotTls => panic!("declined prefix {prefix} / {split}"),
            }
        }
    }
    let parts: Vec<_> = hello.chunks(1).collect();
    assert_metadata(&records(&parts));
}

#[test]
fn no_sni_is_tls_and_trailing_application_bytes_are_ignored() {
    let mut wire = records(&[&handshake(&[])]);
    wire.extend_from_slice(b"application data is not another ClientHello");
    let Classification::Tls(hello) = classify(&wire) else {
        panic!("expected TLS");
    };
    assert!(!hello.matches_sni(""));
    assert!(!hello.offers_alpn("h2"));
}

#[test]
fn malformed_extensions_never_publish_partial_sni() {
    let hello = example();
    let extensions = &hello[47..];
    let mut duplicate = extensions.to_vec();
    duplicate.extend_from_slice(extensions);
    for malformed in [duplicate, vec![0, 16, 0, 3, 0, 1, 0], vec![0, 0, 255, 255]] {
        assert!(matches!(
            classify(&records(&[&handshake(&malformed)])),
            Classification::NotTls
        ));
    }
    let mut broken = hello;
    *broken.last_mut().unwrap() = 0;
    // 🧪 A length error after a valid SNI must discard the earlier metadata.
    broken.push(0);
    let length = broken.len() - 4;
    broken[2..4].copy_from_slice(&(length as u16).to_be_bytes());
    assert!(matches!(
        classify(&records(&[&broken])),
        Classification::NotTls
    ));
}

#[test]
fn non_handshake_and_non_tls_records_decline() {
    for bytes in [
        b"GET / HTTP/1.0".as_slice(),
        &[22, 2, 0, 0, 1, 1],
        &[22, 3, 0, 0, 1, 2],
    ] {
        assert!(matches!(classify(bytes), Classification::NotTls));
    }
}

proptest! {
    #[test]
    fn arbitrary_bytes_never_panic_and_more_always_advances(wire in prop::collection::vec(any::<u8>(), 0..20_000)) {
        if let Classification::NeedMore(n) = classify(&wire) { prop_assert!(n > wire.len()); }
    }

    #[test]
    fn arbitrary_fragmentation_keeps_valid_metadata(chunk in 1usize..100) {
        let hello = example();
        let parts: Vec<_> = hello.chunks(chunk).collect();
        assert_metadata(&records(&parts));
    }
}
