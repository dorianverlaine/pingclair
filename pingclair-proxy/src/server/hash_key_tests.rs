// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧮 Load-balancer hash keys are read whole and exactly from the named header,
//! cookie or query parameter.

use super::*;

fn request(build: impl FnOnce(&mut RequestHeader)) -> RequestHeader {
    let mut header = RequestHeader::build("GET", b"/shop?sid=abc&other=1", None).unwrap();
    build(&mut header);
    header
}

#[test]
fn a_header_key_is_read_from_the_named_field() {
    let header = request(|h| h.insert_header("X-Session", "s-42").unwrap());
    let key = extract_hash_key(&header, &HashKeySource::Header("X-Session".into()));
    assert_eq!(key.as_deref(), Some(&b"s-42"[..]));
}

/// 🍪 Session identifiers are routinely base64, which contains `=` padding.
/// Splitting on every `=` instead of the first would truncate the value and
/// send the same client to different backends as the padding changed.
#[test]
fn a_cookie_value_keeps_its_own_equals_signs() {
    let header = request(|h| {
        h.insert_header("Cookie", "theme=dark; sid=YWJjZA==; other=1")
            .unwrap()
    });
    let key = extract_hash_key(&header, &HashKeySource::Cookie("sid".into()));
    assert_eq!(key.as_deref(), Some(&b"YWJjZA=="[..]));
}

/// 🎯 A repeated cookie name picks the same value whatever the order, and
/// a cookie on a later `Cookie` line is still seen.
#[test]
fn a_repeated_cookie_name_is_resolved_independent_of_order() {
    let forward = request(|h| h.insert_header("Cookie", "sid=beta; sid=alpha").unwrap());
    let reverse = request(|h| h.insert_header("Cookie", "sid=alpha; sid=beta").unwrap());
    let split = request(|h| {
        h.append_header("Cookie", "theme=dark").unwrap();
        h.append_header("Cookie", "sid=beta").unwrap();
        h.append_header("Cookie", "sid=alpha").unwrap();
    });
    let source = HashKeySource::Cookie("sid".into());
    let keys = [&forward, &reverse, &split].map(|header| extract_hash_key(header, &source));
    assert_eq!(
        keys,
        [
            Some(b"alpha".to_vec()),
            Some(b"alpha".to_vec()),
            Some(b"alpha".to_vec())
        ]
    );
}

#[test]
fn a_cookie_name_is_matched_whole_not_by_prefix() {
    let header = request(|h| h.insert_header("Cookie", "sidecar=no; sid=yes").unwrap());
    let key = extract_hash_key(&header, &HashKeySource::Cookie("sid".into()));
    assert_eq!(
        key.as_deref(),
        Some(&b"yes"[..]),
        "`sidecar` must not satisfy a request for `sid`"
    );
}

#[test]
fn a_query_key_is_read_from_the_query_string() {
    let header = request(|_| {});
    let key = extract_hash_key(&header, &HashKeySource::Query("sid".into()));
    assert_eq!(key.as_deref(), Some(&b"abc"[..]));
}

/// 🚫 A missing or empty value must not hash — it must fall back.
///
/// Hashing `""` would map every client that omits the field onto the same
/// backend. That is a hot spot which looks like a load-balancer defect and
/// is really a configuration one, so it is worth its own test rather than
/// being left to the reader of `extract_hash_key`.
#[test]
fn an_absent_or_empty_value_yields_no_key() {
    let missing = request(|_| {});
    assert_eq!(
        extract_hash_key(&missing, &HashKeySource::Header("X-Session".into())),
        None
    );

    let empty = request(|h| h.insert_header("X-Session", "").unwrap());
    assert_eq!(
        extract_hash_key(&empty, &HashKeySource::Header("X-Session".into())),
        None,
        "an empty value is the same hot spot as an absent one"
    );

    let empty_cookie = request(|h| h.insert_header("Cookie", "sid=").unwrap());
    assert_eq!(
        extract_hash_key(&empty_cookie, &HashKeySource::Cookie("sid".into())),
        None
    );
}
