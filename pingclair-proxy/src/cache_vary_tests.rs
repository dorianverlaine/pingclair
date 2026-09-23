// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧪 Variant keys preserve complete field values and stable name sets.

use super::*;
use http::HeaderValue;

fn headers(name: &'static str, values: &[&str]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for value in values {
        headers.append(name, HeaderValue::from_str(value).unwrap());
    }
    headers
}

#[test]
fn response_field_order_case_and_duplicates_do_not_change_the_key() {
    let request = headers("accept-language", &["en", "fr"]);
    let split = headers(
        "vary",
        &["Accept-Encoding", "Accept-Language, ACCEPT-ENCODING"],
    );
    let merged = headers("vary", &["accept-language, accept-encoding"]);
    assert_eq!(variance(&split, &request), variance(&merged, &request));
    assert_ne!(
        variance(&split, &request),
        variance(&headers("vary", &["Accept-Encoding"]), &request)
    );
}

#[test]
fn request_field_sequences_have_distinct_keys() {
    let response = headers("vary", &["x-variant"]);
    let variants: &[&[&str]] = &[
        &[],
        &[""],
        &["en"],
        &["en", "fr"],
        &["en", "de"],
        &["fr", "en"],
        &["ab", "c"],
        &["a", "bc"],
        &["en,fr"],
        &["en", "", "fr"],
    ];
    let keys: Vec<_> = variants
        .iter()
        .map(|values| variance(&response, &headers("x-variant", values)).unwrap())
        .collect();
    for (index, key) in keys.iter().enumerate() {
        assert!(
            !keys[..index].contains(key),
            "variant {index} collapsed into a different field sequence"
        );
    }
}

#[test]
fn non_ascii_request_values_remain_part_of_the_key() {
    let response = headers("vary", &["x-variant"]);
    let mut request = headers("x-variant", &["first"]);
    let first = variance(&response, &request);
    request.append("x-variant", HeaderValue::from_bytes(b"\xff").unwrap());
    assert_ne!(variance(&response, &request), first);
}

#[test]
fn every_invalid_nomination_refuses_storage() {
    for value in [&b"*"[..], &b"bad name"[..], &b"\xff"[..]] {
        let mut response = pingora_http::ResponseHeader::build(200, None).unwrap();
        response.append_header("vary", "Accept-Encoding").unwrap();
        response
            .append_header("vary", HeaderValue::from_bytes(value).unwrap())
            .unwrap();
        assert!(crate::cache_policy::uncacheable_response_reason(&response).is_some());
    }
}
