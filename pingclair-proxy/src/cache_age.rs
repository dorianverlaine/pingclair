// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! ⏳ RFC 9111 age travels with an entry through storage and revalidation.

use pingora_cache::{
    CacheMeta, NoCacheReason, RespCacheable,
    cache_control::{CacheControl, InterpretCacheControl},
    filters,
};
use pingora_http::ResponseHeader;
use std::time::{Duration, SystemTime};

/// 🔁 Keeps the current 304 clock fields that Pingora's merge omits.
pub(crate) struct RevalidationHeaders {
    age: Option<http::HeaderValue>,
    date: Option<http::HeaderValue>,
}

impl RevalidationHeaders {
    pub(crate) fn from_response(response: &ResponseHeader) -> Self {
        Self {
            age: response.headers.get("age").cloned(),
            date: response.headers.get("date").cloned(),
        }
    }

    pub(crate) fn apply(&self, response: &ResponseHeader) -> ResponseHeader {
        let mut corrected = response.clone();
        self.apply_to(&mut corrected);
        corrected
    }

    pub(crate) fn apply_to(&self, response: &mut ResponseHeader) {
        // ⏳ A successful validation must not inherit the previous response's clock.
        for (name, value) in [("age", &self.age), ("date", &self.date)] {
            response.remove_header(name);
            if let Some(value) = value {
                response
                    .insert_header(name, value.clone())
                    .expect("a received header is valid");
            }
        }
    }
}

fn date(response: &ResponseHeader) -> Option<SystemTime> {
    let mut dates = response.headers.get_all("date").iter();
    let first = dates.next()?;
    if dates.next().is_some() {
        return None;
    }
    httpdate::parse_http_date(first.to_str().ok()?).ok()
}

fn initial_age(response: &ResponseHeader, response_time: SystemTime, delay: Duration) -> Duration {
    // ⏳ RFC 9111 §1.2.2 requires saturated delta-seconds rather than overflow.
    let age = response.headers.get("age").map_or(0, |value| {
        if value.as_bytes().is_empty() || !value.as_bytes().iter().all(u8::is_ascii_digit) {
            return 0;
        }
        value.as_bytes().iter().fold(0u64, |age, digit| {
            (age.saturating_mul(10)
                .saturating_add(u64::from(digit - b'0')))
            .min(1 << 31)
        })
    });
    let apparent = date(response)
        .and_then(|date| response_time.duration_since(date).ok())
        .unwrap_or_default();
    apparent.max(Duration::from_secs(age).saturating_add(delay))
}

/// ⏳ Moves expiry and the Age reference back by time already spent upstream.
/// 🔐 Sanitized stored headers stay in metadata; raw headers only supply age and lifetime.
pub(crate) fn account(
    mut meta: CacheMeta,
    response: &ResponseHeader,
    cache_control: Option<&CacheControl>,
    lifetime: Duration,
    delay: Duration,
) -> RespCacheable {
    let received = meta.created();
    let age = initial_age(response, received, delay);
    // 🧮 Pingora's metadata serializer cannot retain a clock before the Unix epoch.
    let Some(epoch) = received
        .checked_sub(age)
        .filter(|epoch| epoch.duration_since(SystemTime::UNIX_EPOCH).is_ok())
    else {
        return RespCacheable::Uncacheable(NoCacheReason::Custom(
            "upstream age exceeds the serializable cache clock",
        ));
    };
    // 📜 Expires is a lifetime relative to Date, not a new countdown from receipt.
    let lifetime = if cache_control
        .and_then(InterpretCacheControl::fresh_duration)
        .is_none()
    {
        filters::calculate_expires_header_time(response)
            .map(|expires| {
                expires
                    .duration_since(date(response).unwrap_or(received))
                    .unwrap_or_default()
            })
            .unwrap_or(lifetime)
    } else {
        lifetime
    };
    let fresh_until = if lifetime.is_zero() {
        received - Duration::from_secs(1)
    } else {
        epoch.checked_add(lifetime).unwrap_or(received)
    };
    meta.update_freshness(
        fresh_until,
        meta.stale_while_revalidate_sec(),
        meta.stale_if_error_sec(),
    );
    // 🏷️ Pingora computes hit Age from this serialized epoch, including after a 304.
    meta.set_epoch_override(epoch);
    RespCacheable::Cacheable(meta)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_delay_date_and_age_use_the_rfc_clock() {
        let received = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let mut header = ResponseHeader::build(200, None).unwrap();
        header
            .insert_header(
                "date",
                httpdate::fmt_http_date(received - Duration::from_secs(10)),
            )
            .unwrap();
        header.insert_header("age", "9").unwrap();
        assert_eq!(
            initial_age(&header, received, Duration::from_secs(3)),
            Duration::from_secs(12)
        );
        header
            .insert_header(
                "date",
                httpdate::fmt_http_date(received + Duration::from_secs(10)),
            )
            .unwrap();
        assert_eq!(
            initial_age(&header, received, Duration::from_secs(3)),
            Duration::from_secs(12)
        );
        header
            .insert_header("age", "184467440737095516160")
            .unwrap();
        assert_eq!(
            initial_age(&header, received, Duration::ZERO),
            Duration::from_secs(1 << 31)
        );
        assert!(matches!(
            account(
                CacheMeta::new(received, received, 0, 0, header.clone()),
                &header,
                None,
                Duration::from_secs(60),
                Duration::ZERO,
            ),
            RespCacheable::Uncacheable(_)
        ));
    }

    #[test]
    fn expires_uses_date_and_preserves_private_header_stripping() {
        let received = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let mut raw = ResponseHeader::build(200, None).unwrap();
        raw.insert_header(
            "date",
            httpdate::fmt_http_date(received - Duration::from_secs(10)),
        )
        .unwrap();
        raw.insert_header(
            "expires",
            httpdate::fmt_http_date(received + Duration::from_secs(50)),
        )
        .unwrap();
        raw.insert_header("age", "20").unwrap();
        raw.insert_header("x-private", "secret").unwrap();
        let mut sanitized = raw.clone();
        sanitized.remove_header("x-private");
        let meta = CacheMeta::new(
            received + Duration::from_secs(50),
            received,
            5,
            7,
            sanitized,
        );
        let RespCacheable::Cacheable(meta) = account(
            meta,
            &raw,
            None,
            Duration::from_secs(50),
            Duration::from_secs(2),
        ) else {
            panic!("an ordinary age must remain cacheable");
        };
        assert_eq!(meta.epoch(), received - Duration::from_secs(22));
        assert_eq!(meta.fresh_until(), received + Duration::from_secs(38));
        assert!(!meta.headers().contains_key("x-private"));
    }
}
