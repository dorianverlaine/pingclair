//! 🗜️ `Accept-Encoding` quality values, in one place.
//!
//! This lives in `pingclair-core` because two crates need it and having two
//! implementations already cost us a defect. `pingclair-proxy` had a correct,
//! well-tested `negotiate()` that **nothing in production called**, while
//! `pingclair-static` had its own `header.contains("gzip")`. Day 26 measured
//! the consequence on a clean Linux box: a client sending
//! `Accept-Encoding: gzip;q=0` — "I explicitly do not want gzip" — received a
//! gzip-encoded response, where the correct answer is the file uncompressed.
//!
//! Only the part that was wrong lives here: reading quality values out of the
//! header. Each caller still owns which codings it offers and in what order,
//! because that is genuinely different between a static file and a proxied
//! response.

/// One entry of an `Accept-Encoding` header.
struct AcceptedCoding<'a> {
    token: &'a str,
    q: f32,
}

/// Parses the header into its entries, keeping each one's quality value.
///
/// A malformed `q` is treated as "acceptable" rather than as a rejection. The
/// header is advisory, and a client sending junk should not be answered with a
/// broken response.
fn parse(header: &str) -> Vec<AcceptedCoding<'_>> {
    header
        .split(',')
        .filter_map(|part| {
            let mut pieces = part.split(';');
            let token = pieces.next()?.trim();
            if token.is_empty() {
                return None;
            }
            let q = pieces
                .find_map(|param| {
                    let (key, value) = param.split_once('=')?;
                    key.trim().eq_ignore_ascii_case("q").then_some(value)
                })
                .and_then(|value| value.trim().parse::<f32>().ok())
                .filter(|value| value.is_finite())
                .map(|value| value.clamp(0.0, 1.0))
                .unwrap_or(1.0);
            Some(AcceptedCoding { token, q })
        })
        .collect()
}

/// 🤝 The quality the client assigned to `coding`, or `None` if it refused it.
///
/// `None` means "do not send this coding". That happens two ways: the client
/// named it with `q=0`, or it sent `*;q=0` and never named it. An explicit
/// mention always beats the wildcard, whichever came first in the header —
/// `*;q=0, gzip` accepts gzip.
///
/// Comparison is case-insensitive because `Accept-Encoding: GZIP` is a valid
/// header that means gzip.
pub fn quality_for(accept_encoding: &str, coding: &str) -> Option<f32> {
    let accepted = parse(accept_encoding);
    let explicit = accepted
        .iter()
        .find(|entry| same_coding(entry.token, coding));
    let q = match explicit {
        Some(entry) => entry.q,
        None => accepted.iter().find(|entry| entry.token == "*")?.q,
    };
    (q > 0.0).then_some(q)
}

/// 🏷️ Whether two `Accept-Encoding` tokens name the same coding.
///
/// Case-insensitive, because `Accept-Encoding: GZIP` is valid and means gzip.
/// `x-gzip` is the legacy spelling some older clients still send and has always
/// been accepted here, so it stays accepted — dropping it while fixing quality
/// values would be an unrelated regression hidden inside a correctness fix.
fn same_coding(token: &str, coding: &str) -> bool {
    let normalise = |s: &str| match s.trim().to_ascii_lowercase().as_str() {
        "x-gzip" => "gzip".to_string(),
        other => other.to_string(),
    };
    normalise(token) == normalise(coding)
}

/// 🥇 Picks the coding to send, or `None` for identity.
///
/// `offered` is the server's preference order. The client's quality values win
/// first — `gzip;q=1.0, zstd;q=0.1` is a real preference, usually because gzip
/// is what that client decodes cheaply — and the server's order only breaks
/// ties. That is what makes a configured `zstd gzip` mean "zstd when the client
/// does not care" without overriding a client that does.
pub fn negotiate<'a>(accept_encoding: &str, offered: &[&'a str]) -> Option<&'a str> {
    offered
        .iter()
        .enumerate()
        .filter_map(|(rank, &coding)| {
            quality_for(accept_encoding, coding).map(|q| (rank, coding, q))
        })
        .max_by(|(rank_a, _, q_a), (rank_b, _, q_b)| q_a.total_cmp(q_b).then(rank_b.cmp(rank_a)))
        .map(|(_, coding, _)| coding)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOTH: &[&str] = &["zstd", "gzip"];

    /// 🚫 The case Day 26 measured: `q=0` is a refusal,
    /// and the old `header.contains("gzip")` answered it with gzip.
    #[test]
    fn q_zero_is_a_refusal() {
        assert_eq!(negotiate("gzip;q=0", BOTH), None);
        assert_eq!(negotiate("gzip;q=0.000", BOTH), None);
        assert_eq!(negotiate("gzip;q=0, zstd;q=0", BOTH), None);
        // 📌 Refusing one coding does not refuse the others.
        assert_eq!(negotiate("zstd;q=0, gzip", BOTH), Some("gzip"));
    }

    #[test]
    fn wildcard_is_a_fallback_that_an_explicit_mention_beats() {
        assert_eq!(negotiate("*", BOTH), Some("zstd"));
        assert_eq!(negotiate("*;q=0", BOTH), None);
        // The explicit mention wins even though the wildcard came first.
        assert_eq!(negotiate("*;q=0, gzip", BOTH), Some("gzip"));
        assert_eq!(negotiate("gzip;q=0, *", BOTH), Some("zstd"));
    }

    #[test]
    fn client_quality_outranks_server_preference() {
        assert_eq!(negotiate("zstd;q=0.1, gzip;q=1.0", BOTH), Some("gzip"));
        assert_eq!(negotiate("zstd;q=1.0, gzip;q=0.5", BOTH), Some("zstd"));
        // Equal quality falls back to the server's order.
        assert_eq!(negotiate("gzip, zstd", BOTH), Some("zstd"));
        assert_eq!(negotiate("gzip, zstd", &["gzip", "zstd"]), Some("gzip"));
    }

    #[test]
    fn a_coding_we_do_not_offer_is_never_chosen() {
        assert_eq!(negotiate("br", BOTH), None);
        assert_eq!(negotiate("br, gzip", BOTH), Some("gzip"));
    }

    /// 🙈 `contains` matched substrings, so a token that merely embeds a coding
    /// name used to select it. Tokens are compared whole now.
    #[test]
    fn a_token_that_merely_embeds_a_name_does_not_match() {
        assert_eq!(negotiate("x-gzip-ish", BOTH), None);
        assert_eq!(negotiate("brotli", &["br"]), None);
    }

    #[test]
    fn case_is_not_significant() {
        assert_eq!(negotiate("GZIP", BOTH), Some("gzip"));
        assert_eq!(negotiate("GZip;Q=0", BOTH), None);
    }

    /// 📌 `x-gzip` was accepted before this module existed and still is; a
    /// correctness fix must not quietly drop a coding older clients send.
    #[test]
    fn the_legacy_x_gzip_spelling_still_means_gzip() {
        assert_eq!(negotiate("x-gzip", BOTH), Some("gzip"));
        assert_eq!(negotiate("x-gzip;q=0", BOTH), None);
    }

    /// 📌 The header is advisory: junk must not turn into a broken response.
    #[test]
    fn a_malformed_quality_is_treated_as_acceptable() {
        assert_eq!(negotiate("gzip;q=banana", BOTH), Some("gzip"));
        assert_eq!(negotiate("gzip;q=", BOTH), Some("gzip"));
    }

    #[test]
    fn an_empty_header_selects_nothing() {
        assert_eq!(negotiate("", BOTH), None);
        assert_eq!(negotiate("   ", BOTH), None);
    }
}
