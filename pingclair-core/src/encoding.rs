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

/// 🏎️ Walks the header's entries, keeping each one's quality value.
///
/// This runs for every compressible response, so it borrows from the header
/// and never collects: the `Vec` it replaced was a heap allocation per
/// response, per offered coding.
///
/// A malformed `q` is treated as "acceptable" rather than as a rejection. The
/// header is advisory, and a client sending junk should not be answered with a
/// broken response.
fn entries(header: &str) -> impl Iterator<Item = AcceptedCoding<'_>> {
    header.split(',').filter_map(|part| {
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
}

/// 🔎 The quality the header gives `coding` by name or, failing that, by `*`.
///
/// `None` means the header does not mention it at all. One pass: the first
/// explicit mention ends the scan, and the first wildcard is remembered in case
/// no explicit mention follows.
fn mentioned_quality(accept_encoding: &str, coding: &str) -> Option<f32> {
    let mut wildcard = None;
    for entry in entries(accept_encoding) {
        if same_coding(entry.token, coding) {
            return Some(entry.q);
        }
        if wildcard.is_none() && entry.token == "*" {
            wildcard = Some(entry.q);
        }
    }
    wildcard
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
    let q = mentioned_quality(accept_encoding, coding)?;
    (q > 0.0).then_some(q)
}

/// 🏷️ Whether two `Accept-Encoding` tokens name the same coding.
///
/// Case-insensitive, because `Accept-Encoding: GZIP` is valid and means gzip.
/// `x-gzip` is the legacy spelling some older clients still send and has always
/// been accepted here, so it stays accepted — dropping it while fixing quality
/// values would be an unrelated regression hidden inside a correctness fix.
///
/// 🏎️ Compared in place: lowercasing into a fresh `String`, as this used to,
/// cost two allocations per offered coding on every response.
fn same_coding(token: &str, coding: &str) -> bool {
    fn canonical(s: &str) -> &str {
        let s = s.trim();
        match s.get(..2) {
            Some(prefix)
                if prefix.eq_ignore_ascii_case("x-") && s[2..].eq_ignore_ascii_case("gzip") =>
            {
                &s[2..]
            }
            _ => s,
        }
    }
    canonical(token).eq_ignore_ascii_case(canonical(coding))
}

// MARK: - Ranking

/// 🥇 The offered codings the client accepts, best first.
///
/// The client's quality values win first — `gzip;q=1.0, zstd;q=0.1` is a real
/// preference, usually because gzip is what that client decodes cheaply — and
/// the server's order only breaks ties. That is what makes a configured
/// `zstd gzip` mean "zstd when the client does not care" without overriding a
/// client that does. Refused codings are never yielded.
///
/// 🏎️ Allocation-free: codings already yielded are remembered in a 64-bit
/// mask, and each step rescans the header instead of storing qualities. The
/// offered lists are two or three codings long, so that rescan is a handful of
/// short comparisons, cheaper than any buffer that would hold the results.
pub struct Ranked<'h, 'o, T, F> {
    accept_encoding: &'h str,
    offered: &'o [T],
    token: F,
    yielded: u64,
}

/// 🥇 Ranks `offered` against the header; `token` names each offered coding.
///
/// Only the first 64 offered codings are considered, which is many more than
/// there are content codings to offer.
pub fn ranked<'h, 'o, T, F>(
    accept_encoding: &'h str,
    offered: &'o [T],
    token: F,
) -> Ranked<'h, 'o, T, F>
where
    F: Fn(&T) -> &str,
{
    Ranked {
        accept_encoding,
        offered,
        token,
        yielded: 0,
    }
}

impl<'o, T, F> Iterator for Ranked<'_, 'o, T, F>
where
    F: Fn(&T) -> &str,
{
    type Item = &'o T;

    fn next(&mut self) -> Option<&'o T> {
        let mut best: Option<(usize, f32)> = None;
        for (rank, item) in self.offered.iter().enumerate().take(64) {
            if self.yielded & (1 << rank) != 0 {
                continue;
            }
            let Some(q) = quality_for(self.accept_encoding, (self.token)(item)) else {
                continue;
            };
            // 📌 Strictly greater, so an equal quality keeps the earlier,
            // server-preferred coding.
            if best.is_none_or(|(_, best_q)| q > best_q) {
                best = Some((rank, q));
            }
        }
        let (rank, _) = best?;
        self.yielded |= 1 << rank;
        Some(&self.offered[rank])
    }
}

/// 🥇 Picks the coding to send from `offered`, or `None` for identity.
///
/// `offered` is the server's preference order; [`Ranked`] explains how it
/// combines with the client's quality values.
pub fn negotiate_by<'o, T>(
    accept_encoding: &str,
    offered: &'o [T],
    token: impl Fn(&T) -> &str,
) -> Option<&'o T> {
    ranked(accept_encoding, offered, token).next()
}

/// 🥇 [`negotiate_by`] for a plain list of coding names.
pub fn negotiate<'a>(accept_encoding: &str, offered: &[&'a str]) -> Option<&'a str> {
    negotiate_by(accept_encoding, offered, |coding| coding).copied()
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
