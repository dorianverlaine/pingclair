//! 🔐 Recognises the one request path that RFC 8555 §8.3 defines for an
//! HTTP-01 challenge: the fixed prefix `/.well-known/acme-challenge/`,
//! followed by exactly one token.
//!
//! 📌 The rule is small but easy to get subtly wrong: stripping the prefix
//! "repeatedly" instead of once also answers
//! `/.well-known/acme-challenge/.well-known/acme-challenge/TOKEN`, a path the
//! certificate authority never asks for.

/// 🔐 The fixed path prefix from RFC 8555 §8.3.
const ACME_CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge/";

/// 🎯 Returns the challenge token when `path` has exactly the shape RFC 8555
/// §8.3 defines, and `None` for every other path.
///
/// 🚫 A token is a single base64url segment, so an empty token or one that
/// contains another `/` cannot be one the authority issued.
pub(crate) fn acme_challenge_token(path: &str) -> Option<&str> {
    let token = path.strip_prefix(ACME_CHALLENGE_PREFIX)?;
    (!token.is_empty() && !token.contains('/')).then_some(token)
}

#[cfg(test)]
mod tests {
    use super::acme_challenge_token;

    #[test]
    fn accepts_exactly_one_prefix_and_one_token() {
        let cases = [
            (
                "/.well-known/acme-challenge/abc-DEF_123",
                Some("abc-DEF_123"),
            ),
            // 🚫 With a doubled slash the old repeated strip reduced this to
            // a bare token and served it (#111).
            (
                "/.well-known/acme-challenge//.well-known/acme-challenge/abc",
                None,
            ),
            // 🚫 A repeated prefix without the doubled slash is a nested path.
            (
                "/.well-known/acme-challenge/.well-known/acme-challenge/abc",
                None,
            ),
            ("/.well-known/acme-challenge/", None),
            ("/.well-known/acme-challenge/a/b", None),
            ("/.well-known/acme-challenge", None),
            ("/other/abc", None),
        ];
        let actual: Vec<_> = cases
            .iter()
            .map(|(path, _)| (*path, acme_challenge_token(path)))
            .collect();
        assert_eq!(actual, cases.to_vec());
    }
}
