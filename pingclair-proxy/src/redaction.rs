//! 🙈 Default redaction of secrets before anything reaches a log.
//!
//! Access logs get shipped, indexed and retained far longer than anyone
//! plans, so a credential that lands in one is effectively leaked. The rule
//! here is redact-by-default: a caller has to opt *out*, never opt in.
//!
//! Two vectors matter in practice:
//!
//! 1. **Query strings.** `?api_key=...`, `?token=...` and presigned-URL
//!    signatures are extremely common, and the full request URI is exactly
//!    what an operator wants in a log.
//! 2. **`Referer`.** This is the sneaky one: it carries the *previous*
//!    page's URL, so a token that was never in this request's own URI can
//!    still be logged through it.

/// Query parameter names whose values are replaced with `REDACTED`.
///
/// Matched case-insensitively, and by substring for the `*_key` / `*_token`
/// families so `access_token`, `refresh_token` and `x-api-key` are all
/// caught without enumerating every vendor's spelling.
const SENSITIVE_QUERY_KEYS: &[&str] = &[
    "token",
    "key",
    "secret",
    "password",
    "passwd",
    "pwd",
    "credential",
    "auth",
    "signature",
    "sig",
    "session",
    "code",
];

/// Headers never written to a log in cleartext.
const SENSITIVE_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "x-csrf-token",
];

pub const REDACTED: &str = "REDACTED";

fn is_sensitive_query_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    SENSITIVE_QUERY_KEYS
        .iter()
        .any(|needle| lower.contains(needle))
}

/// Whether a header must be redacted before being logged.
pub fn is_sensitive_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    SENSITIVE_HEADERS.iter().any(|needle| lower == *needle)
}

/// Redact secret-looking parameters out of a query string.
///
/// Takes the raw query (no leading `?`) and returns it with sensitive values
/// replaced. Parameter *names* and ordering are preserved so the log is still
/// useful for debugging — only the values are destroyed.
pub fn redact_query(query: &str) -> String {
    let mut out = String::with_capacity(query.len());
    for (i, pair) in query.split('&').enumerate() {
        if i > 0 {
            out.push('&');
        }
        match pair.split_once('=') {
            Some((key, _)) if is_sensitive_query_key(key) => {
                out.push_str(key);
                out.push('=');
                out.push_str(REDACTED);
            }
            // A bare flag with no `=` carries no value to leak.
            _ => out.push_str(pair),
        }
    }
    out
}

/// Redact a full request target (`/path?query`) for logging.
///
/// The path itself is left intact: it is the primary thing an operator needs,
/// and secrets in a path segment are rare enough that blanket-redacting paths
/// would destroy far more value than it protects.
pub fn redact_target(target: &str) -> String {
    match target.split_once('?') {
        Some((path, query)) => format!("{path}?{}", redact_query(query)),
        None => target.to_string(),
    }
}

/// Redact a `Referer` value.
///
/// Referer carries the previous page's full URL, so a token that never
/// appeared in this request can still leak through it. Same query treatment,
/// with the scheme/host left readable.
pub fn redact_referer(referer: &str) -> String {
    redact_target(referer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_common_secret_parameters() {
        for (input, must_not_contain) in [
            ("api_key=abc123", "abc123"),
            ("access_token=zzz", "zzz"),
            ("refresh_token=zzz", "zzz"),
            ("password=hunter2", "hunter2"),
            ("X-Api-Key=shh", "shh"),
            ("signature=deadbeef", "deadbeef"),
            ("sig=deadbeef", "deadbeef"),
            ("client_secret=oops", "oops"),
            // The probe value must not also occur in the parameter *name*,
            // which is deliberately preserved — e.g. "sess" would match
            // inside "session_id" and give a false failure.
            ("session_id=SVALUE", "SVALUE"),
        ] {
            let out = redact_query(input);
            assert!(
                !out.contains(must_not_contain),
                "leaked {must_not_contain} in {out}"
            );
            assert!(out.contains(REDACTED), "no redaction marker in {out}");
        }
    }

    #[test]
    fn keeps_harmless_parameters_readable() {
        let out = redact_query("page=2&sort=desc&q=hello");
        assert_eq!(out, "page=2&sort=desc&q=hello");
    }

    #[test]
    fn redacts_only_the_sensitive_parameter_in_a_mixed_query() {
        let out = redact_query("page=2&api_key=abc123&sort=desc");
        assert_eq!(out, "page=2&api_key=REDACTED&sort=desc");
    }

    #[test]
    fn is_case_insensitive() {
        let out = redact_query("API_KEY=abc&Token=xyz");
        assert!(!out.contains("abc"), "{out}");
        assert!(!out.contains("xyz"), "{out}");
    }

    #[test]
    fn preserves_parameter_names_and_order_for_debuggability() {
        let out = redact_query("first=1&api_key=x&last=9");
        assert!(out.starts_with("first=1&"), "{out}");
        assert!(out.ends_with("&last=9"), "{out}");
        assert!(
            out.contains("api_key="),
            "parameter name should survive: {out}"
        );
    }

    #[test]
    fn handles_empty_and_valueless_input() {
        assert_eq!(redact_query(""), "");
        assert_eq!(redact_query("flag"), "flag");
        // A `token` flag with no value has nothing to leak.
        assert_eq!(redact_query("token"), "token");
        assert_eq!(redact_query("token="), "token=REDACTED");
    }

    #[test]
    fn redacts_target_but_keeps_the_path() {
        assert_eq!(redact_target("/v1/users"), "/v1/users");
        assert_eq!(
            redact_target("/v1/users?api_key=abc&page=2"),
            "/v1/users?api_key=REDACTED&page=2"
        );
    }

    /// Referer is the vector that leaks a token the current request never had.
    #[test]
    fn redacts_referer_query() {
        let out = redact_referer("https://app.example.com/callback?code=authcode123&state=x");
        assert!(!out.contains("authcode123"), "{out}");
        assert!(
            out.starts_with("https://app.example.com/callback?"),
            "{out}"
        );
    }

    #[test]
    fn sensitive_headers_are_recognized_case_insensitively() {
        for name in [
            "Authorization",
            "authorization",
            "Cookie",
            "SET-COOKIE",
            "X-Api-Key",
            "Proxy-Authorization",
        ] {
            assert!(is_sensitive_header(name), "{name} should be sensitive");
        }
        for name in ["User-Agent", "Accept", "Content-Type", "X-Request-Id"] {
            assert!(!is_sensitive_header(name), "{name} should not be redacted");
        }
    }

    /// A value that merely *contains* a sensitive word must not trigger
    /// header redaction — header matching is exact, unlike query keys.
    #[test]
    fn header_matching_is_exact_not_substring() {
        assert!(!is_sensitive_header("x-cookie-preference"));
        assert!(!is_sensitive_header("authorization-policy"));
    }
}
