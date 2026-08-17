// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🙈 A configured string that must not appear in a log.

use serde::{Deserialize, Serialize};

/// 🙈 A secret read from configuration: an API key, a DNS provider token.
///
/// The whole of it is the [`std::fmt::Debug`] implementation. A secret held in a
/// plain `String` inside a type that derives `Debug` is one `{:?}` away from a
/// log line, and the `{:?}` does not have to be near the secret — it can be on
/// any type that contains it, anywhere, including a panic message. This
/// repository's own convention says sensitive fields are masked "in logs,
/// metrics, admin dumps, and panic messages", and a derived `Debug` cannot
/// honour that no matter how careful each call site is.
///
/// 📌 Deliberately **not** `Display`, and deliberately not `AsRef<str>`. Both
/// would let the value be formatted by accident, which is the thing being
/// prevented. Code that genuinely needs the bytes calls [`Self::expose`], which
/// is a word you can grep for when you want to know where a secret is used.
///
/// 🧭 `serde(transparent)`, so the wire format is unchanged: a secret is still a
/// bare JSON string, and a configuration written before this type existed loads
/// and round-trips identically. This is about what reaches a log, not about what
/// reaches disk — for that, see `pingclair_core::secure_file`.
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretString(String);

impl std::fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 🧭 Empty and set are distinguishable, because "did the operator
        // actually configure this" is a question worth answering from a log and
        // is not itself a secret. The length is not shown: it says something
        // about the value, and it is never the thing being debugged.
        if self.0.is_empty() {
            formatter.write_str("SecretString(empty)")
        } else {
            formatter.write_str("SecretString(redacted)")
        }
    }
}

impl SecretString {
    /// 🔓 The secret itself, for the code that has to send it somewhere.
    ///
    /// Named for grepping: every place a configured secret leaves this process
    /// is a call to this method, so `rg expose\\(\\)` is the audit.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// 🈳 Whether nothing was configured.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for SecretString {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 🙈 The secret does not appear in its own `Debug` output.
    ///
    /// Asserted on the wrapper *and* on a struct containing it, because the
    /// leak this prevents is not `{:?}` on the secret — nobody writes that — it
    /// is `{:?}` on something that happens to contain one.
    #[test]
    fn a_secret_is_not_in_its_debug_output() {
        // 🧭 Only ever formatted, never read — which is the point, and is why
        // dead-code analysis has to be told.
        #[derive(Debug)]
        #[allow(dead_code)]
        struct Holder {
            api_key: Option<SecretString>,
            listen: String,
        }

        let secret = SecretString::from("s3cret-sentinel-value");
        assert!(!format!("{secret:?}").contains("s3cret-sentinel-value"));

        let holder = Holder {
            api_key: Some(secret),
            listen: "127.0.0.1:2019".to_string(),
        };
        let rendered = format!("{holder:?}");
        assert!(
            !rendered.contains("s3cret-sentinel-value"),
            "a containing struct leaked the secret: {rendered}"
        );
        // 🧭 The rest of the struct is still debuggable, which is the point of
        // redacting one field instead of the whole type.
        assert!(rendered.contains("127.0.0.1:2019"));
    }

    /// 🧭 Empty and set are told apart, since that is not the secret.
    #[test]
    fn an_unset_secret_reads_differently_from_a_set_one() {
        assert_eq!(
            format!("{:?}", SecretString::default()),
            "SecretString(empty)"
        );
        assert_eq!(
            format!("{:?}", SecretString::from("x")),
            "SecretString(redacted)"
        );
    }

    /// 🧾 The wire format is a bare string, so old documents still load.
    #[test]
    fn the_json_shape_is_unchanged() {
        let secret: SecretString = serde_json::from_str("\"token\"").unwrap();
        assert_eq!(secret.expose(), "token");
        assert_eq!(serde_json::to_string(&secret).unwrap(), "\"token\"");
    }
}
