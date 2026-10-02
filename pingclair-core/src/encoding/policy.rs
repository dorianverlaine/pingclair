// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🎯 Classifies configured response patterns once, before serving requests.

use super::EncodeOptions;

/// 🎯 A response-header pattern whose wildcard shape is fixed at load time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderPattern {
    Any,
    Exact(String),
    Prefix(String),
    Suffix(String),
    Contains(String),
}

impl HeaderPattern {
    fn compile(pattern: &str) -> Self {
        #[cfg(test)]
        CLASSIFICATIONS.with(|count| count.set(count.get() + 1));
        if pattern == "*" {
            return Self::Any;
        }
        match (pattern.strip_prefix('*'), pattern.strip_suffix('*')) {
            (Some(rest), Some(_)) => Self::Contains(rest.trim_end_matches('*').into()),
            (Some(suffix), None) => Self::Suffix(suffix.into()),
            (None, Some(prefix)) => Self::Prefix(prefix.into()),
            (None, None) => Self::Exact(pattern.into()),
        }
    }

    /// 🎯 Only the response value is inspected on the request path.
    pub fn matches(&self, value: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(pattern) => value == pattern,
            Self::Prefix(pattern) => value.starts_with(pattern),
            Self::Suffix(pattern) => value.ends_with(pattern),
            Self::Contains(pattern) => value.contains(pattern),
        }
    }
}

#[derive(Debug, Clone)]
enum MimePattern {
    Any,
    Exact(String),
    Wildcard { prefix: String, suffix: String },
}

impl MimePattern {
    fn compile(pattern: &str) -> Self {
        #[cfg(test)]
        CLASSIFICATIONS.with(|count| count.set(count.get() + 1));
        let pattern = pattern.trim();
        if pattern == "*/*" {
            return Self::Any;
        }
        match pattern.split_once('*') {
            Some((prefix, suffix)) => Self::Wildcard {
                prefix: prefix.into(),
                suffix: suffix.into(),
            },
            None => Self::Exact(pattern.into()),
        }
    }

    fn matches(&self, mime: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(pattern) => mime.eq_ignore_ascii_case(pattern),
            Self::Wildcard { prefix, suffix } => {
                mime.get(..prefix.len())
                    .is_some_and(|value| value.eq_ignore_ascii_case(prefix))
                    && mime
                        .get(mime.len().saturating_sub(suffix.len())..)
                        .is_some_and(|value| value.eq_ignore_ascii_case(suffix))
            }
        }
    }
}

#[derive(Debug, Clone)]
struct HeaderRule {
    name: String,
    absent: bool,
    patterns: Vec<HeaderPattern>,
}

/// 🎯 Immutable encoding policy shared by proxy and static response execution.
#[derive(Debug, Clone)]
pub struct EncodePolicy {
    explicit: bool,
    statuses: Vec<u16>,
    headers: Vec<HeaderRule>,
    mime: Vec<MimePattern>,
}

impl EncodePolicy {
    /// 🧱 Builds every configuration-only decision at site load time.
    pub fn compile(options: &EncodeOptions, types: &[String]) -> Self {
        let (statuses, headers) = options.matcher.as_ref().map_or_else(
            || (Vec::new(), Vec::new()),
            |matcher| {
                (
                    matcher.status_codes.clone(),
                    matcher
                        .headers
                        .iter()
                        .map(|(name, patterns)| {
                            let (name, absent) = name
                                .strip_prefix('!')
                                .map_or((name.as_str(), false), |name| (name, true));
                            HeaderRule {
                                name: name.into(),
                                absent,
                                patterns: patterns
                                    .iter()
                                    .map(|pattern| HeaderPattern::compile(pattern))
                                    .collect(),
                            }
                        })
                        .collect(),
                )
            },
        );
        let mime = if types.is_empty() {
            crate::config::DEFAULT_GZIP_TYPES
                .iter()
                .map(|pattern| MimePattern::compile(pattern))
                .collect()
        } else {
            types
                .iter()
                .map(|pattern| MimePattern::compile(pattern))
                .collect()
        };
        Self {
            explicit: options.matcher.is_some(),
            statuses,
            headers,
            mime,
        }
    }

    /// 🎯 An explicit response matcher replaces the default MIME allow-list.
    pub fn has_matcher(&self) -> bool {
        self.explicit
    }

    /// 🎯 Response header values are borrowed rather than collected.
    pub fn matches(&self, status: u16, header: impl Fn(&str, &[HeaderPattern]) -> bool) -> bool {
        (self.statuses.is_empty()
            || self.statuses.contains(&status)
            || self.statuses.contains(&(status / 100)))
            && self.headers.iter().all(|rule| {
                if rule.absent {
                    !header(&rule.name, &[])
                } else {
                    header(&rule.name, &rule.patterns)
                }
            })
    }

    /// 🎯 Parameters belong to response data; configured pattern shapes are already compiled.
    pub fn allows_content_type(&self, content_type: &str) -> bool {
        let mime = content_type.split(';').next().map(str::trim).unwrap_or("");
        !mime.is_empty() && self.mime.iter().any(|pattern| pattern.matches(mime))
    }
}

#[cfg(test)]
thread_local! { static CLASSIFICATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_patterns_are_classified_only_at_load() {
        let options = EncodeOptions {
            matcher: Some(crate::config::ResponseMatcher {
                status_codes: vec![2],
                headers: [(
                    "X-Encode".into(),
                    vec![
                        "yes".into(),
                        "pre*".into(),
                        "*end".into(),
                        "*middle*".into(),
                        "*".into(),
                    ],
                )]
                .into(),
            }),
            ..Default::default()
        };
        CLASSIFICATIONS.with(|count| count.set(0));
        let policy =
            EncodePolicy::compile(&options, &[" text/* ".into(), "application/*+json".into()]);
        let compiled = CLASSIFICATIONS.with(|count| count.get());
        assert_eq!(compiled, 7);
        for _ in 0..50 {
            assert!(policy.matches(200, |name, patterns| name == "X-Encode"
                && patterns.iter().any(|pattern| pattern.matches("prefix"))));
            assert!(!policy.matches(404, |_, _| true));
            assert!(policy.allows_content_type("TEXT/plain; charset=utf-8"));
            assert!(policy.allows_content_type("application/ld+json"));
            assert!(!policy.allows_content_type("image/png"));
        }
        assert_eq!(CLASSIFICATIONS.with(|count| count.get()), compiled);
    }

    #[test]
    fn compiled_patterns_preserve_matching_rules() {
        for pattern in ["*", "exact", "pre*", "*suffix", "*middle*", "**", "*foo**"] {
            let compiled = HeaderPattern::compile(pattern);
            for value in ["", "exact", "prefix", "a-suffix", "a-middle-z", "foo"] {
                assert_eq!(
                    compiled.matches(value),
                    super::super::header_pattern_matches(value, pattern)
                );
            }
        }
        for pattern in ["text/*", "application/*+json", "*/*", " IMAGE/PNG "] {
            let compiled = MimePattern::compile(pattern);
            for mime in [
                "",
                "text/plain",
                "application/ld+json",
                "image/png",
                "TEXT/HTML",
            ] {
                assert_eq!(
                    compiled.matches(mime),
                    super::super::gzip_type_matches(mime, pattern)
                );
            }
        }
    }
}
