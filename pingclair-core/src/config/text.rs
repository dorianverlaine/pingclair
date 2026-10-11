// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 📝 Text keeps its interpretation across adaptation, JSON and reload.

use serde::{Deserialize, Serialize};

/// 💬 One request fact a dynamic text value can read.
///
/// 📌 This is the typed spelling of the Caddy placeholders the legacy form
/// still carries: a closed set, checked by the frontend at load time and
/// resolved through the same lookups as `{client_ip}`, `{uri}` and friends, so
/// the two spellings can never disagree about what a name means.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TextSource {
    /// 🛡️ The client after trusted-proxy handling.
    ClientIp,
    /// 🔌 The socket peer, whatever any header claims.
    RemoteHost,
    RemotePort,
    /// 🧭 What the client used, which a plaintext hop behind a TLS terminator
    /// cannot be read off the headers.
    Scheme,
    Host,
    Path,
    Method,
    /// 🧭 The current request target: path and query, never scheme or
    /// authority. A rewrite changes it, because it is *this* request's target.
    Uri,
    /// 🚨 Only meaningful inside an error route; the shared validation refuses
    /// it anywhere else.
    ErrorStatus,
    ErrorMessage,
}

/// 💬 One piece of a compiled dynamic text value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TextSegment {
    Literal(String),
    Source(TextSource),
}

/// 📝 Legacy strings are templates; native literals carry an explicit tag;
/// `Format(…)` and `from:` compile to a segment list at load time.
///
/// 🚫 This nonrecursive wire value never reinterprets literal braces as
/// sources, and the segment form never re-parses text at request time: the
/// frontend compiles the pattern once, and the transports only look up the
/// sources it names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ConfigText {
    Template(String),
    Literal { literal: String },
    Segments { segments: Vec<TextSegment> },
}

impl ConfigText {
    /// 📝 Marks text as data, even when it resembles a legacy placeholder.
    pub fn literal(value: impl Into<String>) -> Self {
        Self::Literal {
            literal: value.into(),
        }
    }

    /// 💬 A compiled segment list that reads exactly one source.
    pub fn from_source(source: TextSource) -> Self {
        Self::Segments {
            segments: vec![TextSegment::Source(source)],
        }
    }

    /// 📝 The characters when they need no request-time data.
    pub fn as_static_str(&self) -> Option<&str> {
        match self {
            Self::Template(value) => Some(value),
            Self::Literal { literal } => Some(literal),
            Self::Segments { .. } => None,
        }
    }

    /// 🧭 Reports whether request-time placeholder interpretation is allowed.
    pub fn is_template(&self) -> bool {
        matches!(self, Self::Template(_))
    }

    /// 🧭 Reports whether resolution can change the characters at all: a
    /// legacy template that carries a placeholder, or a compiled segment list.
    pub fn needs_resolution(&self) -> bool {
        match self {
            Self::Template(value) => value.contains('{'),
            Self::Literal { .. } => false,
            Self::Segments { .. } => true,
        }
    }

    /// 💬 The compiled segments, when this value is the typed form.
    pub fn segments(&self) -> Option<&[TextSegment]> {
        match self {
            Self::Segments { segments } => Some(segments),
            _ => None,
        }
    }
}

/// 📝 Reading a text value yields its characters; the interpretation is what
/// `is_template` answers, not what this does. Comparisons against `&str` are
/// then the plain question "do the characters match", which is what a test
/// asserting a body or a message means to ask.
impl PartialEq<str> for ConfigText {
    fn eq(&self, other: &str) -> bool {
        self.as_static_str() == Some(other)
    }
}

impl PartialEq<&str> for ConfigText {
    fn eq(&self, other: &&str) -> bool {
        self.as_static_str() == Some(*other)
    }
}

impl From<String> for ConfigText {
    fn from(value: String) -> Self {
        Self::Template(value)
    }
}

impl From<&str> for ConfigText {
    fn from(value: &str) -> Self {
        Self::Template(value.to_owned())
    }
}
