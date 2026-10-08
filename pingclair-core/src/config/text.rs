// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 📝 Text keeps its interpretation across adaptation, JSON and reload.

use serde::{Deserialize, Serialize};

/// 📝 Legacy strings are templates; native literals carry an explicit tag.
/// This nonrecursive wire value never reinterprets literal braces as sources.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ConfigText {
    Template(String),
    Literal { literal: String },
}

impl ConfigText {
    /// 📝 Marks text as data, even when it resembles a legacy placeholder.
    pub fn literal(value: impl Into<String>) -> Self {
        Self::Literal {
            literal: value.into(),
        }
    }

    /// 📝 Returns the characters without changing their interpretation.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Template(value) => value,
            Self::Literal { literal } => literal,
        }
    }

    /// 🧭 Reports whether request-time placeholder interpretation is allowed.
    pub fn is_template(&self) -> bool {
        matches!(self, Self::Template(_))
    }
}

/// 📝 Reading a text value yields its characters; the interpretation is what
/// `is_template` answers, not what this does. Comparisons against `&str` are
/// then the plain question "do the characters match", which is what a test
/// asserting a body or a message means to ask.
impl std::ops::Deref for ConfigText {
    type Target = str;

    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl PartialEq<str> for ConfigText {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<&str> for ConfigText {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
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
