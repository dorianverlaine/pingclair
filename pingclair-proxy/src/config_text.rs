// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 📝 Both transports resolve typed text through the same interpretation gate.

use pingclair_core::config::{ConfigText, TextSegment};

pub(crate) trait TextInput {
    /// 📝 The characters for the template forms; `None` for a compiled segment
    /// list, which has no single string until the request is known.
    fn static_text(&self) -> Option<&str>;
    /// 💬 The compiled segments, when the value is the typed form.
    fn segments(&self) -> Option<&[TextSegment]>;
    /// 🧭 Whether request-time resolution can change the characters at all.
    fn needs_resolution(&self) -> bool;
}

impl TextInput for str {
    fn static_text(&self) -> Option<&str> {
        Some(self)
    }
    fn segments(&self) -> Option<&[TextSegment]> {
        None
    }
    fn needs_resolution(&self) -> bool {
        self.contains('{')
    }
}

impl TextInput for String {
    fn static_text(&self) -> Option<&str> {
        Some(self)
    }
    fn segments(&self) -> Option<&[TextSegment]> {
        None
    }
    fn needs_resolution(&self) -> bool {
        self.contains('{')
    }
}

impl TextInput for ConfigText {
    fn static_text(&self) -> Option<&str> {
        self.as_static_str()
    }
    fn segments(&self) -> Option<&[TextSegment]> {
        ConfigText::segments(self)
    }
    fn needs_resolution(&self) -> bool {
        ConfigText::needs_resolution(self)
    }
}
