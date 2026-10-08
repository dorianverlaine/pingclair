// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 📝 Both transports resolve typed text through the same interpretation gate.

use pingclair_core::config::ConfigText;

pub(crate) trait TextInput {
    fn text(&self) -> &str;
    fn is_template(&self) -> bool;
}

impl TextInput for str {
    fn text(&self) -> &str {
        self
    }
    fn is_template(&self) -> bool {
        true
    }
}

impl TextInput for String {
    fn text(&self) -> &str {
        self
    }
    fn is_template(&self) -> bool {
        true
    }
}

impl TextInput for ConfigText {
    fn text(&self) -> &str {
        self.as_str()
    }
    fn is_template(&self) -> bool {
        self.is_template()
    }
}
