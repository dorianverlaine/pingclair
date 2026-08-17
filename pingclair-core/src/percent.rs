// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔤 Turning the escapes in a URL back into the bytes of a filename.
//!
//! A URL spells a name in percent-escapes and a filesystem does not, so
//! somewhere the two have to be reconciled. This module is the one place that
//! does it, and it exists as a module rather than a helper because there are two
//! callers — the static file server's path resolution and the `file` matcher's
//! existence probe — and a rule about untrusted bytes that exists in two copies
//! is a rule that will be enforced in one place and forgotten in the other.
//!
//! # 🛡️ Where this may and may not be called
//!
//! **Only where a name is about to become a filename.** Not on a URI. A request
//! path is normalized as a URI earlier and separately, and that step decodes
//! only escapes whose byte is *unreserved* — because the result has to stay a
//! valid URI that can be forwarded upstream, and because decoding a separator
//! there would invent structure the client never sent.
//!
//! By the time anything calls in here, the string is no longer a URI: it is one
//! path component on its way to a syscall, where a space is an ordinary
//! character and there is no query string left to confuse.
//!
//! # 🚫 What is refused rather than decoded
//!
//! A separator or a NUL. Neither can appear in a filename, so refusing costs
//! nothing real, and decoding either one is how a single component becomes
//! several — `PathBuf::push` *replaces* the left side when the right is
//! absolute, which is the exact mechanism that once let a configured index
//! escape the document root.

/// 🔤 Decodes one path component into `out`, appending bytes.
///
/// Returns `false` when the component must not be used as a filename because an
/// escape decoded to a separator or a NUL. `out` may hold partial output in that
/// case; the caller is expected to discard the whole component, not salvage it.
///
/// A malformed escape is data, not an error: `%zz` decodes to the four
/// characters `%zz`, which is what a client sending a literal percent produces.
/// Being stricter than the filesystem here would refuse names that exist.
///
/// `\` is refused on every platform, not only where it separates. A backslash is
/// a separator on Windows, and a path rule that holds on one platform and not
/// another is how a Windows-only traversal gets shipped from a machine that
/// cannot reproduce it. The cost is a Unix filename containing a backslash,
/// which is not something a URL should be spelling.
pub fn decode_path_component(component: &str, out: &mut Vec<u8>) -> bool {
    let bytes = component.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match decoded_byte(bytes, index) {
            Some(byte) => {
                if byte == b'/' || byte == b'\\' || byte == 0 {
                    return false;
                }
                out.push(byte);
                index += 3;
            }
            None => {
                out.push(bytes[index]);
                index += 1;
            }
        }
    }
    true
}

/// 📂 Resolves a request path to a file below `root`, decoding escapes and
/// refusing anything that would leave.
///
/// `None` means "this names no file this handler may serve": a `..` component
/// either before or after decoding, a component that decodes to a separator or a
/// NUL, or — off Unix — bytes that are not valid text. Callers answer that as
/// absent rather than trying to repair it.
///
/// The `..` check runs twice on purpose. Once on the encoded component, so a
/// plain `../` is refused without doing any work, and once on the decoded bytes,
/// because `%2e%2e` does not look like a traversal until it has been decoded.
///
/// 📌 Three callers share this: the `templates` handler on both transports, and
/// the FastCGI script-filename join. The static file server does *not* — it
/// resolves `..` by popping rather than refusing, because a request path may
/// legitimately climb back down inside the document root, and the `file` matcher
/// does not because it has to skip decoding for globbing patterns. What all of
/// them share is [`decode_path_component`], which is where the rule about
/// untrusted bytes actually lives.
pub fn resolve_under_root(root: &std::path::Path, path: &str) -> Option<std::path::PathBuf> {
    let mut resolved = root.to_path_buf();
    let mut decoded = Vec::new();
    for component in path.split('/') {
        if component.is_empty() || component == "." {
            continue;
        }
        if component == ".." {
            return None;
        }
        if !component.contains('%') {
            resolved.push(component);
            continue;
        }
        decoded.clear();
        if !decode_path_component(component, &mut decoded) {
            return None;
        }
        match decoded.as_slice() {
            b"" | b"." => {}
            b".." => return None,
            other => resolved.push(component_os_str(other)?),
        }
    }
    Some(resolved)
}

/// 📁 Views decoded bytes as a path component.
///
/// On Unix a filename *is* bytes, so a name that is not valid UTF-8 is a real
/// name and resolving it is the point.
#[cfg(unix)]
fn component_os_str(component: &[u8]) -> Option<&std::ffi::OsStr> {
    use std::os::unix::ffi::OsStrExt as _;
    Some(std::ffi::OsStr::from_bytes(component))
}

/// 🪟 Elsewhere a path is text, so bytes that are not valid UTF-8 name nothing
/// and the request is refused rather than lossily repaired — a lossy conversion
/// would open a *different* file than the one asked for.
#[cfg(not(unix))]
fn component_os_str(component: &[u8]) -> Option<&std::ffi::OsStr> {
    std::str::from_utf8(component)
        .ok()
        .map(std::ffi::OsStr::new)
}

/// 🔤 The byte a three-character escape at `index` stands for, or `None` when
/// there is no well-formed escape there.
///
/// 🍃 Reads through a bounds-checked window rather than slicing by index: this
/// runs on attacker-controlled bytes, and with `panic = "abort"` in release an
/// out-of-range slice is the whole process dying at a remote client's choosing.
fn decoded_byte(bytes: &[u8], index: usize) -> Option<u8> {
    let window = bytes.get(index..index + 3)?;
    let [b'%', high, low] = window else {
        return None;
    };
    Some((hex_digit(*high)? << 4) | hex_digit(*low)?)
}

/// 🔢 One hex digit's value, either case.
fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(component: &str) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        decode_path_component(component, &mut out).then_some(out)
    }

    fn decode_str(component: &str) -> Option<String> {
        decode(component).map(|bytes| String::from_utf8(bytes).expect("valid UTF-8"))
    }

    /// 🔤 The names a client cannot send unescaped.
    #[test]
    fn escapes_become_the_bytes_they_spell() {
        assert_eq!(
            decode_str("hello%20world.txt").as_deref(),
            Some("hello world.txt")
        );
        assert_eq!(
            decode_str("%E6%96%87%E4%BB%B6.txt").as_deref(),
            Some("文件.txt")
        );
        assert_eq!(decode_str("a%23b").as_deref(), Some("a#b"));
        assert_eq!(decode_str("a%3Fb").as_deref(), Some("a?b"));
        assert_eq!(decode_str("%25").as_deref(), Some("%"));
        assert_eq!(decode_str("%2e%2e").as_deref(), Some(".."));
    }

    /// 👍 A component with nothing to decode comes back byte for byte.
    #[test]
    fn an_ordinary_name_is_unchanged() {
        assert_eq!(
            decode_str("report-2026.final_v2.pdf").as_deref(),
            Some("report-2026.final_v2.pdf")
        );
    }

    /// 🚫 A separator or a NUL is refused, in either hex case.
    #[test]
    fn a_separator_or_nul_is_refused() {
        for component in ["a%2fb", "a%2Fb", "%2f", "a%5cb", "a%5Cb", "a%00b", "%00"] {
            assert!(
                decode(component).is_none(),
                "{component} must be refused, not decoded"
            );
        }
    }

    /// 👍 A malformed escape is taken literally, because a file may be named
    /// that way and refusing would hide it.
    #[test]
    fn a_malformed_escape_is_data() {
        for component in ["%zz", "%", "100%", "a%2", "%%20"] {
            assert!(decode(component).is_some(), "{component} was refused");
        }
        assert_eq!(decode_str("%zz").as_deref(), Some("%zz"));
        assert_eq!(decode_str("a%2").as_deref(), Some("a%2"));
        // 🧾 `%%20` is a literal `%` followed by an escaped space: the first `%`
        // begins no valid escape, and the scan resumes at the next byte rather
        // than swallowing it.
        assert_eq!(decode_str("%%20").as_deref(), Some("% "));
    }

    /// 🛡️ Decoding happens once, so a double-encoded separator stays harmless.
    ///
    /// `%252f` decodes to the four characters `%2f`, not to a separator. A second
    /// pass would find one, which is why there is never a second pass.
    #[test]
    fn decoding_does_not_recurse() {
        assert_eq!(decode_str("%252f").as_deref(), Some("%2f"));
        assert_eq!(decode_str("%252e%252e").as_deref(), Some("%2e%2e"));
    }

    /// 🔤 A name that is not valid UTF-8 is still a name on Unix, so the decode
    /// yields bytes and does not insist they are text.
    #[test]
    fn invalid_utf8_survives_as_bytes() {
        assert_eq!(decode("a%FFb"), Some(vec![b'a', 0xff, b'b']));
    }
}
