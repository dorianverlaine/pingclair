// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 📁 Turning a directory into a page.
//!
//! A browse listing is the one place this server takes bytes it did not choose
//! — filenames, and the request path — and puts them in a document a browser
//! will parse. So it is the one place in the static server where output
//! encoding is a security property rather than a formatting preference, and it
//! is split out here so that logic has somewhere to be read on its own.
//!
//! Three rules, and each one exists because leaving it out is exploitable:
//!
//! 1. **A hidden name is hidden here too.** Answering a direct request for
//!    `/secret.env` with a 404 while naming it in the index of `/` is not
//!    concealment; it is a list of what to go and ask for.
//! 2. **Names are encoded for the context they land in.** Display text is HTML
//!    escaped; a link target is percent-encoded. A filename is data, and the
//!    person who created it is not always the operator.
//! 3. **The page has a ceiling.** The whole listing is built in memory and then
//!    possibly compressed, so a directory with a million entries must not
//!    decide how much memory this process uses.

use std::borrow::Cow;
use std::ffi::OsStr;

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_encode};

use super::FileServer;
use pingclair_core::error::Result;

// MARK: - Ceilings

/// 📏 Entries rendered when the operator named no limit.
///
/// Matches the `--file-limit` default, and exists because the previous
/// behaviour was `usize::MAX`: a directory of a million files became a
/// multi-megabyte `String`, a second copy of it compressed, and both held at
/// once. The number of files in a directory is not something the operator
/// necessarily controls — an upload target is the ordinary case — so leaving
/// this uncapped hands a memory decision to whoever writes there.
pub(super) const DEFAULT_ENTRY_LIMIT: usize = 10_000;

/// 📏 A hard ceiling on the rendered page, independent of the entry count.
///
/// The entry limit alone is not a bound on bytes: a filename can be 255 bytes,
/// it appears twice per row, and percent-encoding can triple it. 10,000 such
/// rows is over 15 MB. This is the number that actually bounds the allocation.
pub(super) const MAX_LISTING_BYTES: usize = 1 << 20;

// MARK: - Encoding

/// 🔗 What survives unencoded in a link.
///
/// Only RFC 3986 `unreserved` — alphanumerics and `-._~`. Everything else is
/// percent-encoded, which is deliberately more than a path segment strictly
/// requires: over-encoding is always a valid spelling of the same segment, and
/// the alternative is reasoning about which sub-delimiters are also significant
/// in HTML. Two things fall out of encoding this widely, and both are the
/// reason for it:
///
/// - **A name cannot become a scheme.** `javascript:alert(1)` is a legal
///   filename, and as a link target its leading segment would be read as a
///   scheme — a link that runs script instead of fetching a file. Encoded, the
///   colon is `%3A`, and a scheme may not contain `%`, so it is a path again.
/// - **Nothing HTML-significant is left.** After this, a link target holds only
///   alphanumerics, `-._~` and `%`, none of which can end an attribute. That is
///   why the target needs no second escaping pass, while display text does.
const UNRESERVED: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// 🛡️ Appends `text` with everything that could leave a text node or a quoted
/// attribute written as an entity.
///
/// Both `"` and `'` are escaped even though the attributes here are
/// double-quoted, because a helper that is only safe in one quoting style is a
/// trap for the next caller. The scan borrows: the overwhelmingly common case
/// is a filename with none of these, and it copies straight through.
fn push_html_escaped(out: &mut String, text: &str) {
    let mut rest = text;
    while let Some(index) = rest.find(['&', '<', '>', '"', '\'']) {
        out.push_str(&rest[..index]);
        // 🧾 `&#39;` rather than `&apos;`, which is not an HTML 4 entity and so
        // renders literally in a document served without a doctype.
        out.push_str(match rest.as_bytes()[index] {
            b'&' => "&amp;",
            b'<' => "&lt;",
            b'>' => "&gt;",
            b'"' => "&quot;",
            _ => "&#39;",
        });
        rest = &rest[index + 1..];
    }
    out.push_str(rest);
}

/// 🔗 The bytes of a name, for building a link that can actually reach the file.
///
/// A filename is bytes, not text: `to_string_lossy` would turn a name that is
/// not valid UTF-8 into U+FFFD and produce a link to a file that does not
/// exist. Encoding from the raw bytes keeps the link correct even when the
/// displayed text cannot be.
#[cfg(unix)]
fn name_bytes(name: &OsStr) -> Cow<'_, [u8]> {
    use std::os::unix::ffi::OsStrExt as _;
    Cow::Borrowed(name.as_bytes())
}

/// 🪟 Elsewhere an `OsStr` exposes no byte view, so the lossy text is the best
/// link target available.
#[cfg(not(unix))]
fn name_bytes(name: &OsStr) -> Cow<'_, [u8]> {
    match name.to_string_lossy() {
        Cow::Borrowed(text) => Cow::Borrowed(text.as_bytes()),
        Cow::Owned(text) => Cow::Owned(text.into_bytes()),
    }
}

// MARK: - Rendering

/// 📁 One row of the listing.
///
/// Owns its name because that is what `read_dir` hands over, and holding it
/// lets the page stream straight out of the directory read with no intermediate
/// collection — which is what keeps the ceiling below a real bound rather than
/// a bound on a copy.
pub(super) struct ListingEntry {
    name: std::ffi::OsString,
    is_dir: bool,
}

impl ListingEntry {
    pub(super) fn new(name: std::ffi::OsString, is_dir: bool) -> Self {
        Self { name, is_dir }
    }

    /// 📁 Appends `<a href="…">…</a>` for this entry.
    ///
    /// The trailing slash marking a directory is appended after encoding, on
    /// both halves: it is structure this function is adding, not part of the
    /// name, and encoding it to `%2F` would point the link at a file whose name
    /// ends in a slash — which cannot exist.
    fn push_row(&self, out: &mut String) {
        out.push_str("<a href=\"");
        out.extend(percent_encode(&name_bytes(&self.name), UNRESERVED));
        if self.is_dir {
            out.push('/');
        }
        out.push_str("\">");
        push_html_escaped(out, &self.name.to_string_lossy());
        if self.is_dir {
            out.push('/');
        }
        out.push_str("</a>\n");
    }
}

/// 📁 Renders the page.
///
/// `entry_limit` and `byte_limit` are parameters rather than the constants
/// directly so that the ceilings can be exercised without building a directory
/// of a million files — the bound is the part worth testing, and a test that
/// takes a minute to set up is a test that stops being run.
///
/// Truncation is announced in the page. A listing that silently stops is worse
/// than one that stops visibly: the reader has no way to tell "this directory
/// holds nine files" from "this directory holds nine of some larger number".
pub(super) fn render(
    req_path: &str,
    entries: impl Iterator<Item = ListingEntry>,
    entry_limit: usize,
    byte_limit: usize,
) -> String {
    // 📏 Room for a modest directory without regrowing, and far below the
    // ceiling so the ceiling is what bounds this and not the guess.
    let mut html = String::with_capacity(1024);

    html.push_str("<html><head><title>Index of ");
    push_html_escaped(&mut html, req_path);
    html.push_str("</title></head><body><h1>Index of ");
    push_html_escaped(&mut html, req_path);
    html.push_str("</h1><hr><pre>");

    if req_path != "/" {
        html.push_str("<a href=\"..\">../</a>\n");
    }

    // 📏 `written` is the rows already in the page — the hide filter runs
    // upstream of this iterator, so an entry pulled here is an entry rendered.
    let mut truncated = false;
    for (written, entry) in entries.enumerate() {
        if written == entry_limit || html.len() >= byte_limit {
            truncated = true;
            break;
        }
        entry.push_row(&mut html);
    }

    html.push_str("</pre>");
    if truncated {
        html.push_str("<p>Listing truncated.</p>");
    }
    html.push_str("<hr></body></html>");
    html
}

impl FileServer {
    /// 📁 Reads a directory and renders it.
    ///
    /// The `hide` filter runs before the entry limit, not after. Reversed, a
    /// hidden entry would consume one of the slots, so counting the rows
    /// against a known directory would report how many hidden names it holds —
    /// the listing would conceal the names and disclose the count.
    ///
    /// 📌 `browse_limit` is resolved here rather than at load time, which is the
    /// one place this file steps around the precompute-at-configuration rule.
    /// The reason is proportion: this function has already made a `readdir`
    /// syscall and is about to make one `stat` per entry, so a single
    /// `unwrap_or` is not measurable against it, and the alternative is
    /// changing a field threaded through twelve construction sites across both
    /// transports — where the real risk is one of them being missed.
    pub(super) async fn generate_listing(
        &self,
        dir_path: &std::path::Path,
        req_path: &str,
    ) -> Result<String> {
        // Synchronous directory read — a readdir on a local filesystem is a
        // cheap syscall, not worth a spawn_blocking round trip.
        let read_dir = std::fs::read_dir(dir_path)?;

        // 🙈 One buffer reused for every hide check instead of a `PathBuf` per
        // entry: `push` writes the name, `pop` restores the directory. Skipped
        // entirely when nothing is hidden, which is the common case.
        let hiding = !self.config.hide.is_empty();
        let mut probe = if hiding {
            dir_path.to_path_buf()
        } else {
            std::path::PathBuf::new()
        };

        let entries = read_dir.filter_map(|entry| {
            // 🧹 A name that vanished between the readdir and the stat is left
            // out rather than failing the page. It was deleted while we were
            // looking at it, which is the answer the listing should give.
            let entry = entry.ok()?;
            let name = entry.file_name();

            if hiding {
                probe.push(&name);
                let hidden = self.config.hide.hides(&probe);
                probe.pop();
                if hidden {
                    return None;
                }
            }

            let is_dir = entry.file_type().ok()?.is_dir();
            Some(ListingEntry::new(name, is_dir))
        });

        Ok(render(
            req_path,
            entries,
            self.config.browse_limit.unwrap_or(DEFAULT_ENTRY_LIMIT),
            MAX_LISTING_BYTES,
        ))
    }
}

#[cfg(test)]
mod encoding_tests {
    use super::*;

    fn entry(name: &str, is_dir: bool) -> ListingEntry {
        ListingEntry::new(name.into(), is_dir)
    }

    fn one_row(name: &str, is_dir: bool) -> String {
        let mut row = String::new();
        entry(name, is_dir).push_row(&mut row);
        row
    }

    /// 🛡️ Every character that can end an attribute or open a tag is an entity.
    #[test]
    fn display_text_escapes_the_five_dangerous_characters() {
        let mut out = String::new();
        push_html_escaped(&mut out, "a&b<c>d\"e'f");
        assert_eq!(out, "a&amp;b&lt;c&gt;d&quot;e&#39;f");
    }

    /// 👍 An ordinary name passes through untouched, or the escaping would have
    /// been bought by making every listing unreadable.
    #[test]
    fn an_ordinary_name_is_unchanged() {
        let mut out = String::new();
        push_html_escaped(&mut out, "report-2026.final_v2.pdf");
        assert_eq!(out, "report-2026.final_v2.pdf");
    }

    /// 🚫 A colon in a name cannot start a scheme once encoded.
    #[test]
    fn a_scheme_shaped_name_becomes_a_path() {
        let row = one_row("javascript:alert(1)", false);
        assert!(!row.contains("\"javascript:"), "{row}");
        assert!(row.contains("javascript%3Aalert%281%29"), "{row}");
    }

    /// 🛡️ A quote in a name cannot close the `href` attribute.
    #[test]
    fn a_quote_in_a_name_cannot_close_the_attribute() {
        let row = one_row("x\" onmouseover=alert(1) y", false);
        assert_eq!(
            row.matches('"').count(),
            2,
            "the only quotes may be the attribute's own: {row}"
        );
    }

    /// 🔗 The `#` and `?` that would otherwise cut a link short are encoded.
    ///
    /// Unencoded, `notes#draft.txt` links to `notes` with a fragment, and
    /// `a?b.txt` links to `a` with a query — both fetch the wrong thing, or
    /// nothing.
    #[test]
    fn url_structure_characters_are_encoded() {
        let row = one_row("notes#draft?v=2.txt", false);
        assert!(row.contains("notes%23draft%3Fv%3D2.txt"), "{row}");
    }

    /// 📁 The slash marking a directory is structure, not part of the name.
    #[test]
    fn a_directory_keeps_a_real_trailing_slash() {
        let row = one_row("sub dir", true);
        assert!(row.contains("href=\"sub%20dir/\""), "{row}");
        assert!(row.contains(">sub dir/</a>"), "{row}");
    }

    /// 🔗 A name that is not valid UTF-8 still gets a link that can reach it.
    ///
    /// The displayed text has to become U+FFFD — there is nothing else to show
    /// — but the link is built from the bytes, so it still names the file.
    #[cfg(unix)]
    #[test]
    fn a_non_utf8_name_links_by_its_bytes() {
        use std::os::unix::ffi::OsStringExt as _;
        let name = std::ffi::OsString::from_vec(vec![b'a', 0xff, b'b']);
        let mut row = String::new();
        ListingEntry::new(name, false).push_row(&mut row);
        assert!(row.contains("href=\"a%FFb\""), "{row}");
        assert!(row.contains(">a\u{fffd}b</a>"), "{row}");
    }

    /// 🛡️ The reflected request path is escaped in both places it appears.
    #[test]
    fn the_request_path_is_escaped_in_title_and_heading() {
        let page = render("/<script>", std::iter::empty(), 10, 4096);
        assert!(!page.contains("<script>"), "{page}");
        assert_eq!(
            page.matches("&lt;script&gt;").count(),
            2,
            "title and heading both reflect it: {page}"
        );
    }
}

#[cfg(test)]
mod ceiling_tests {
    use super::*;

    fn many(count: usize) -> impl Iterator<Item = ListingEntry> {
        (0..count).map(|index| ListingEntry::new(format!("file-{index:08}.txt").into(), false))
    }

    /// 📏 The default entry limit is a real number, not `usize::MAX`.
    #[test]
    fn the_default_entry_limit_bounds_the_row_count() {
        let page = render(
            "/",
            many(DEFAULT_ENTRY_LIMIT + 500),
            DEFAULT_ENTRY_LIMIT,
            usize::MAX,
        );
        assert_eq!(page.matches("<a href=").count(), DEFAULT_ENTRY_LIMIT);
        assert!(
            page.contains("Listing truncated"),
            "truncation must be said"
        );
    }

    /// 📏 The byte ceiling holds even when the entry count would not have.
    ///
    /// This is the bound that matters: a filename can be 255 bytes and appears
    /// twice per row, so the entry limit alone permits a page in the tens of
    /// megabytes.
    #[test]
    fn the_byte_ceiling_bounds_the_page() {
        let long = "x".repeat(255);
        let entries = (0..100_000)
            .map(move |index| ListingEntry::new(format!("{index:06}{long}").into(), false));
        let page = render("/", entries, usize::MAX, MAX_LISTING_BYTES);

        assert!(
            page.len() < MAX_LISTING_BYTES + 4096,
            "page grew to {} bytes past a {MAX_LISTING_BYTES}-byte ceiling",
            page.len()
        );
        assert!(
            page.contains("Listing truncated"),
            "truncation must be said"
        );
    }

    /// 👍 A listing that fits says nothing about truncation, or the note would
    /// appear on every page and mean nothing.
    #[test]
    fn a_listing_that_fits_is_not_marked_truncated() {
        let page = render("/", many(9), DEFAULT_ENTRY_LIMIT, MAX_LISTING_BYTES);
        assert_eq!(page.matches("<a href=").count(), 9);
        assert!(!page.contains("truncated"), "{page}");
    }
}
