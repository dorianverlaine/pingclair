// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 📦 Moving the TLS store in and out of a tarball.
//!
//! Export and import are one feature written twice, and they only work if the
//! two halves agree on where the archive root is. They did not: export wrote
//! every entry under a `pingclair/` directory and import unpacked straight into
//! the store root, so a round trip put the store one level below itself. The
//! server looks in `<store>/internal`, found nothing at
//! `<store>/pingclair/internal`, and quietly minted a fresh internal CA — so the
//! restore that was supposed to preserve every client's trust silently broke it.
//!
//! They live together here so the next change to either has the other in view.

use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

/// 📦 The directory older archives were written under.
///
/// Kept only so an archive this tool already produced still restores. Nothing
/// writes it any more.
const LEGACY_PREFIX: &str = "pingclair";

/// 📦 Writes the store's contents to `writer`, rooted at the archive root.
///
/// 🤡 This used to prefix every entry with `pingclair/`, which is where the
/// round-trip defect came from. The archive root is the store root now, which is
/// both what import expects and what `caddy storage export` produces — the
/// command this one is modelled on.
pub(crate) fn export_store<W: Write>(dir: &Path, writer: W) -> anyhow::Result<W> {
    let mut builder = tar::Builder::new(writer);
    builder
        .append_dir_all(".", dir)
        .map_err(|error| anyhow::anyhow!("❌ Export failed: {error}"))?;
    builder
        .into_inner()
        .map_err(|error| anyhow::anyhow!("❌ Export failed: {error}"))
}

/// 📦 Unpacks an archive into the store.
///
/// 🛡️ Every entry's path is checked to be strictly relative before anything is
/// written: each component must be an ordinary name, which refuses `..`, an
/// absolute path, and a Windows drive prefix. `tar`'s own `unpack` already
/// refuses parent traversal, but this writes each entry itself in order to
/// rewrite the path, so it cannot inherit that check and has to state it.
///
/// 📦 A single leading `pingclair/` is dropped, which does two jobs: an archive
/// written by the older export still restores to the right place, and a store
/// that a previous import nested is repaired the next time one runs.
pub(crate) fn import_store<R: Read>(dir: &Path, reader: R) -> anyhow::Result<()> {
    let mut archive = tar::Archive::new(reader);
    let entries = archive
        .entries()
        .map_err(|error| anyhow::anyhow!("❌ Import failed: {error}"))?;

    for entry in entries {
        let mut entry = entry.map_err(|error| anyhow::anyhow!("❌ Import failed: {error}"))?;
        let path = entry
            .path()
            .map_err(|error| anyhow::anyhow!("❌ Import failed: {error}"))?
            .into_owned();

        let Some(relative) = archive_relative_path(&path) else {
            anyhow::bail!(
                "❌ Import refused: the archive names `{}`, which is not a path inside the store",
                path.display()
            );
        };
        if relative.as_os_str().is_empty() {
            continue;
        }

        let target = dir.join(&relative);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| anyhow::anyhow!("❌ Import failed: {error}"))?;
        }
        entry
            .unpack(&target)
            .map_err(|error| anyhow::anyhow!("❌ Import failed: {error}"))?;
    }
    Ok(())
}

/// 🛡️ The path an entry may be written to, or `None` if it must not be written.
fn archive_relative_path(path: &Path) -> Option<PathBuf> {
    let mut relative = PathBuf::new();
    for component in path.components() {
        match component {
            // 🧾 `./a` is how `append_dir_all(".", …)` spells `a`.
            Component::CurDir => {}
            Component::Normal(name) => relative.push(name),
            // 🚫 `..`, `/`, and a drive prefix are all ways out of the store.
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(match relative.strip_prefix(LEGACY_PREFIX) {
        Ok(stripped) => stripped.to_path_buf(),
        Err(_) => relative,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &Path, contents: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }

    fn tree(root: &Path) -> Vec<String> {
        let mut found = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else {
                    found.push(
                        path.strip_prefix(root)
                            .unwrap()
                            .to_string_lossy()
                            .into_owned(),
                    );
                }
            }
        }
        found.sort();
        found
    }

    fn populated_store() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join("internal/root.crt"), "ROOTCRT");
        write(&dir.path().join("internal/root.key"), "ROOTKEY");
        write(
            &dir.path().join("certs/example.com/example.com.crt"),
            "LEAF",
        );
        dir
    }

    /// 📦 A store that goes out and comes back must be the same store.
    ///
    /// 🤡 It was not. Export wrote everything under `pingclair/` and import
    /// unpacked into the store root, so the restore landed at
    /// `<store>/pingclair/internal/root.key` — one level below where the server
    /// looks. The operator saw "✅ Store imported", the server then found no
    /// internal CA and minted a new one, and every client that trusted the old
    /// root stopped trusting this server. A disaster-recovery path that reports
    /// success and restores nothing is worse than one that fails.
    #[test]
    fn a_round_trip_restores_the_same_tree() {
        let source = populated_store();
        let destination = tempfile::tempdir().unwrap();

        let archive = export_store(source.path(), Vec::new()).unwrap();
        import_store(destination.path(), archive.as_slice()).unwrap();

        assert_eq!(
            tree(destination.path()),
            tree(source.path()),
            "the restored store is not the store that was exported"
        );
        assert_eq!(
            std::fs::read_to_string(destination.path().join("internal/root.key")).unwrap(),
            "ROOTKEY"
        );
    }

    /// 📦 An archive written by the older export still restores to the right
    /// place, and a store a previous import nested is repaired.
    #[test]
    fn a_legacy_prefixed_archive_still_restores_flat() {
        let source = populated_store();
        let destination = tempfile::tempdir().unwrap();

        // 🧾 Exactly what the previous version produced.
        let mut builder = tar::Builder::new(Vec::new());
        builder.append_dir_all("pingclair", source.path()).unwrap();
        let archive = builder.into_inner().unwrap();

        import_store(destination.path(), archive.as_slice()).unwrap();

        assert_eq!(tree(destination.path()), tree(source.path()));
    }

    /// 🧾 One tar entry, built byte by byte.
    ///
    /// The `tar` crate refuses to *write* a path containing `..`, which is the
    /// right thing for a builder and useless for this test: the archive under
    /// test is one that arrived from somewhere else. So the 512-byte ustar
    /// header is assembled directly, which is what a hostile archive looks like.
    fn raw_tar_entry(name: &str, data: &[u8]) -> Vec<u8> {
        let mut header = [0u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        header[100..108].copy_from_slice(b"0000600\0");
        header[108..116].copy_from_slice(b"0000000\0");
        header[116..124].copy_from_slice(b"0000000\0");
        header[124..136].copy_from_slice(format!("{:011o}\0", data.len()).as_bytes());
        header[136..148].copy_from_slice(b"00000000000\0");
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        // 🔢 The checksum is computed with its own field read as spaces.
        header[148..156].copy_from_slice(b"        ");
        let sum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
        header[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
        header[155] = b' ';

        let mut archive = header.to_vec();
        archive.extend_from_slice(data);
        archive.resize(archive.len().div_ceil(512) * 512, 0);
        // 🏁 Two zero blocks end a tar stream.
        archive.extend_from_slice(&[0u8; 1024]);
        archive
    }

    /// 🛡️ An entry naming a path outside the store is refused, not written.
    ///
    /// This half is not a regression — `tar`'s own `unpack` refused parent
    /// traversal too. It is here because rewriting the path meant unpacking each
    /// entry by hand, which gives up that check, so the replacement has to be
    /// tested rather than assumed.
    #[test]
    fn an_escaping_entry_is_refused() {
        let destination = tempfile::tempdir().unwrap();
        let archive = raw_tar_entry("../escaped.key", b"OWNED");

        let error = import_store(destination.path(), archive.as_slice())
            .expect_err("an entry climbing out of the store must be refused");
        assert!(
            format!("{error}").contains("not a path inside the store"),
            "got {error}"
        );
        assert!(
            !destination
                .path()
                .parent()
                .unwrap()
                .join("escaped.key")
                .exists(),
            "the entry was written outside the store"
        );
    }

    /// 🛡️ …and so is an absolute one, which is the other way out.
    #[test]
    fn an_absolute_entry_is_refused() {
        let destination = tempfile::tempdir().unwrap();
        let archive = raw_tar_entry("/etc/pingclair-owned.key", b"OWNED");

        let error = import_store(destination.path(), archive.as_slice())
            .expect_err("an absolute entry must be refused");
        assert!(
            format!("{error}").contains("not a path inside the store"),
            "got {error}"
        );
    }
}
