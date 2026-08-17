// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔐 Atomic persistence for files that must not be readable by anyone else.
//!
//! Written for TLS private material and now shared with everything else that
//! puts a secret on disk — the Admin API's autosaved document carries the admin
//! key and DNS credentials, and a store export is an archive of private keys.
//! One implementation on purpose: a second copy of "0600, unique temporary,
//! fsync, rename, fsync the parent" is a second chance to leave a step out, and
//! every step here is one that a plain `fs::write` gets wrong.
//!
//! What a plain `std::fs::write` does instead: creates the file with `0666 &
//! !umask`, which is `0644` under the ordinary default, so the secret is
//! world-readable for its whole life. It also does not fsync, so a crash can
//! leave a truncated file where a complete one is expected, and a fixed
//! temporary name makes two writers collide.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

/// 🧬 Supplies collision-resistant suffixes without consulting the clock.
static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// 🔒 Writes private material through a same-directory temporary file.
///
/// 🛡️ The temporary file is owner-only from creation on Unix, synchronized
/// before publication, and atomically renamed over the destination.
pub fn write_private_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;

    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let suffix = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temporary_name = format!(
        ".{}.tmp-{}-{}",
        file_name.to_string_lossy(),
        std::process::id(),
        suffix
    );
    let temporary_path = parent.join(temporary_name);

    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        let mut file = options.open(&temporary_path)?;
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);

        fs::rename(&temporary_path, path)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
            fs::File::open(parent)?.sync_all()?;
        }

        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}
