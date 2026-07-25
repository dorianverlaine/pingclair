//! ACME Account Credential Persistence
//!
//! 🔑 Stores the ACME account credentials (account URL + private key) on disk
//! so the same account is reused across restarts instead of re-registering on
//! every issuance. Without this, frequent restarts hit the ACME provider's
//! new-account rate limits (e.g., Let's Encrypt allows 10 accounts per IP per
//! 3 hours).
//!
//! **Layout:**
//! - Production: `<tls_store>/acme/account.json`
//! - Staging: `<tls_store>/acme/account.staging.json`
//!
//! The file contains the account private key and is written with mode 0600
//! on Unix.

use std::path::{Path, PathBuf};

// MARK: - Paths

/// Returns the path of the account credentials file for the given store root
/// and ACME environment.
pub fn credentials_path(store_root: &Path, staging: bool) -> PathBuf {
    let filename = if staging {
        "account.staging.json"
    } else {
        "account.json"
    };
    store_root.join("acme").join(filename)
}

// MARK: - Persistence

/// Loads the serialized account credentials from disk.
///
/// - Returns: `Ok(Some(json))` when the file exists and is readable,
///   `Ok(None)` when it does not exist, or an `Err` on I/O failure.
pub fn load(path: &Path) -> std::io::Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(json) => Ok(Some(json)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Saves the serialized account credentials to disk.
///
/// Creates the parent directory when needed. On Unix the file is written with
/// mode 0600 because it contains the account private key.
pub fn save(path: &Path, json: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, json)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_path_separates_staging_from_production() {
        let root = Path::new("/tmp/store");
        assert_eq!(
            credentials_path(root, false),
            PathBuf::from("/tmp/store/acme/account.json")
        );
        assert_eq!(
            credentials_path(root, true),
            PathBuf::from("/tmp/store/acme/account.staging.json")
        );
    }

    #[test]
    fn load_returns_none_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = credentials_path(dir.path(), false);
        assert_eq!(load(&path).unwrap(), None);
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = credentials_path(dir.path(), false);

        // The parent directory does not exist yet; save must create it.
        let json = r#"{"id":"https://acme.example/acct/1","key_pkcs8":"AAAA"}"#;
        save(&path, json).unwrap();
        assert_eq!(load(&path).unwrap().as_deref(), Some(json));

        // A second save overwrites in place.
        let json2 = r#"{"id":"https://acme.example/acct/2","key_pkcs8":"BBBB"}"#;
        save(&path, json2).unwrap();
        assert_eq!(load(&path).unwrap().as_deref(), Some(json2));
    }

    #[cfg(unix)]
    #[test]
    fn saved_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = credentials_path(dir.path(), false);
        save(&path, "{}").unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
