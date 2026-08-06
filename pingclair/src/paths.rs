// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 📂 The two filesystem locations the binary has to work out for itself.
//!
//! Neither is a constant, and that is the whole reason they live together: one
//! is the configuration the operator meant when they typed no path at all, the
//! other is where certificates and the autosaved document survive a restart.
//! Both are answered by convention rather than by configuration, so both are
//! places a wrong guess is silent — a config that "worked" because it found a
//! different file, or a certificate store that starts empty on every boot.

/// 📂 Resolves the default configuration path the way Caddy does: prefer the
/// project's own `Pingclairfile`, then fall back to a conventional
/// `Caddyfile` so a migrated config works without flags.
pub(crate) fn resolve_config_path(explicit: Option<&str>) -> String {
    if let Some(path) = explicit.filter(|p| !p.is_empty()) {
        return path.to_string();
    }
    for candidate in ["Pingclairfile", "Caddyfile"] {
        if std::path::Path::new(candidate).exists() {
            return candidate.to_string();
        }
    }
    "Pingclairfile".to_string()
}

/// 🔐 Resolves the persistent TLS/config store directory.
///
/// The Admin API autosaves the active document under this directory so
/// `--resume` can restore an API-driven configuration after a restart.
pub(crate) fn tls_store_dir() -> std::path::PathBuf {
    if let Ok(path) = std::env::var("PINGCLAIR_TLS_STORE") {
        return std::path::PathBuf::from(path);
    }
    // 🧭 Caddy stores data under the user's data directory; a hard-coded
    // `/var/lib/pingclair/certs` made an unprivileged first run impossible.
    let data_home = std::env::var("XDG_DATA_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|_| {
            std::env::var("HOME").map(|home| {
                #[cfg(target_os = "macos")]
                {
                    std::path::PathBuf::from(home).join("Library/Application Support")
                }
                #[cfg(not(target_os = "macos"))]
                {
                    std::path::PathBuf::from(home).join(".local/share")
                }
            })
        })
        .unwrap_or_else(|_| std::path::PathBuf::from("/var/lib/pingclair"));
    data_home.join("pingclair")
}
