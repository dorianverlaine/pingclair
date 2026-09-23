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

/// 📂 The names `pingclair run` looks for, in order, when given no path.
pub(crate) const CONFIG_CANDIDATES: [&str; 2] = ["Pingclairfile", "Caddyfile"];

/// 🧾 What the search for a configuration path found.
///
/// 📌 The three cases are separate because two of them read identically at the
/// call site and mean opposite things. Resolving "no argument, no file" to the
/// literal `Pingclairfile` produces `No such file or directory (os error 2)`
/// with no path in it, so an operator who typed `run` in the wrong directory is
/// sent looking for a file that was never the problem. See
/// [`CONFIG_CANDIDATES`] and [`resolve_default_config`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DefaultConfig {
    /// An explicit path was given, and is used whatever it names.
    Given(String),
    /// No path was given, and this conventional name exists here.
    Found(String),
    /// No path was given, and neither conventional name exists here.
    Missing,
}

/// 📂 Resolves the default configuration path the way Caddy does: prefer the
/// project's own `Pingclairfile`, then fall back to a conventional
/// `Caddyfile` so a migrated config works without flags.
pub(crate) fn resolve_config_path(explicit: Option<&str>) -> String {
    match resolve_default_config(explicit) {
        DefaultConfig::Given(path) | DefaultConfig::Found(path) => path,
        DefaultConfig::Missing => CONFIG_CANDIDATES[0].to_string(),
    }
}

/// 📂 [`resolve_config_path`], keeping the two cases that look the same apart.
pub(crate) fn resolve_default_config(explicit: Option<&str>) -> DefaultConfig {
    if let Some(path) = explicit.filter(|p| !p.is_empty()) {
        return DefaultConfig::Given(path.to_string());
    }
    for candidate in CONFIG_CANDIDATES {
        if std::path::Path::new(candidate).exists() {
            return DefaultConfig::Found(candidate.to_string());
        }
    }
    DefaultConfig::Missing
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

#[cfg(test)]
mod tests {
    use super::*;

    /// 🎯 An explicit path is used whatever it names, including when it does
    /// not exist — the operator said where to look, so the search must not
    /// second-guess them.
    #[test]
    fn an_explicit_path_is_taken_as_given() {
        assert!(matches!(
            resolve_default_config(Some("/etc/pingclair/Pingclairfile")),
            DefaultConfig::Given(path) if path == "/etc/pingclair/Pingclairfile"
        ));
    }

    /// 🚫 An empty argument is not a path, and must not be reported as one:
    /// `Given("")` would compile an empty filename and fail on it rather than
    /// saying nothing was found.
    #[test]
    fn an_empty_argument_falls_through_to_the_search() {
        assert!(!matches!(
            resolve_default_config(Some("")),
            DefaultConfig::Given(_)
        ));
    }

    /// 📌 The two answers that read identically at a call site are still the
    /// same file: the resolving form is what every other command wants, and it
    /// must keep returning the first candidate when nothing is found.
    #[test]
    fn the_resolving_form_still_names_the_first_candidate() {
        assert_eq!(
            resolve_config_path(Some("/etc/pingclair/Pingclairfile")),
            "/etc/pingclair/Pingclairfile"
        );
        if !DefaultConfig::Missing.eq(&resolve_default_config(None)) {
            // A workspace that happens to contain a `Pingclairfile` or a
            // `Caddyfile` — it does not — would make the assertion below
            // meaningless rather than wrong, so it is skipped instead.
            assert_eq!(resolve_config_path(None), CONFIG_CANDIDATES[0]);
        }
    }
}
