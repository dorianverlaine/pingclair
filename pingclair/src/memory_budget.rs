// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧮 Sizes the static-file caches from the memory this process may actually use.
//!
//! The caches have always had fixed ceilings; the question this module answers
//! is whether the machine can afford them. A 4 GiB host can, a 512 MiB
//! container cannot, and the same configuration used to be "fine" or "fatal"
//! depending on hardware nobody consulted (#33). The budgets are a slice of
//! what is available — cgroup limit first, then the host's available memory —
//! clamped to the ceilings and never above them, and the values in force are
//! logged so an operator can see what was chosen.
//!
//! 📌 This runs once at startup, before the first file server exists; the
//! first installation wins and nothing here is consulted again.

use pingclair_static::{CacheBudgets, configure_cache_budgets};

/// 🧮 Installs the cache budgets and reports the values the process will use.
pub(crate) fn install_cache_budgets() {
    let available = available_memory();
    let budgets = CacheBudgets::for_available_memory(available);
    if !configure_cache_budgets(budgets) {
        return;
    }
    tracing::info!(
        available_bytes = available,
        compressed_bytes = budgets.compressed_bytes,
        content_bytes = budgets.content_bytes,
        metadata_entries = budgets.metadata_entries,
        "🧮 Static cache budgets sized from available memory"
    );
}

/// 🔎 The memory this process may use, or `None` when no source can be read.
fn available_memory() -> Option<u64> {
    cgroup_limit()
        .or_else(meminfo_available)
        .or_else(physical_memory)
}

/// 🔎 A cgroup memory limit, v2 first then v1. `max` and v1's near-`u64::MAX`
/// sentinel both mean "no limit", which is not a number to size caches from.
fn cgroup_limit() -> Option<u64> {
    [
        "/sys/fs/cgroup/memory.max",
        "/sys/fs/cgroup/memory/memory.limit_in_bytes",
    ]
    .into_iter()
    .find_map(|path| parse_cgroup_limit(&std::fs::read_to_string(path).ok()?))
}

/// 📏 The limit a cgroup file states, or `None` for an unlimited cgroup.
fn parse_cgroup_limit(text: &str) -> Option<u64> {
    let value = text.trim();
    if value.eq_ignore_ascii_case("max") {
        return None;
    }
    value
        .parse::<u64>()
        .ok()
        // 🔭 v1 writes 2^63-4096 for "unlimited"; no real memory limit is
        // anywhere near an exbibyte.
        .filter(|limit| *limit > 0 && *limit < 1 << 60)
}

/// 🔎 `MemAvailable` from `/proc/meminfo`, in bytes.
fn meminfo_available() -> Option<u64> {
    parse_meminfo_available(&std::fs::read_to_string("/proc/meminfo").ok()?)
}

/// 📏 The `MemAvailable:` line, whose value `/proc/meminfo` states in kB.
fn parse_meminfo_available(text: &str) -> Option<u64> {
    text.lines()
        .find_map(|line| line.strip_prefix("MemAvailable:"))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|kilobytes| kilobytes.parse::<u64>().ok())
        .map(|kilobytes| kilobytes.saturating_mul(1024))
}

/// 🔎 `hw.memsize` on macOS; other platforms use the sources above.
#[cfg(target_os = "macos")]
fn physical_memory() -> Option<u64> {
    let mut value: u64 = 0;
    let mut size = std::mem::size_of::<u64>();
    // 🛡️ `sysctlbyname` writes exactly `size` bytes into `value` and reports
    // success through its return value.
    let status = unsafe {
        libc::sysctlbyname(
            c"hw.memsize".as_ptr(),
            std::ptr::addr_of_mut!(value).cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    (status == 0 && value > 0).then_some(value)
}

/// 📌 Elsewhere the platform has no memory source wired up here.
#[cfg(not(target_os = "macos"))]
fn physical_memory() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cgroup_limit_is_read_in_both_spellings() {
        assert_eq!(parse_cgroup_limit("536870912\n"), Some(512 * 1024 * 1024));
        assert_eq!(parse_cgroup_limit("max"), None);
        // 🔭 cgroup v1's "unlimited" sentinel is not a limit.
        assert_eq!(parse_cgroup_limit("9223372036854771712"), None);
        assert_eq!(parse_cgroup_limit("0"), None);
        assert_eq!(parse_cgroup_limit("nonsense"), None);
    }

    #[test]
    fn meminfo_available_is_stated_in_kilobytes() {
        let meminfo = "MemTotal:       16319268 kB\n\
                       MemFree:         1045600 kB\n\
                       MemAvailable:    8392716 kB\n\
                       Buffers:          104400 kB\n";
        assert_eq!(parse_meminfo_available(meminfo), Some(8392716 * 1024));
        assert_eq!(parse_meminfo_available("MemTotal: 1 kB\n"), None);
    }
}
