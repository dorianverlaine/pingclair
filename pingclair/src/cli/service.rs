// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🛠️ `pingclair service …`, which is a thin wrapper over `systemctl`.
//!
//! Almost all of this module is the non-Linux branch, and that is on purpose.
//! `systemctl` exists only under systemd, so on macOS — where this is developed
//! and where the test below runs — the honest answer is a clear refusal rather
//! than a shell-out that fails with something cryptic. The deployment contract
//! on those platforms is the unit file in `scripts/`, not this command.

use super::ServiceAction;

/// 🛠️ Manages the systemd unit (Linux) or explains that service management is
/// unavailable (other platforms). systemctl itself is Linux-only, so the
/// non-Linux branch is the one local macOS tests exercise.
pub(crate) fn manage_system_service(action: ServiceAction) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let cmd = match action {
            ServiceAction::Start => "start",
            ServiceAction::Stop => "stop",
            ServiceAction::Restart => "restart",
            ServiceAction::Reload => "reload",
            ServiceAction::Status => "status",
        };

        tracing::info!("🛠️ Managing service: {}", cmd);
        let status = std::process::Command::new("systemctl")
            .arg(cmd)
            .arg("pingclair")
            .status();

        match status {
            Ok(s) if s.success() => {
                let past_tense = match action {
                    ServiceAction::Start => "started",
                    ServiceAction::Stop => "stopped",
                    ServiceAction::Restart => "restarted",
                    ServiceAction::Reload => "reloaded",
                    ServiceAction::Status => "queried",
                };
                println!("✅ Service {past_tense} successfully");
            }
            Ok(s) => {
                anyhow::bail!("❌ Failed to {cmd} service (exit code: {s})");
            }
            Err(e) => {
                anyhow::bail!("❌ Failed to execute systemctl: {e}");
            }
        }
        Ok(())
    }

    // 🚫 macOS and other non-Linux platforms have no systemctl; the systemd
    // unit shipped in scripts/ is the deployment contract instead.
    #[cfg(not(target_os = "linux"))]
    {
        let _ = action;
        anyhow::bail!("❌ Service management is only supported on Linux (systemd).");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 🚫 On non-Linux platforms (including local macOS), the service
    /// subcommand must fail with a clear message instead of pretending to run
    /// systemctl.
    #[test]
    #[cfg(not(target_os = "linux"))]
    fn service_management_reports_linux_only() {
        let error = manage_system_service(ServiceAction::Start)
            .expect_err("service management must fail outside Linux");
        assert!(
            error.to_string().contains("Linux"),
            "the message must explain the platform limit: {error}"
        );
    }
}
