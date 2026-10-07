// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 📡 The subcommands that reach outside this process.
//!
//! `reload`, `stop`, `trust` and `untrust` are the odd ones out: every other
//! subcommand either starts a server or reads a file, while these three talk to
//! something that already exists — a Pingclair already running on the admin
//! port, or the operating system's trust store.
//!
//! That is why the HTTP client here is thirty lines of `TcpStream` rather than
//! a dependency. Two requests with no body to parse do not justify pulling an
//! HTTP client into the production binary, and the dependency tree of a TLS
//! server is a thing worth keeping small on purpose.

use crate::paths::tls_store_dir;

/// 🧾 Parses a `Field: value` CLI argument into a header pair, like Caddy's
/// `--header-up "X-Foo: bar"`.
pub(crate) fn parse_header_pair(raw: &str) -> Result<(String, String), String> {
    let Some((name, value)) = raw.split_once(':') else {
        return Err(format!(
            "expected `Field: value`, got `{raw}` (the colon is required)"
        ));
    };
    Ok((name.trim().to_string(), value.trim().to_string()))
}

/// 📡 Minimal HTTP/1.1 client for the Admin API (`reload`/`stop`).
///
/// The production binary has no HTTP client dependency; a tiny request is
/// enough for these two commands and keeps the dependency tree unchanged.
/// The second half of the returned pair is the response *body* — the part
/// that names a failure — not the raw response including its status line.
pub(crate) fn admin_request(
    method: &str,
    path: &str,
    content_type: Option<&str>,
    body: Option<&str>,
    address: &str,
) -> anyhow::Result<(u16, String)> {
    use std::io::{Read, Write};

    let body_bytes = body.unwrap_or("");
    let mut stream = std::net::TcpStream::connect(address)
        .map_err(|error| anyhow::anyhow!("❌ Cannot reach admin API at {address}: {error}"))?;
    let mut request =
        format!("{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n");
    if let Some(content_type) = content_type {
        request.push_str(&format!("Content-Type: {content_type}\r\n"));
    }
    request.push_str(&format!("Content-Length: {}\r\n\r\n", body_bytes.len()));
    stream.write_all(request.as_bytes())?;
    if !body_bytes.is_empty() {
        stream.write_all(body_bytes.as_bytes())?;
    }

    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let status = response
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);
    Ok((status, response_body(&response)))
}

/// 🧾 The part of a raw HTTP response that follows the header block.
///
/// Callers print this when a request fails, because the status line only says
/// *that* something went wrong. The body is where the server names the reason
/// — a masked secret, a matcher it could not read — and it used to be dropped
/// on the floor here, which is how a 400 became `HTTP/1.1 400 Bad Request`.
fn response_body(response: &str) -> String {
    response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or("")
        .to_string()
}

/// 🔐 Installs or removes the internal CA root from the system trust store.
///
/// Caddy's `trust`/`untrust` do the same for its local CA. Linux needs the
/// root CA copied under `/usr/local/share/ca-certificates` (hence sudo) and
/// `update-ca-certificates`; macOS uses the `security` tool.
pub(crate) fn trust_internal_ca(trust: bool) -> anyhow::Result<()> {
    let root = tls_store_dir().join("pki/authorities/local/root.crt");
    if !root.is_file() {
        anyhow::bail!(
            "❌ No internal CA root at {} (start a localhost site first)",
            root.display()
        );
    }

    #[cfg(target_os = "macos")]
    {
        let action = if trust {
            "add-trusted-cert"
        } else {
            "remove-trusted-cert"
        };
        let status = std::process::Command::new("security")
            .args([action, "-d", "-r", "trustRoot", root.to_str().unwrap()])
            .status()
            .map_err(|error| anyhow::anyhow!("❌ Failed to run security: {error}"))?;
        if !status.success() {
            anyhow::bail!("❌ `security {action}` failed (exit {status})");
        }
        println!(
            "✅ Internal CA root {} the macOS trust store",
            if trust { "added to" } else { "removed from" }
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    {
        let destination = "/usr/local/share/ca-certificates/pingclair-root.crt";
        if trust {
            let status = std::process::Command::new("sudo")
                .args(["install", "-m", "644", root.to_str().unwrap(), destination])
                .status()
                .map_err(|error| anyhow::anyhow!("❌ Failed to run sudo install: {error}"))?;
            if !status.success() {
                anyhow::bail!(
                    "❌ Failed to install the root certificate (exit {status}); \
                     run with sudo"
                );
            }
            let status = std::process::Command::new("sudo")
                .args(["update-ca-certificates"])
                .status()
                .map_err(|error| {
                    anyhow::anyhow!("❌ Failed to run update-ca-certificates: {error}")
                })?;
            if !status.success() {
                anyhow::bail!("❌ update-ca-certificates failed (exit {status})");
            }
            println!("✅ Internal CA root installed into the system trust store");
        } else {
            let status = std::process::Command::new("sudo")
                .args(["rm", "-f", destination])
                .status()
                .map_err(|error| {
                    anyhow::anyhow!("❌ Failed to remove the root certificate: {error}")
                })?;
            if !status.success() {
                anyhow::bail!("❌ Failed to remove the root certificate (exit {status})");
            }
            let status = std::process::Command::new("sudo")
                .args(["update-ca-certificates", "--fresh"])
                .status()
                .map_err(|error| {
                    anyhow::anyhow!("❌ Failed to run update-ca-certificates: {error}")
                })?;
            if !status.success() {
                anyhow::bail!("❌ update-ca-certificates failed (exit {status})");
            }
            println!("✅ Internal CA root removed from the system trust store");
        }
        Ok(())
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (trust, root);
        anyhow::bail!("❌ System trust management is only supported on macOS and Linux");
    }
}

#[cfg(test)]
mod tests {
    use super::response_body;

    /// 🧾 The body, not the status line, is what a caller can act on.
    #[test]
    fn test_response_body_is_what_follows_the_header_block() {
        let response = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n\r\nInvalid config: a \
             tagged matcher";
        assert_eq!(response_body(response), "Invalid config: a tagged matcher");
        // A response that never finished its headers has no body to print.
        assert_eq!(response_body("HTTP/1.1 400 Bad Request\r\n"), "");
    }
}
