// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔒 The HTTPS port never carries plaintext.
//!
//! The plain idea: a client that connects to port 443 — or to whatever
//! `https_port` names — is about to send a TLS ClientHello, and an operator who
//! reads `:443` in a configuration believes the traffic there is encrypted. A
//! plaintext listener on that port breaks both. A browser gets a handshake
//! failure, and any client that does speak plain HTTP to it sends its cookies
//! and `Authorization` header across the network in the clear.
//!
//! 🤡 Before this module, four spellings loaded without complaint and served
//! cleartext HTTP there: a native `HTTPListener(on: ":443")` without `.tls`,
//! a Pingclairfile `http://example.com:443`, `tls off` on the HTTPS port, and a
//! JSON document whose `plaintext_listen` named it. `validate` passed all four.
//!
//! The check runs in [`crate::compiler::validate_config`], so the Pingclairfile,
//! the native language, a JSON file and an Admin `/load` body are all refused
//! by the same rule. It judges each socket with
//! [`ServerConfig::requires_tls_on`] — the rule the runtime uses to install its
//! acceptor — so "refused here" and "would have been plaintext there" are the
//! same set.
//!
//! 📌 Load path only. Nothing here runs per request.

use crate::compiler::{CompileError, CompileResult};
use pingclair_core::config::{
    CONVENTIONAL_HTTPS_PORT, PingclairConfig, ServerConfig, listen_port, normalize_listen_addr,
};

/// 🔒 Refuses every plaintext socket on the HTTPS port.
pub(crate) fn refuse_plaintext_on_https_port(config: &PingclairConfig) -> CompileResult<()> {
    let http_port = config.global.http_port;
    let https_port = config.global.https_port;
    let is_https_port = |port: u16| port == CONVENTIONAL_HTTPS_PORT || port == https_port;

    // 🧭 The HTTP port is plaintext by definition: every site without TLS
    // derives its listener there, and so does the automatic HTTP→HTTPS
    // companion the runtime adds later, out of sight of this check.
    if is_https_port(http_port) {
        return Err(CompileError::InvalidServer {
            message: format!(
                "`http_port {http_port}` puts plaintext HTTP on the HTTPS port. Choose a \
                 different HTTP port"
            ),
        });
    }

    for server in &config.servers {
        for address in server.listen_addresses(http_port, https_port) {
            let Some(port) = listen_port(&address) else {
                continue;
            };
            if !is_https_port(port) || server.requires_tls_on(&address, http_port, https_port) {
                continue;
            }
            return Err(CompileError::InvalidServer {
                message: plaintext_refusal(server, &address),
            });
        }
    }

    // 🛠️ The Admin API speaks plaintext HTTP only, so the HTTPS port is not a
    // place it can listen either.
    if let Some(admin) = &config.admin
        && admin.enabled
        && listen_port(&normalize_listen_addr(&admin.listen)).is_some_and(is_https_port)
    {
        return Err(CompileError::InvalidServer {
            message: format!(
                "the Admin API listens on `{}`, the HTTPS port, and the Admin API is plaintext \
                 HTTP. Move it to another port",
                admin.listen
            ),
        });
    }
    Ok(())
}

/// 💬 Names the site, the socket, and the reason it would have been plaintext,
/// because the fix differs: drop an explicit plaintext declaration, or add TLS.
fn plaintext_refusal(server: &ServerConfig, address: &str) -> String {
    let site = server
        .name
        .as_deref()
        .or_else(|| server.names.first().map(String::as_str))
        .filter(|name| !name.is_empty() && *name != "_")
        .unwrap_or("a site without a name");
    let declared = server
        .plaintext_listen
        .iter()
        .any(|declared| normalize_listen_addr(declared) == address);
    let reason = if declared {
        "the configuration declares that socket plaintext (an `http://` address, `tls off`, \
         or a native listener without `.tls`)"
    } else {
        "it has no TLS"
    };
    format!(
        "{site} would serve plaintext HTTP on `{address}`, the HTTPS port, because {reason}. \
         Plaintext is refused on the HTTPS port: give the site TLS, or serve plaintext on \
         another port"
    )
}

#[cfg(test)]
mod tests {
    fn refusal(source: &str) -> String {
        crate::compile(source)
            .expect_err("plaintext on the HTTPS port must be refused")
            .to_string()
    }

    /// 🔒 An explicit `http://` address on 443 is refused, naming the cause.
    #[test]
    fn an_http_address_on_the_https_port_is_refused() {
        let message = refusal("http://example.test:443 {\n    respond \"x\"\n}\n");
        assert!(message.contains("`[::]:443`, the HTTPS port"), "{message}");
        assert!(
            message.contains("declares that socket plaintext"),
            "{message}"
        );
    }

    /// 📴 `tls off` cannot turn the HTTPS port into a plaintext listener.
    #[test]
    fn tls_off_on_the_https_port_is_refused() {
        let message = refusal("example.test:443 {\n    tls off\n    respond \"x\"\n}\n");
        assert!(
            message.contains("example.test would serve plaintext"),
            "{message}"
        );
    }

    /// 🌐 A native listener on 443 without `.tls` used to serve cleartext.
    #[test]
    fn a_native_listener_on_the_https_port_without_tls_is_refused() {
        let message = refusal(
            "HTTPListener(on: \":443\") {\n    Site(host: \"example.test\") {\n        \
             Fallback { Respond(body: \"x\") }\n    }\n}\n",
        );
        assert!(message.contains("the HTTPS port"), "{message}");
    }

    /// 🔢 A configured `https_port` is protected, and so is 443 beside it.
    #[test]
    fn a_custom_https_port_and_443_are_both_protected() {
        let custom = refusal(
            "{\n    https_port 8443\n}\nhttp://example.test:8443 {\n    respond \"x\"\n}\n",
        );
        assert!(custom.contains("`[::]:8443`, the HTTPS port"), "{custom}");
        let conventional =
            refusal("{\n    https_port 8443\n}\nhttp://example.test:443 {\n    respond \"x\"\n}\n");
        assert!(
            conventional.contains("`[::]:443`, the HTTPS port"),
            "{conventional}"
        );
    }

    /// 🧭 An HTTP port on the HTTPS port would host every plaintext site and
    /// every redirect companion there.
    #[test]
    fn an_http_port_on_the_https_port_is_refused() {
        let message = refusal("{\n    http_port 443\n}\nexample.test {\n    respond \"x\"\n}\n");
        assert!(message.contains("`http_port 443`"), "{message}");
    }

    /// 🛠️ The plaintext Admin API cannot take the HTTPS port.
    #[test]
    fn the_admin_api_on_the_https_port_is_refused() {
        let message = refusal("{\n    admin :443\n}\nexample.test {\n    respond \"x\"\n}\n");
        assert!(message.contains("Admin API"), "{message}");
    }

    /// 👍 TLS on the HTTPS port and plaintext elsewhere still load.
    #[test]
    fn tls_on_the_https_port_and_plaintext_elsewhere_load() {
        crate::compile(
            "example.test {\n    tls internal\n    respond \"tls\"\n}\n\
             http://example.test:8080 {\n    respond \"plain\"\n}\n",
        )
        .expect("TLS on 443 and plaintext on 8080 are both ordinary");
    }
}
