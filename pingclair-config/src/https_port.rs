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
//! 📴 One exception, matching the reference: under `auto_https off` the
//! operator has turned automatic HTTPS off on purpose, and a site with no TLS
//! policy serves plaintext wherever it listens. The plaintext Admin API and an
//! `http_port` on the HTTPS port stay refused even then.
//!
//! 📌 Load path only. Nothing here runs per request.

use crate::compiler::{CompileError, CompileResult};
use pingclair_core::config::{
    AutoHttpsMode, CONVENTIONAL_HTTPS_PORT, PingclairConfig, ServerConfig, listen_port,
    normalize_listen_addr,
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

    // 📴 `auto_https off` is the operator turning automatic HTTPS off on
    // purpose, and a site with no TLS policy then serves plaintext wherever it
    // listens, the HTTPS port included — the reference behaves the same way.
    // Every other route to plaintext there is still refused below.
    if config.global.auto_https == AutoHttpsMode::Off {
        return refuse_admin_on_https_port(config, is_https_port);
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

    refuse_admin_on_https_port(config, is_https_port)
}

/// 🛠️ The Admin API speaks plaintext HTTP only, so the HTTPS port is not a
/// place it can listen either, whatever `auto_https` says.
fn refuse_admin_on_https_port(
    config: &PingclairConfig,
    is_https_port: impl Fn(u16) -> bool,
) -> CompileResult<()> {
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
        "the configuration declares that socket plaintext (an `http://` address, a JSON \
         `plaintext_listen` entry, or a native listener without `.tls`)"
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

    /// 🔒 A JSON document reaches this check without any adapter, so it is
    /// the path that proves the rule: `plaintext_listen` on 443 is refused.
    #[test]
    fn a_json_plaintext_listener_on_the_https_port_is_refused() {
        let mut config = pingclair_core::config::PingclairConfig::default();
        config.servers.push(pingclair_core::config::ServerConfig {
            name: Some("example.test".to_string()),
            listen: vec![":443".to_string()],
            plaintext_listen: vec![":443".to_string()],
            ..Default::default()
        });
        let message = crate::compiler::validate_config(&config)
            .expect_err("plaintext on the HTTPS port must be refused")
            .to_string();
        assert!(message.contains("`[::]:443`, the HTTPS port"), "{message}");
        assert!(
            message.contains("declares that socket plaintext"),
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

    /// 🔢 With `https_port 8443`, 443 is still protected. The address check
    /// in the Pingclairfile adapter only knows the configured HTTPS port, so
    /// this is the rule that catches plaintext on 443 beside it.
    #[test]
    fn port_443_is_protected_beside_a_custom_https_port() {
        let message =
            refusal("{\n    https_port 8443\n}\nhttp://example.test:443 {\n    respond \"x\"\n}\n");
        assert!(message.contains("`[::]:443`, the HTTPS port"), "{message}");
    }

    /// 🧭 An HTTP port on the HTTPS port would host every plaintext site and
    /// every redirect companion there.
    #[test]
    fn an_http_port_on_the_https_port_is_refused() {
        let message = refusal("{\n    http_port 443\n}\nexample.test {\n    respond \"x\"\n}\n");
        assert!(message.contains("`http_port 443`"), "{message}");
    }

    /// 📴 `auto_https off` with a nameless `:443` and no `tls` serves
    /// plaintext, as the reference does; a named site there keeps TLS.
    #[test]
    fn auto_https_off_lets_a_nameless_https_port_site_serve_plaintext() {
        let config = crate::compile("{\n    auto_https off\n}\n:443 {\n    respond \"x\"\n}\n")
            .expect("auto_https off makes a nameless :443 plaintext");
        let server = &config.servers[0];
        assert_eq!(
            (server.tls.is_none(), server.plaintext_listen.as_slice()),
            (true, ["[::]:443".to_string()].as_slice())
        );

        let named =
            crate::compile("{\n    auto_https off\n}\nexample.test:443 {\n    respond \"x\"\n}\n")
                .expect("a named site keeps its TLS policy");
        assert!(named.servers[0].requires_tls_on("[::]:443", 80, 443));
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
