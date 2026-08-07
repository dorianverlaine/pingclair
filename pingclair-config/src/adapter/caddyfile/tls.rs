// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

use super::AdapterError;
use crate::parser::ast::*;
use crate::parser::caddy_ast::Directive;

// MARK: - 🔐 TLS Directive

/// 🔐 Adapts the supported downstream TLS directive forms.
pub(super) fn adapt_tls_directive(d: &Directive) -> Result<TlsDirective, AdapterError> {
    let mut tls = TlsDirective::default();

    // 📧 Positional arguments mean the same with and without a block, so they
    // are read once. A single argument containing `@` is the ACME account
    // email, decided exactly the way upstream decides it; anything else on
    // its own is refused rather than silently dropped when a block follows.
    match d.args.as_slice() {
        [] => {}
        [arg] if arg == "off" => tls.off = true,
        [arg] if arg == "auto" => tls.auto = true,
        [arg] if arg == "internal" => tls.internal = true,
        [arg] if arg.contains('@') => tls.acme_email = Some(arg.clone()),
        [arg] if arg == "force_automate" => {
            return Err(AdapterError::UnsupportedFeature(
                "tls force_automate".into(),
                "Pingclair does not implement certificate force-automation yet".into(),
            ));
        }
        [cert, key] => {
            tls.cert = Some(cert.clone());
            tls.key = Some(key.clone());
        }
        _ => {
            return Err(AdapterError::InvalidArgument(
                "tls".into(),
                "expected 'off', 'auto', 'internal', an email address, '<cert> <key>', \
                 or a block"
                    .into(),
            ));
        }
    }

    if let Some(block) = &d.block {
        for sub in &block.directives {
            match sub.name.as_str() {
                "cert" => tls.cert = sub.args.first().cloned(),
                "key" => tls.key = sub.args.first().cloned(),
                "acme_email" | "email" => tls.acme_email = sub.args.first().cloned(),
                "auto" => tls.auto = true,
                "internal" => {
                    if !sub.args.is_empty() {
                        return Err(AdapterError::InvalidArgument(
                            "tls internal".into(),
                            "expected no arguments".into(),
                        ));
                    }
                    tls.internal = true;
                }
                "http3" => {
                    tls.http3 = Some(
                        sub.args
                            .first()
                            .map(|s| s != "off" && s != "false")
                            .unwrap_or(true),
                    );
                }
                // 🚫 TLS options the format defines and this crate does not
                // implement. Almost all of them belong to two subsystems we do
                // not have — certificate issuance beyond the built-in local
                // authority, and mutual TLS — so the honest answer is to name
                // the feature rather than the word.
                //
                // 📌 Getting this wrong is worse here than elsewhere: an
                // operator debugging why `client_auth` did nothing, told the
                // word is unknown, will assume they misspelled a TLS setting
                // and go looking for the right spelling of a feature that does
                // not exist.
                name if is_known_tls_option(name) => {
                    return Err(AdapterError::UnsupportedFeature(
                        format!("tls {name}"),
                        "Pingclair does not implement this TLS option yet".into(),
                    ));
                }
                _ => return Err(AdapterError::UnknownDirective(format!("tls: {}", sub.name))),
            }
        }
    }

    // 🚫 `tls off` with a block contradicts itself — one half says there is
    // no TLS and the other configures it — so the combination is refused
    // rather than letting one half win silently.
    if tls.off && d.block.is_some() {
        return Err(AdapterError::InvalidArgument(
            "tls".into(),
            "off cannot be combined with a block".into(),
        ));
    }

    // 🔗 A certificate without its matching private key is unusable.
    if tls.cert.is_some() != tls.key.is_some() {
        return Err(AdapterError::InvalidArgument(
            "tls".into(),
            "cert and key must be specified together".into(),
        ));
    }

    // 🛡️ A local issuer must never fall through to manual or public issuance.
    if tls.internal && (tls.auto || tls.cert.is_some() || tls.acme_email.is_some()) {
        return Err(AdapterError::InvalidArgument(
            "tls".into(),
            "internal cannot be combined with auto, cert/key, or an ACME email".into(),
        ));
    }

    Ok(tls)
}

/// 🧾 TLS block options the format defines, whether or not we implement them.
///
/// Two clusters, and neither is a small gap: certificate issuance beyond the
/// built-in local authority (`issuer`, `ca`, `eab`, `dns` and its timers,
/// `on_demand`, `get_certificate`), and mutual TLS (`client_auth`). Both are
/// subsystems rather than options, which is exactly why they need to be told
/// apart from a misspelling.
fn is_known_tls_option(name: &str) -> bool {
    matches!(
        name,
        "protocols"
            | "ciphers"
            | "curves"
            | "client_auth"
            | "alpn"
            | "load"
            | "ca"
            | "ca_root"
            | "key_type"
            | "eab"
            | "issuer"
            | "get_certificate"
            | "dns"
            | "resolvers"
            | "propagation_delay"
            | "propagation_timeout"
            | "dns_ttl"
            | "dns_challenge_override_domain"
            | "on_demand"
            | "reuse_private_keys"
            | "insecure_secrets_log"
            | "renewal_window_ratio"
            | "force_automate"
    )
}
