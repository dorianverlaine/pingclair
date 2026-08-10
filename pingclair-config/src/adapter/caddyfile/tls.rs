// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

use super::AdapterError;
use crate::parser::ast::*;
use crate::parser::caddy_ast::Directive;
use pingclair_core::config::{ClientAuthConfig, ClientAuthMode, TrustPool};

// MARK: - 🔐 TLS Directive

/// 🏷️ Reads the one server name a `default_sni` may carry.
///
/// Shared by the site-level `tls { default_sni … }` and the global option of
/// the same name, so the two spellings cannot drift into accepting different
/// things — the failure this repository has already had once, when a flat
/// alias took milliseconds where its block form took seconds.
pub(super) fn parse_default_sni(d: &Directive) -> Result<String, AdapterError> {
    match d.args.as_slice() {
        [name] if !name.is_empty() => Ok(name.clone()),
        // 🚫 An empty or missing name would select nothing, which is the state
        // this option exists to get out of.
        [] => Err(AdapterError::ArgumentCount("default_sni".into(), 1, 0)),
        args => Err(AdapterError::ArgumentCount(
            "default_sni".into(),
            1,
            args.len(),
        )),
    }
}

/// 🛡️ Deepest `trust_pool combined { source combined { … } }` nesting accepted.
///
/// `combined` is recursive, and the Admin API deserialises straight into these
/// types, so the nesting an attacker can express is the nesting the parser has
/// to survive. Nothing legitimate nests trust pools more than a couple deep;
/// this mirrors the bound matchers already carry for the same reason.
const MAX_TRUST_POOL_DEPTH: usize = 8;

/// 🪪 Reads `client_auth { … }` into a typed configuration.
///
/// ⚠️ Parsing it is not enforcing it. Nothing in the acceptor checks a client
/// certificate yet, which is why `validate_config` refuses a configuration that
/// asks for one: a site that believes it requires mutual TLS and does not is a
/// worse outcome than a site that will not start.
fn parse_client_auth(d: &Directive) -> Result<ClientAuthConfig, AdapterError> {
    let mut auth = ClientAuthConfig::default();
    let mut mode_given = false;

    let Some(block) = &d.block else {
        return Err(AdapterError::InvalidArgument(
            "tls client_auth".into(),
            "block required, e.g. `client_auth { mode require_and_verify }`".into(),
        ));
    };

    for sub in &block.directives {
        match sub.name.as_str() {
            "mode" => {
                let value = expect_single(sub, "client_auth mode")?;
                auth.mode = match value.as_str() {
                    "request" => ClientAuthMode::Request,
                    "require" => ClientAuthMode::Require,
                    "verify_if_given" => ClientAuthMode::VerifyIfGiven,
                    "require_and_verify" => ClientAuthMode::RequireAndVerify,
                    // 🚫 A misspelled mode must not fall back to a weaker one.
                    other => {
                        return Err(AdapterError::InvalidArgument(
                            "tls client_auth mode".into(),
                            format!(
                                "unknown mode `{other}` (expected request, require, \
                                 verify_if_given or require_and_verify)"
                            ),
                        ));
                    }
                };
                mode_given = true;
            }
            "trusted_ca_cert" => auth
                .trusted_ca_certs
                .push(expect_single(sub, "client_auth trusted_ca_cert")?),
            "trusted_ca_cert_file" => auth
                .trusted_ca_cert_files
                .push(expect_single(sub, "client_auth trusted_ca_cert_file")?),
            "trusted_leaf_cert" => auth
                .trusted_leaf_certs
                .push(expect_single(sub, "client_auth trusted_leaf_cert")?),
            "trusted_leaf_cert_file" => auth
                .trusted_leaf_cert_files
                .push(expect_single(sub, "client_auth trusted_leaf_cert_file")?),
            "trust_pool" => auth.trust_pool = Some(parse_trust_pool(sub, 0)?),
            // 🚫 `verifier` selects a pluggable module, and we have no module
            // registry. Accepting the word would mean an operator's custom
            // verification silently never running.
            "verifier" => {
                return Err(AdapterError::UnsupportedFeature(
                    "tls client_auth verifier".into(),
                    "client-certificate verifier modules are not implemented".into(),
                ));
            }
            other => {
                return Err(AdapterError::UnknownDirective(format!(
                    "client_auth: {other}"
                )));
            }
        }
    }

    // 🚫 Upstream refuses the two spellings together, because each one is a
    // complete answer to the same question and there is no rule for merging
    // them.
    if auth.trust_pool.is_some()
        && !(auth.trusted_ca_certs.is_empty() && auth.trusted_ca_cert_files.is_empty())
    {
        return Err(AdapterError::InvalidArgument(
            "tls client_auth".into(),
            "cannot specify both `trust_pool` and `trusted_ca_cert`/`trusted_ca_cert_file`".into(),
        ));
    }

    // 🎚️ Upstream's default: verifying makes sense once there is something to
    // verify against, so a trust pool implies the strict mode and its absence
    // means the certificate is only demanded.
    if !mode_given {
        auth.mode = if auth.trust_pool.is_some() {
            ClientAuthMode::RequireAndVerify
        } else {
            ClientAuthMode::Require
        };
    }
    Ok(auth)
}

/// 🏛️ Reads one `trust_pool <provider> { … }`, bounded against deep nesting.
fn parse_trust_pool(d: &Directive, depth: usize) -> Result<TrustPool, AdapterError> {
    if depth > MAX_TRUST_POOL_DEPTH {
        return Err(AdapterError::InvalidArgument(
            "tls client_auth trust_pool".into(),
            format!("nested more than {MAX_TRUST_POOL_DEPTH} levels deep"),
        ));
    }
    let provider = d
        .args
        .first()
        .ok_or_else(|| AdapterError::ArgumentCount("tls client_auth trust_pool".into(), 1, 0))?;
    let directives = d
        .block
        .as_ref()
        .map(|block| block.directives.as_slice())
        .unwrap_or_default();

    match provider.as_str() {
        "inline" => {
            let mut trust_der = Vec::new();
            for sub in directives {
                match sub.name.as_str() {
                    "trust_der" => trust_der.extend(sub.args.iter().cloned()),
                    other => {
                        return Err(AdapterError::UnknownDirective(format!(
                            "trust_pool inline: {other}"
                        )));
                    }
                }
            }
            Ok(TrustPool::Inline { trust_der })
        }
        "file" => {
            let mut pem_files = Vec::new();
            for sub in directives {
                match sub.name.as_str() {
                    "pem_file" => pem_files.extend(sub.args.iter().cloned()),
                    other => {
                        return Err(AdapterError::UnknownDirective(format!(
                            "trust_pool file: {other}"
                        )));
                    }
                }
            }
            Ok(TrustPool::File { pem_files })
        }
        "system" => Ok(TrustPool::System),
        "combined" => {
            let mut sources = Vec::new();
            for sub in directives {
                match sub.name.as_str() {
                    "source" => sources.push(parse_trust_pool(sub, depth + 1)?),
                    other => {
                        return Err(AdapterError::UnknownDirective(format!(
                            "trust_pool combined: {other}"
                        )));
                    }
                }
            }
            Ok(TrustPool::Combined { sources })
        }
        // 🚫 `pki_root`, `pki_intermediate` and `storage` all read from
        // subsystems this build does not have.
        other => Err(AdapterError::UnsupportedFeature(
            format!("tls client_auth trust_pool {other}"),
            "only inline, file, system and combined are implemented".into(),
        )),
    }
}

/// 🔢 Reads a subdirective that takes exactly one argument.
fn expect_single(d: &Directive, name: &str) -> Result<String, AdapterError> {
    match d.args.as_slice() {
        [value] => Ok(value.clone()),
        args => Err(AdapterError::ArgumentCount(name.into(), 1, args.len())),
    }
}

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
                "default_sni" => tls.default_sni = Some(parse_default_sni(sub)?),
                "client_auth" => tls.client_auth = Some(parse_client_auth(sub)?),
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

#[cfg(test)]
mod client_auth_tests {
    use super::*;
    use crate::compile;
    use pingclair_core::config::{ClientAuthMode, TrustPool};

    fn client_auth_of(source: &str) -> ClientAuthConfig {
        compile(source)
            .expect("must compile")
            .servers
            .remove(0)
            .tls
            .expect("tls")
            .client_auth
            .expect("client_auth")
    }

    /// 🎚️ Each mode keeps its own meaning; none collapses into a weaker one.
    #[test]
    fn every_mode_keeps_its_own_meaning() {
        for (written, expected) in [
            ("request", ClientAuthMode::Request),
            ("require", ClientAuthMode::Require),
            ("verify_if_given", ClientAuthMode::VerifyIfGiven),
            ("require_and_verify", ClientAuthMode::RequireAndVerify),
        ] {
            let auth = client_auth_of(&format!(
                "localhost {{\n\ttls {{\n\t\tclient_auth {{\n\t\t\tmode {written}\n\t\t}}\n\t}}\n\trespond \"ok\"\n}}"
            ));
            assert_eq!(auth.mode, expected, "mode {written}");
        }
    }

    /// 🚫 A misspelled mode must not fall back to a weaker one.
    #[test]
    fn an_unknown_mode_is_refused_rather_than_defaulted() {
        let error = compile(
            "localhost {\n\ttls {\n\t\tclient_auth {\n\t\t\tmode requre_and_verify\n\t\t}\n\t}\n\trespond \"ok\"\n}",
        )
        .expect_err("a typo in the mode must not silently weaken it");
        assert!(format!("{error}").contains("unknown mode"), "{error}");
    }

    /// 🎚️ Upstream's default: a trust pool implies verifying, its absence does not.
    #[test]
    fn the_default_mode_follows_whether_there_is_anything_to_verify_against() {
        let with_pool = client_auth_of(
            "localhost {\n\ttls {\n\t\tclient_auth {\n\t\t\ttrust_pool system\n\t\t}\n\t}\n\trespond \"ok\"\n}",
        );
        assert_eq!(with_pool.mode, ClientAuthMode::RequireAndVerify);

        let without = client_auth_of(
            "localhost {\n\ttls {\n\t\tclient_auth {\n\t\t\ttrusted_leaf_cert AAAA\n\t\t}\n\t}\n\trespond \"ok\"\n}",
        );
        assert_eq!(without.mode, ClientAuthMode::Require);
    }

    /// 🧩 `combined` nests, and the shape survives compilation.
    #[test]
    fn a_combined_pool_keeps_its_sources_in_order() {
        let auth = client_auth_of(
            "localhost {\n\ttls {\n\t\tclient_auth {\n\t\t\ttrust_pool combined {\n\t\t\t\tsource inline {\n\t\t\t\t\ttrust_der AAAA BBBB\n\t\t\t\t}\n\t\t\t\tsource system\n\t\t\t}\n\t\t}\n\t}\n\trespond \"ok\"\n}",
        );
        let TrustPool::Combined { sources } = auth.trust_pool.expect("trust pool") else {
            panic!("expected a combined pool");
        };
        assert_eq!(sources.len(), 2);
        assert_eq!(
            sources[0],
            TrustPool::Inline {
                trust_der: vec!["AAAA".to_string(), "BBBB".to_string()]
            }
        );
        assert_eq!(sources[1], TrustPool::System);
    }

    /// 🛡️ Nesting is bounded, because the Admin API deserialises into this type.
    ///
    /// An untagged recursive type already produced a remotely triggerable stack
    /// overflow in this codebase once; a bound is the other half of not
    /// repeating it.
    #[test]
    fn deeply_nested_pools_are_refused_rather_than_overflowing() {
        let depth = MAX_TRUST_POOL_DEPTH + 4;
        let mut body = "trust_pool combined {\n".to_string();
        for _ in 0..depth {
            body.push_str("source combined {\n");
        }
        body.push_str("source system\n");
        for _ in 0..=depth {
            body.push_str("}\n");
        }
        let error = compile(&format!(
            "localhost {{\n\ttls {{\n\t\tclient_auth {{\n{body}\t\t}}\n\t}}\n\trespond \"ok\"\n}}"
        ))
        .expect_err("nesting past the bound must be refused");
        assert!(format!("{error}").contains("levels deep"), "{error}");
    }

    /// 🚫 The two ways of naming a trust source cannot both be given.
    #[test]
    fn a_trust_pool_and_the_legacy_spelling_cannot_both_be_given() {
        let error = compile(
            "localhost {\n\ttls {\n\t\tclient_auth {\n\t\t\ttrust_pool system\n\t\t\ttrusted_ca_cert AAAA\n\t\t}\n\t}\n\trespond \"ok\"\n}",
        )
        .expect_err("each is a complete answer; there is no rule for merging them");
        assert!(
            format!("{error}").contains("cannot specify both"),
            "{error}"
        );
    }

    /// 🚫 A verifier module is refused rather than accepted and never run.
    #[test]
    fn a_verifier_module_is_refused_by_name() {
        let error = compile(
            "localhost {\n\ttls {\n\t\tclient_auth {\n\t\t\tverifier leaf\n\t\t}\n\t}\n\trespond \"ok\"\n}",
        )
        .expect_err("an unimplemented verifier must not look configured");
        assert!(format!("{error}").contains("verifier"), "{error}");
    }
}
