// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔐 The `.tls(...)` modifier: certificate variants, client authentication
//! and the DNS-01 cluster.

use super::*;
use pingclair_core::config::{
    ClientAuthConfig, ClientAuthMode, DnsProviderConfig, SecretString, TrustPool,
};

/// 🏷️ The named settings `.tls(...)` accepts.
///
/// 📌 The positional variant (`.automatic`, `.internal`, `.files`) is not a
/// label; `describe` reports these names as the settings an operator can add
/// beside it.
pub(crate) const TLS_LABELS: &[&str] = &[
    "defaultSNI",
    "clientAuth",
    "renewalWindow",
    "ocspStapling",
    "resolvers",
    "dnsTTL",
    "propagationDelay",
    "propagationTimeout",
    "overrideDomain",
];

/// 🛡️ Deepest `.combined([...])` nesting accepted, mirroring the runtime's
/// bound: the Admin API deserialises straight into these types, so the nesting
/// a parser accepts is the nesting the verifier has to survive.
const MAX_TRUST_POOL_DEPTH: usize = 8;

/// 🔐 One parsed `.tls(...)`.
pub(super) struct ParsedTls {
    pub(super) config: TlsConfig,
    /// 📴 Whether this modifier wrote `ocspStapling: .off`. The record is
    /// process-wide because this build never staples: `.off` describes the
    /// state in force rather than changing it.
    pub(super) ocsp_stapling_off: bool,
}

/// 🔐 Parses one `.tls(...)`.
///
/// 📌 A site passes its listener's configuration as `base`: the site's
/// modifier then starts from it and overrides only what it writes down, which
/// is what "a site overrides its listener" has to mean for a site that adds
/// one setting.
pub(super) fn parse_tls(modifier: &Call, base: Option<&TlsConfig>) -> Result<ParsedTls, Error> {
    if modifier.body.is_some() {
        return Err(modifier.at.error("tls does not take a block"));
    }

    let mut variant: Option<&Call> = None;
    let mut settings: Vec<(&str, &Value)> = Vec::new();
    for (label, value) in &modifier.args {
        let Some(label) = label.as_deref() else {
            if variant.is_some() {
                return Err(modifier
                    .at
                    .error("tls takes one variant: .automatic, .internal or .files"));
            }
            let Value::Typed(call) = value else {
                return Err(modifier
                    .at
                    .error("tls takes one variant: .automatic, .internal or .files"));
            };
            variant = Some(call);
            continue;
        };
        if !TLS_LABELS.contains(&label) {
            return Err(modifier.at.error(format!("unknown tls setting `{label}`")));
        }
        if settings.iter().any(|(name, _)| *name == label) {
            return Err(modifier
                .at
                .error(format!("duplicate tls setting `{label}`")));
        }
        settings.push((label, value));
    }
    if variant.is_none() && settings.is_empty() {
        return Err(modifier.at.error(
            "tls needs one variant (.automatic, .internal or .files) or at least one setting \
             such as defaultSNI: or clientAuth:",
        ));
    }

    let mut config = base.cloned().unwrap_or_default();
    if let Some(variant) = variant {
        apply_variant(variant, &mut config)?;
    }

    let mut ocsp_stapling_off = false;
    let mut dns_touched = false;
    for (name, value) in settings {
        match name {
            "defaultSNI" => {
                config.default_sni = Some(non_empty_string(value, "defaultSNI", modifier.at)?);
            }
            "clientAuth" => {
                config.client_auth = Some(parse_client_auth(value, modifier.at)?);
            }
            "renewalWindow" => {
                config.renewal_window_ratio = Some(parse_ratio(value, modifier.at)?);
            }
            "ocspStapling" => {
                parse_ocsp(value, modifier.at)?;
                ocsp_stapling_off = true;
            }
            "resolvers" => {
                dns_touched = true;
                let resolvers = string_list(value, "resolvers", modifier.at)?;
                config.dns_challenge.get_or_insert_default().resolvers = resolvers;
            }
            "dnsTTL" => {
                dns_touched = true;
                let seconds = duration_secs(value, "dnsTTL", modifier.at)?;
                config.dns_challenge.get_or_insert_default().ttl_secs = Some(seconds);
            }
            "propagationDelay" => {
                dns_touched = true;
                let seconds = duration_secs(value, "propagationDelay", modifier.at)?;
                config
                    .dns_challenge
                    .get_or_insert_default()
                    .propagation_delay_secs = Some(seconds);
            }
            "propagationTimeout" => {
                dns_touched = true;
                let seconds = duration_secs(value, "propagationTimeout", modifier.at)?;
                config
                    .dns_challenge
                    .get_or_insert_default()
                    .propagation_timeout_secs = Some(seconds);
            }
            "overrideDomain" => {
                dns_touched = true;
                config
                    .dns_challenge
                    .get_or_insert_default()
                    .challenge_override_domain =
                    Some(non_empty_string(value, "overrideDomain", modifier.at)?);
            }
            other => {
                return Err(modifier.at.error(format!("unknown tls setting `{other}`")));
            }
        }
    }
    // 🚫 The DNS settings describe DNS-01. On a manual or internal
    // certificate they would record a provider that never runs, so they are
    // refused instead of quietly stored.
    if dns_touched && !config.auto {
        return Err(modifier.at.error(
            "the DNS settings describe DNS-01, which needs `.automatic`; a manual or internal \
             certificate never asks a DNS provider",
        ));
    }
    Ok(ParsedTls {
        config,
        ocsp_stapling_off,
    })
}

/// 🧭 Applies the one positional variant, replacing whichever acquisition mode
/// the base configuration was in.
fn apply_variant(variant: &Call, config: &mut TlsConfig) -> Result<(), Error> {
    match variant.name.as_str() {
        "internal" => {
            expect_bare(variant, ".internal")?;
            config.auto = false;
            config.internal = true;
            config.cert = None;
            config.key = None;
            config.acme_email = None;
            config.dns_challenge = None;
        }
        "automatic" => {
            let (email, challenge) = automatic_arguments(variant)?;
            config.auto = true;
            config.internal = false;
            config.cert = None;
            config.key = None;
            if let Some(email) = email {
                config.acme_email = Some(non_empty_string(email, "email", variant.at)?);
            }
            if let Some(challenge) = challenge {
                let provider = parse_challenge(challenge, variant.at)?;
                config.dns_challenge.get_or_insert_default().provider = Some(provider);
            }
        }
        "files" => {
            let (certificate, key) = file_arguments(variant)?;
            config.cert = Some(non_empty_string(certificate, "certificate", variant.at)?);
            config.key = Some(non_empty_string(key, "key", variant.at)?);
            config.auto = false;
            config.internal = false;
            config.acme_email = None;
            config.dns_challenge = None;
        }
        other => {
            return Err(variant.at.error(format!(
                "unknown TLS variant `.{other}`; expected .automatic, .internal or .files"
            )));
        }
    }
    Ok(())
}

/// 📧 The labeled arguments of `.automatic(email:, challenge:)`.
fn automatic_arguments(variant: &Call) -> Result<(Option<&Value>, Option<&Value>), Error> {
    if variant.body.is_some() {
        return Err(variant.at.error(".automatic does not take a block"));
    }
    if !variant.modifiers.is_empty() {
        return Err(variant.at.error(".automatic does not take modifiers"));
    }
    let mut email: Option<&Value> = None;
    let mut challenge: Option<&Value> = None;
    for (label, value) in &variant.args {
        match label.as_deref() {
            Some("email") if email.is_none() => email = Some(value),
            Some("challenge") if challenge.is_none() => challenge = Some(value),
            Some(name @ ("email" | "challenge")) => {
                return Err(variant
                    .at
                    .error(format!(".automatic setting `{name}` is written twice")));
            }
            Some(name) => {
                return Err(variant.at.error(format!(
                    "unknown .automatic setting `{name}`; expected email or challenge"
                )));
            }
            None => {
                return Err(variant.at.error(
                    ".automatic takes labeled settings: .automatic(email: \"admin@example.com\")",
                ));
            }
        }
    }
    Ok((email, challenge))
}

/// 📜 The labeled arguments of `.files(certificate:, key:)`.
fn file_arguments(variant: &Call) -> Result<(&Value, &Value), Error> {
    if variant.body.is_some() {
        return Err(variant.at.error(".files does not take a block"));
    }
    if !variant.modifiers.is_empty() {
        return Err(variant.at.error(".files does not take modifiers"));
    }
    let mut certificate: Option<&Value> = None;
    let mut key: Option<&Value> = None;
    for (label, value) in &variant.args {
        match label.as_deref() {
            Some("certificate") if certificate.is_none() => certificate = Some(value),
            Some("key") if key.is_none() => key = Some(value),
            Some(name @ ("certificate" | "key")) => {
                return Err(variant
                    .at
                    .error(format!(".files setting `{name}` is written twice")));
            }
            Some(name) => {
                return Err(variant.at.error(format!(
                    "unknown .files setting `{name}`; expected certificate or key"
                )));
            }
            None => {
                return Err(variant.at.error(
                    ".files takes labeled paths: .files(certificate: \"./c.pem\", key: \"./k.pem\")",
                ));
            }
        }
    }
    let certificate =
        certificate.ok_or_else(|| variant.at.error(".files needs certificate: and key:"))?;
    let key = key.ok_or_else(|| variant.at.error(".files needs certificate: and key:"))?;
    Ok((certificate, key))
}

/// 📡 `.dns(provider)`: the module name plus its positional arguments.
///
/// 🔐 The arguments are the first field in the language that *stores* a
/// secret: a `@Secret` binding is exactly what belongs here, and a plain
/// literal is allowed the way a Caddyfile token is. Everything else about the
/// token is the provider's own business.
fn parse_challenge(value: &Value, at: Position) -> Result<DnsProviderConfig, Error> {
    let Value::Typed(call) = value else {
        return Err(at.error("challenge takes .dns(provider), e.g. .dns(.cloudflare(\"token\"))"));
    };
    if call.name != "dns" {
        return Err(call.at.error(format!(
            "unknown challenge `.{name}`; the only challenge this build speaks is .dns(provider)",
            name = call.name
        )));
    }
    expect_positional(call, "challenge .dns")?;
    let [(None, Value::Typed(provider))] = call.args.as_slice() else {
        return Err(call
            .at
            .error("dns takes one provider such as .cloudflare(\"token\")"));
    };
    expect_positional(provider, "a DNS provider")?;
    let mut arguments = Vec::new();
    for (_, argument) in &provider.args {
        let Value::String(text) = unwrap_secret(argument) else {
            return Err(provider
                .at
                .error("a DNS provider's arguments are quoted strings"));
        };
        arguments.push(SecretString::from(text.clone()));
    }
    Ok(DnsProviderConfig {
        name: provider.name.clone(),
        arguments,
    })
}

/// 🪪 `clientAuth: .request(trust:, verifier:)` and its three siblings.
fn parse_client_auth(value: &Value, at: Position) -> Result<ClientAuthConfig, Error> {
    let Value::Typed(mode) = value else {
        return Err(at.error(
            "clientAuth takes a mode: .request, .require, .verifyIfGiven or .requireAndVerify",
        ));
    };
    let parsed_mode = match mode.name.as_str() {
        "request" => ClientAuthMode::Request,
        "require" => ClientAuthMode::Require,
        "verifyIfGiven" => ClientAuthMode::VerifyIfGiven,
        "requireAndVerify" => ClientAuthMode::RequireAndVerify,
        other => {
            return Err(mode.at.error(format!(
                "unknown clientAuth mode `.{other}`; expected .request, .require, \
                 .verifyIfGiven or .requireAndVerify"
            )));
        }
    };
    if mode.body.is_some() {
        return Err(mode.at.error("clientAuth does not take a block"));
    }
    if !mode.modifiers.is_empty() {
        return Err(mode.at.error("clientAuth does not take modifiers"));
    }
    let mut trust: Option<&Value> = None;
    let mut verifier: Option<&Value> = None;
    for (label, value) in &mode.args {
        match label.as_deref() {
            Some("trust") if trust.is_none() => trust = Some(value),
            Some("verifier") if verifier.is_none() => verifier = Some(value),
            Some(name @ ("trust" | "verifier")) => {
                return Err(mode
                    .at
                    .error(format!("clientAuth setting `{name}` is written twice")));
            }
            Some(name) => {
                return Err(mode.at.error(format!(
                    "unknown clientAuth setting `{name}`; expected trust or verifier"
                )));
            }
            None => {
                return Err(mode.at.error(
                    "clientAuth settings are labeled, e.g. \
                     .requireAndVerify(trust: .files([\"./clients.pem\"]))",
                ));
            }
        }
    }
    let mut auth = ClientAuthConfig {
        mode: parsed_mode,
        ..ClientAuthConfig::default()
    };
    if let Some(trust) = trust {
        // 🚫 A trust pool in a mode that never builds a trust path is dead
        // configuration: the operator wrote down the CAs to check and this
        // build would not check them.
        if !matches!(
            parsed_mode,
            ClientAuthMode::VerifyIfGiven | ClientAuthMode::RequireAndVerify
        ) {
            return Err(mode.at.error(
                "trust only means something in .verifyIfGiven or .requireAndVerify; this mode \
                 never builds a trust path",
            ));
        }
        auth.trust_pool = Some(parse_trust_pool(trust, 0, mode.at)?);
    }
    if let Some(verifier) = verifier {
        parse_leaf_verifier(verifier, &mut auth, mode.at)?;
    }
    Ok(auth)
}

/// 🏛️ One trust source: `.files`, `.inline`, `.system`, the two `pki`
/// sources, or a `.combined([...])` of several.
fn parse_trust_pool(value: &Value, depth: usize, at: Position) -> Result<TrustPool, Error> {
    if depth > MAX_TRUST_POOL_DEPTH {
        return Err(at.error(format!(
            "trust nests deeper than {MAX_TRUST_POOL_DEPTH} combined levels"
        )));
    }
    let Value::Typed(call) = value else {
        return Err(at.error(
            "trust takes one source: .files([...]), .inline([...]), .system, \
             .pkiRoot(authority:), .pkiIntermediate(authority:) or .combined([...])",
        ));
    };
    match call.name.as_str() {
        "files" => Ok(TrustPool::File {
            pem_files: positional_strings(call, "trust .files")?,
        }),
        "inline" => Ok(TrustPool::Inline {
            trust_der: positional_strings(call, "trust .inline")?,
        }),
        "system" => {
            expect_bare(call, "trust .system")?;
            Ok(TrustPool::System)
        }
        "pkiRoot" | "pkiIntermediate" => {
            call.leaf(&["authority"])?;
            let authority = call.string("authority")?;
            if authority.is_empty() {
                return Err(call.at.error("authority must not be empty"));
            }
            Ok(if call.name == "pkiRoot" {
                TrustPool::PkiRoot { authority }
            } else {
                TrustPool::PkiIntermediate { authority }
            })
        }
        "combined" => {
            expect_positional(call, "trust .combined")?;
            let [(None, Value::Array(items))] = call.args.as_slice() else {
                return Err(call.at.error("combined takes one array of trust sources"));
            };
            if items.is_empty() {
                return Err(call.at.error("combined needs at least one source"));
            }
            let sources = items
                .iter()
                .map(|item| parse_trust_pool(item, depth + 1, call.at))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(TrustPool::Combined { sources })
        }
        other => Err(call.at.error(format!(
            "unknown trust source `.{other}`; expected .files, .inline, .system, .pkiRoot, \
             .pkiIntermediate or .combined"
        ))),
    }
}

/// 🍃 `verifier: .leaf(...)`, the one verifier this build implements: the
/// presented leaf must be one of a known set, on top of any chain check.
fn parse_leaf_verifier(
    value: &Value,
    auth: &mut ClientAuthConfig,
    at: Position,
) -> Result<(), Error> {
    let Value::Typed(call) = value else {
        return Err(at.error("verifier takes .leaf(...), the only verifier this build implements"));
    };
    if call.name != "leaf" {
        // 🚫 An unknown verifier is refused rather than accepted and ignored:
        // this is an authentication check, and a check the operator believes
        // in but that never runs is the worst way to be wrong.
        return Err(call.at.error(format!(
            "unknown verifier `.{name}`; this build implements .leaf(...) and refuses other \
             names rather than running no check",
            name = call.name
        )));
    }
    expect_positional(call, "verifier .leaf")?;
    let [(None, Value::Typed(source))] = call.args.as_slice() else {
        return Err(call
            .at
            .error("leaf takes one source: .files([...]), .der([...]) or .directory(\"...\")"));
    };
    match source.name.as_str() {
        "files" => auth.trusted_leaf_cert_files = positional_strings(source, "leaf .files")?,
        "der" => auth.trusted_leaf_certs = positional_strings(source, "leaf .der")?,
        "directory" => {
            expect_positional(source, "leaf .directory")?;
            let [(None, Value::String(path))] = source.args.as_slice() else {
                return Err(source.at.error("leaf .directory takes one quoted path"));
            };
            if path.is_empty() {
                return Err(source.at.error("leaf .directory takes a non-empty path"));
            }
            auth.trusted_leaf_cert_folders = vec![path.clone()];
        }
        other => {
            return Err(source.at.error(format!(
                "unknown leaf source `.{other}`; expected .files, .der or .directory"
            )));
        }
    }
    Ok(())
}

/// 📴 `ocspStapling: .off` — accepted, and only `.off`.
fn parse_ocsp(value: &Value, at: Position) -> Result<(), Error> {
    let Value::Typed(call) = value else {
        return Err(
            at.error("ocspStapling takes .off; stapling itself is not implemented in this build")
        );
    };
    match call.name.as_str() {
        "off" => {
            expect_bare(call, "ocspStapling .off")?;
            Ok(())
        }
        "on" => Err(call.at.error(
            "OCSP stapling is not implemented, so `.on` would promise a response this build \
             never attaches; the only accepted value is `.off`",
        )),
        other => Err(call.at.error(format!(
            "unknown ocspStapling value `.{other}`; expected .off"
        ))),
    }
}

/// 🔄 `renewalWindow: .ratio(0.1)`, a fraction strictly between 0 and 1.
fn parse_ratio(value: &Value, at: Position) -> Result<f64, Error> {
    let Value::Typed(call) = value else {
        return Err(at.error("renewalWindow takes .ratio(0.1), a fraction between 0 and 1"));
    };
    if call.name != "ratio" {
        return Err(call.at.error(format!(
            "unknown renewalWindow value `.{name}`; expected .ratio(0.1)",
            name = call.name
        )));
    }
    expect_positional(call, ".ratio")?;
    let [(None, Value::Decimal(text))] = call.args.as_slice() else {
        return Err(call
            .at
            .error("ratio takes one decimal literal such as .ratio(0.1)"));
    };
    let ratio: f64 = text
        .parse()
        .map_err(|_| call.at.error("ratio is not a decimal number"))?;
    if !(ratio > 0.0 && ratio < 1.0) {
        return Err(call.at.error(format!(
            "ratio {text} is outside the open interval (0, 1); 0.3333 renews once a third of \
             the lifetime remains"
        )));
    }
    Ok(ratio)
}

/// 🧷 A non-empty quoted string, with the error pointing at the `.tls(...)`.
fn non_empty_string(value: &Value, setting: &str, at: Position) -> Result<String, Error> {
    match value {
        Value::String(text) if !text.is_empty() => Ok(text.clone()),
        _ => Err(at.error(format!("{setting} takes a non-empty quoted string"))),
    }
}

/// 🧷 A non-empty array of non-empty quoted strings.
fn string_list(value: &Value, setting: &str, at: Position) -> Result<Vec<String>, Error> {
    let Value::Array(items) = value else {
        return Err(at.error(format!("{setting} takes an array of quoted strings")));
    };
    if items.is_empty() {
        return Err(at.error(format!("{setting} must not be empty")));
    }
    items
        .iter()
        .map(|item| match item {
            Value::String(text) if !text.is_empty() => Ok(text.clone()),
            _ => Err(at.error(format!(
                "{setting} takes an array of non-empty quoted strings"
            ))),
        })
        .collect()
}

/// 🧷 The single positional array of strings inside a typed value.
fn positional_strings(call: &Call, what: &str) -> Result<Vec<String>, Error> {
    expect_positional(call, what)?;
    let [(None, Value::Array(items))] = call.args.as_slice() else {
        return Err(call
            .at
            .error(format!("{what} takes one array of quoted strings")));
    };
    if items.is_empty() {
        return Err(call.at.error(format!("{what} must not be empty")));
    }
    items
        .iter()
        .map(|item| match item {
            Value::String(text) if !text.is_empty() => Ok(text.clone()),
            _ => Err(call
                .at
                .error(format!("{what} takes an array of non-empty quoted strings"))),
        })
        .collect()
}

/// 🧷 Checks a typed value takes no block, no modifiers and only positional
/// arguments.
fn expect_positional(call: &Call, what: &str) -> Result<(), Error> {
    if call.body.is_some() {
        return Err(call.at.error(format!("{what} does not take a block")));
    }
    if !call.modifiers.is_empty() {
        return Err(call.at.error(format!("{what} does not take modifiers")));
    }
    if call.args.iter().any(|(label, _)| label.is_some()) {
        return Err(call.at.error(format!("{what} takes unlabeled arguments")));
    }
    Ok(())
}

/// 🧷 Checks a typed value takes nothing at all.
fn expect_bare(call: &Call, what: &str) -> Result<(), Error> {
    expect_positional(call, what)?;
    if !call.args.is_empty() {
        return Err(call.at.error(format!("{what} takes no arguments")));
    }
    Ok(())
}

/// 🔓 Peels the `@Secret` mark so the one field that stores secrets can read
/// the value. Every other position is refused before this point.
fn unwrap_secret(value: &Value) -> &Value {
    match value {
        Value::Secret { value, .. } => unwrap_secret(value),
        other => other,
    }
}
