// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! Configuration type definitions
//!
//! These types represent the runtime configuration for Pingclair.
//!
//! # 🚫 Strict schemas on the trust surface
//!
//! Serde's default is to ignore a field it does not recognise. For most
//! settings that is merely annoying — you misspell `max_size`, nothing
//! happens, and you notice. For a setting that decides *who is trusted*, it is
//! a silent downgrade: the field you thought you set is gone, and what remains
//! is the type's default.
//!
//! The concrete failure this guards against: writing `"modde":
//! "require_and_verify"` inside `client_auth` used to deserialise cleanly and
//! validate cleanly, leaving [`ClientAuthMode::Require`] in force — a mode that
//! demands a client certificate and then never checks who signed it. The
//! operator asked for verified mutual TLS and got "any certificate at all".
//!
//! So every type below that names key material, names a trust anchor, or
//! decides how hard an identity is checked carries
//! `#[serde(deny_unknown_fields)]`: [`TlsConfig`], [`ClientAuthConfig`],
//! [`TrustPool`], [`UpstreamTlsConfig`], [`AdminConfig`], the `pki` and
//! `acme_server` types, and the DNS-01 types that hold provider credentials.
//! A typo there is a load failure, not a weaker server.
//!
//! Two consequences worth knowing before adding a field. Renaming one is a
//! breaking change, so a spelling that shipped has to stay reachable through
//! an explicit `#[serde(alias = "…")]` rather than by leniency. And
//! `deny_unknown_fields` cannot coexist with `#[serde(flatten)]`, which is why
//! [`HandlerElement`] and [`NamedLogConfig`] are not on the list.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Root configuration for Pingclair
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
// 🚫 Reject unknown top-level fields: a Caddy JSON document must never be
// silently parsed into an empty Pingclair config, which would report success
// while loading nothing.
#[serde(deny_unknown_fields)]
pub struct PingclairConfig {
    /// Debug mode
    #[serde(default)]
    pub debug: bool,

    /// Server configurations
    #[serde(default)]
    pub servers: Vec<ServerConfig>,

    /// Admin API configuration
    #[serde(default)]
    pub admin: Option<AdminConfig>,

    /// Global configuration
    #[serde(default)]
    pub global: GlobalConfig,

    /// Global logging configuration
    #[serde(default)]
    pub logging: LoggingConfig,
}

/// Global configuration options
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GlobalConfig {
    /// Global ACME email
    pub email: Option<String>,

    /// 🏛️ Certificate authorities declared by the global `pki` block.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pki: Vec<PkiAuthority>,

    /// 🤝 Upstream's `skip_install_trust`. It describes what this server
    /// already does: the internal CA root is only ever installed by the
    /// explicit `pingclair trust` command, never automatically at startup. The
    /// option is accepted so a configuration written for upstream translates,
    /// and it changes nothing here.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub skip_install_trust: bool,

    /// 📡 The DNS provider every site falls back to, from the global `dns`
    /// option. It answers two different questions upstream — DNS-01 challenges
    /// and general resolution — and this field is the first of those.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsProviderConfig>,

    /// 📡 The global `acme_dns` option: switch every site's automatic
    /// certificate onto DNS-01. `Some(None)` is the bare spelling, which means
    /// "use the provider `dns` named".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acme_dns: Option<Option<DnsProviderConfig>>,

    /// 🔎 The global `tls_resolvers` option: which resolvers every DNS-01
    /// propagation check asks.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tls_resolvers: Vec<String>,

    /// 🌐 Port the server uses for plaintext HTTP, matching Caddy's
    /// `http_port` option. The automatic port-80 companion and the default
    /// listener for non-TLS hostname sites honor this.
    #[serde(default = "default_http_port")]
    pub http_port: u16,

    /// 🔐 Port the server uses for HTTPS, matching Caddy's `https_port`
    /// option. The automatic-443 derivation and `server_requires_tls`
    /// conventions use this instead of a hard-coded 443.
    #[serde(default = "default_https_port")]
    pub https_port: u16,

    /// 📊 Whether Prometheus metrics are collected and served. Enabled by
    /// default to preserve existing deployments; `{ metrics }` in a
    /// Pingclairfile enables it explicitly.
    #[serde(default = "default_bool_true")]
    pub metrics: bool,

    /// 📊 How much detail the collected metrics carry.
    ///
    /// Separate from [`GlobalConfig::metrics`], which decides *whether* to
    /// collect at all. This decides *what the series look like* — and the split
    /// matters because the expensive question in a metrics system is never
    /// "how many counters" but "how many label combinations".
    #[serde(default, skip_serializing_if = "MetricsOptions::is_default")]
    pub metrics_options: MetricsOptions,

    /// Global auto-HTTPS setting
    #[serde(default)]
    pub auto_https: AutoHttpsMode,

    /// 🔐 Whether default automation uses the built-in local authority
    /// instead of public ACME, matching Caddy's global `local_certs` option.
    #[serde(default, skip_serializing_if = "is_false")]
    pub local_certs: bool,

    /// Blocked IP addresses (CIDR supported)
    #[serde(default)]
    pub blocked_ips: Vec<String>,

    /// 🛡️ Proxy IP or CIDR ranges allowed to supply client identity headers.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,

    /// Max number of idle upstream connections Pingora keeps open per
    /// worker thread for reuse. Explicitly configurable rather than left
    /// as an implicit framework default, so a deployment under load has a
    /// deliberate, known ceiling on upstream connection fan-out instead of
    /// an invisible one. `None` uses Pingora's own default (128).
    #[serde(default)]
    pub upstream_keepalive_pool_size: Option<usize>,

    /// Enable HTTP/3 (QUIC) listeners on HTTPS ports. Defaults to true;
    /// set to false to serve HTTPS over TCP (HTTP/1.1 + HTTP/2) only.
    #[serde(default = "default_bool_true")]
    pub http3: bool,

    /// Worker threads **per listen service**. Pingora's default is 1, which
    /// single-threads the entire server; `None` scales to the machine's
    /// available parallelism (nginx `worker_processes auto` semantics).
    #[serde(default)]
    pub worker_threads: Option<usize>,

    /// How often hostname upstreams are re-resolved, in seconds. `0` turns
    /// re-resolution off and pins every upstream to the address it had at
    /// startup. Only names are affected: IP literals never reach a resolver.
    #[serde(default = "default_dns_refresh_secs")]
    pub dns_refresh_secs: u64,

    /// 🚰 How long a shutdown waits for requests already in flight, in
    /// seconds. `None` means wait for them however long they take, which is
    /// what Caddy does and what `grace_period` overrides.
    ///
    /// The default matters more than it looks. Pingora gives the runtime five
    /// seconds unless told otherwise, so before this existed a `SIGTERM`
    /// during a large download cut the response off mid-body: on 2026-08-05 a
    /// 20 MiB file arrived as 4.1 MiB with no error the client could see. A
    /// rolling restart did that to every download in progress.
    #[serde(default)]
    pub grace_period_secs: Option<u64>,

    /// 🔄 How early a certificate is renewed, as a fraction of its lifetime.
    ///
    /// `0.3333` means "renew once a third of the validity remains" — for a
    /// 90-day certificate, at 30 days left. Expressed as a ratio rather than a
    /// duration because that is the only form that survives the certificate
    /// lifetime changing: a fixed 30-day window renews a 7-day certificate
    /// immediately, forever.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renewal_window_ratio: Option<f64>,

    /// 🌐 Bind addresses every site inherits when it names none of its own.
    ///
    /// A site's own `bind` wins. This exists so a machine with several
    /// interfaces can say once which one the server belongs on.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub default_bind: Vec<String>,

    /// 🔗 The ACME issuer chain an operator prefers, from `preferred_chains`.
    ///
    /// ⚠️ Recorded and reported at startup, never acted on: `instant-acme`
    /// 0.8.5 — checked 2026-08-12, no `alternate`/`preferred_chain` in its
    /// public API — downloads the default chain the CA offers and exposes no
    /// way to ask for another. Stored rather than refused because serving the
    /// default chain still works, and refused-at-startup would turn a
    /// preference into an outage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred_chains: Option<PreferredChains>,
}

/// 🔗 Which issuer chain to prefer when a CA offers more than one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreferredChains {
    /// The chain with the fewest certificates in it.
    Smallest,
    /// Any chain whose issuers include one of these common names.
    AnyCommonName(Vec<String>),
    /// Any chain whose root has one of these common names.
    RootCommonName(Vec<String>),
}

/// 🧾 Reads probe headers written either as one value or as several.
///
/// `{"X-Probe": "yes"}` and `{"X-Probe": ["yes"]}` mean the same thing, and both
/// have to keep loading: the single-string spelling is what every JSON
/// configuration written before multi-value support says, and a config that
/// stops loading on upgrade is a worse defect than the one this fixes.
///
/// 📌 Hand-written rather than `#[serde(untagged)]` on a helper enum. Untagged
/// works here — the shape is not recursive — but its failure message names
/// neither branch, so a malformed value reports "data did not match any
/// variant" and the operator has to guess which of two spellings they got
/// wrong. Startup errors are read exactly once, by someone in a hurry.
fn deserialize_probe_headers<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{MapAccess, Visitor};

    struct Values;

    impl<'de> Visitor<'de> for Values {
        type Value = Vec<String>;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a header value, or a list of header values")
        }

        fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
            Ok(vec![value.to_string()])
        }

        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<Self::Value, A::Error> {
            let mut values = Vec::with_capacity(seq.size_hint().unwrap_or(1));
            while let Some(value) = seq.next_element::<String>()? {
                values.push(value);
            }
            Ok(values)
        }
    }

    struct Headers;

    impl<'de> Visitor<'de> for Headers {
        type Value = BTreeMap<String, Vec<String>>;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a map of header names to values")
        }

        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut headers = BTreeMap::new();
            while let Some(name) = map.next_key::<String>()? {
                let values = map.next_value_seed(ValuesSeed)?;
                // 🔁 Extend rather than replace: a JSON object should not have
                // a duplicate key, but if one arrives, dropping the earlier
                // values is the exact bug this field exists to fix.
                headers.entry(name).or_insert_with(Vec::new).extend(values);
            }
            Ok(headers)
        }
    }

    struct ValuesSeed;

    impl<'de> serde::de::DeserializeSeed<'de> for ValuesSeed {
        type Value = Vec<String>;

        fn deserialize<D2: serde::Deserializer<'de>>(
            self,
            deserializer: D2,
        ) -> Result<Self::Value, D2::Error> {
            deserializer.deserialize_any(Values)
        }
    }

    deserializer.deserialize_map(Headers)
}

/// 📊 How much detail the collected metrics carry.
///
/// Every field here buys resolution with cardinality. A Prometheus series is
/// created per distinct combination of label values, so a label whose value
/// comes from the request — and `Host` does — is a label an outsider can inflate
/// by sending requests. That is why none of these are on by default and why
/// [`MetricsOptions::observe_catchall_hosts`] carries a warning rather than a
/// default.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricsOptions {
    /// 🏷️ Breaks the request metrics down by `Host`.
    ///
    /// Off by default: without it every request folds into one series per
    /// method and status, which is both the cheaper shape and the one that
    /// cannot be inflated from outside.
    #[serde(default, skip_serializing_if = "is_false")]
    pub per_host: bool,

    /// ⚠️ Gives a host its own label even when no site is configured for it.
    ///
    /// With `per_host` on and this off, only hosts this configuration actually
    /// serves get their own series and everything else folds into one — so the
    /// number of series is decided by the Pingclairfile, not by whoever is
    /// sending requests. Turning it on hands that decision to the sender, which
    /// on a public listener is an unbounded-memory lever; upstream documents it
    /// as not recommended, and this is why.
    #[serde(default, skip_serializing_if = "is_false")]
    pub observe_catchall_hosts: bool,

    /// 📡 Asks for OTLP push in addition to the scrape endpoint.
    ///
    /// Parsed so a configuration written for upstream still loads and still
    /// says what it meant, but Pingclair has no OTLP exporter — `run` refuses
    /// to start rather than collect metrics that silently go nowhere.
    #[serde(default, skip_serializing_if = "is_false")]
    pub otlp: bool,
}

impl MetricsOptions {
    /// 🧾 True when nothing has been asked for, so serialization can omit it.
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    /// 🔀 Folds another block's answers into this one, keeping every `true`.
    ///
    /// Upstream merges rather than replaces because the same option can be
    /// written twice — once globally and once inside a `servers` block — and
    /// the two are read at different points in adaptation. Merging makes the
    /// order they appear in irrelevant; last-one-wins would make a
    /// configuration's meaning depend on how it happens to be laid out.
    pub fn merge(&mut self, other: &Self) {
        self.per_host |= other.per_host;
        self.observe_catchall_hosts |= other.observe_catchall_hosts;
        self.otlp |= other.otlp;
    }
}

/// 🌐 Default plaintext HTTP port, matching Caddy's default.
fn default_http_port() -> u16 {
    80
}

/// 🔐 Default HTTPS port, matching Caddy's default.
fn default_https_port() -> u16 {
    443
}

/// Default upstream re-resolution interval (seconds).
pub fn default_dns_refresh_secs() -> u64 {
    30
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            email: None,
            metrics_options: MetricsOptions::default(),
            pki: Vec::new(),
            skip_install_trust: false,
            dns: None,
            acme_dns: None,
            tls_resolvers: Vec::new(),
            http_port: default_http_port(),
            https_port: default_https_port(),
            metrics: default_bool_true(),
            auto_https: AutoHttpsMode::default(),
            local_certs: false,
            blocked_ips: Vec::new(),
            trusted_proxies: Vec::new(),
            upstream_keepalive_pool_size: None,
            http3: true,
            worker_threads: None,
            dns_refresh_secs: default_dns_refresh_secs(),
            // 🚰 `None` is "wait for in-flight requests however long they
            // take", which is Caddy's behaviour rather than a missing value.
            grace_period_secs: None,
            renewal_window_ratio: None,
            default_bind: Vec::new(),
            preferred_chains: None,
        }
    }
}

/// Auto-HTTPS modes
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AutoHttpsMode {
    #[default]
    On,
    Off,
    DisableRedirects,
}

/// 🗜️ Default MIME patterns eligible for reverse-proxy gzip compression.
pub const DEFAULT_GZIP_TYPES: &[&str] = &[
    "text/*",
    "application/json",
    "application/*+json",
    "application/x-ndjson",
    "application/json-seq",
    "application/xml",
    "application/*+xml",
    "application/javascript",
    "application/x-javascript",
    "image/svg+xml",
];

/// 🗜️ Builds the default reverse-proxy gzip MIME pattern list.
pub fn default_gzip_types() -> Vec<String> {
    DEFAULT_GZIP_TYPES
        .iter()
        .map(|value| (*value).to_string())
        .collect()
}

/// 🗜️ A content coding Pingclair can actually *produce* for a proxied response.
///
/// Deliberately narrower than what the config grammar accepts: the parser also
/// understands `br`, but the reverse-proxy path has no streaming Brotli
/// encoder, so the compiler rejects it rather than silently downgrading to
/// gzip. Anything present in this enum is guaranteed to have a working encoder
/// behind it — that invariant is what lets the negotiator treat the configured
/// list as offerable without further checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Encoding {
    Gzip,
    Zstd,
}

impl Encoding {
    /// The `Content-Encoding` / `Accept-Encoding` token for this coding.
    pub fn token(self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
            Self::Zstd => "zstd",
        }
    }

    /// Parses an `Accept-Encoding` token into a coding we can produce.
    ///
    /// Returns `None` for well-formed codings we simply do not implement
    /// (`br`, `deflate`, …) as well as for junk — the caller treats both the
    /// same way, by offering something else.
    pub fn from_token(token: &str) -> Option<Self> {
        match token.trim().to_ascii_lowercase().as_str() {
            "gzip" | "x-gzip" => Some(Self::Gzip),
            "zstd" => Some(Self::Zstd),
            _ => None,
        }
    }
}

/// 🗜️ Codings offered when a server declares no `encode` directive at all.
///
/// Gzip-only, which is what every Pingclair release through `0.1.7` did
/// unconditionally. Keeping it as the default means making `encode` real is
/// not a silent behavior change for configs that never mentioned it.
pub fn default_encodings() -> Vec<Encoding> {
    vec![Encoding::Gzip]
}

/// Server (virtual host) configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Server name / hostname
    pub name: Option<String>,

    /// 🏠 Every hostname this site serves. The primary name is also kept in
    /// [`Self::name`] for backward compatibility; the runtime registers each
    /// entry as a virtual host pointing at the same configuration.
    #[serde(default)]
    pub names: Vec<String>,

    /// 📍 Optional interface to bind the site's listener to (`bind` directive).
    /// When the site has no explicit `listen`, the runtime uses this as the
    /// host for the automatically derived 443/80 address.
    #[serde(default)]
    pub bind: Option<String>,

    /// Listen addresses
    #[serde(default)]
    pub listen: Vec<String>,

    /// 🧭 The subset of [`Self::listen`] that requires a PROXY protocol header.
    ///
    /// Kept as a parallel list rather than folded into `listen` so the shape of
    /// `listen` stays a plain array of strings: it round-trips through the
    /// Admin API unchanged, and a configuration written before this field
    /// existed still loads as "no listener requires the header".
    ///
    /// Every entry must also appear in `listen`. An address here that is not
    /// listened on is rejected rather than ignored — silently dropping it would
    /// leave a listener the operator believes is protected accepting anything.
    #[serde(default)]
    pub proxy_protocol_listen: Vec<String>,

    /// 📴 The subset of [`Self::listen`] that must remain plaintext.
    ///
    /// An explicit `http://` address and `tls off` are listener policy, not
    /// hints. Keeping that decision beside the concrete address prevents a
    /// conventional HTTPS port from silently turning TLS back on at runtime.
    /// Every entry must also appear in `listen`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub plaintext_listen: Vec<String>,

    /// TLS configuration
    #[serde(default)]
    pub tls: Option<TlsConfig>,

    /// Routes for this server
    #[serde(default)]
    pub routes: Vec<RouteConfig>,

    /// Log configuration for this server
    #[serde(default)]
    pub log: Option<LogConfig>,

    /// 🪵 Names of global channels this server also writes to.
    ///
    /// Additive rather than exclusive: a server may keep its inline `log`
    /// block *and* fan out to a shared channel, which is how "everything to
    /// stdout, errors also to a file" is expressed without duplicating the
    /// whole block.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub log_channels: Vec<String>,

    /// 🪵 Named per-site access loggers from `log <name> { … }`.
    ///
    /// A named site logger is configured by the block that declares it, in
    /// the shape upstream Caddy gives the same spelling. The name is a
    /// handle for `log_name`/`include` associations (D2); the logger itself
    /// is independent of any global channel.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub named_logs: Vec<NamedLogConfig>,

    /// Maximum request body size in bytes (default: 1MB)
    #[serde(default = "default_body_limit")]
    pub client_max_body_size: u64,

    /// 🧱 Configurable downstream resource and time bounds.
    #[serde(default)]
    pub limits: ResourceLimitsConfig,

    /// Security headers configuration
    #[serde(default)]
    pub security: SecurityConfig,

    /// 🗜️ MIME patterns eligible for reverse-proxy gzip compression.
    #[serde(default = "default_gzip_types")]
    pub gzip_types: Vec<String>,

    /// 🗜️ Content codings offered for proxied responses, in *server*
    /// preference order — the order the `encode` directive listed them.
    ///
    /// An empty list disables response compression for this server entirely
    /// (`encode off`); the field is absent from older JSON configs, which
    /// fall back to [`default_encodings`].
    #[serde(default = "default_encodings")]
    pub encodings: Vec<Encoding>,

    /// Custom error pages: HTTP status code → file path served for that
    /// error (404/500/502/504, ...). Falls back to the built-in plain-text
    /// response when unset or unreadable.
    #[serde(default)]
    pub error_pages: BTreeMap<u16, String>,

    /// 🚨 Status-selective routes run when a handler raises an error status.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub error_routes: Vec<ErrorRouteConfig>,

    /// 🧰 Site-level `vars` rules, least specific first; every matching rule
    /// runs so the most specific value wins.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vars_routes: Vec<VarsRule>,
}

/// 🚨 One `handle_errors [<codes…>]` block: a status-selective error route.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorRouteConfig {
    /// Exact status codes this route handles; empty means every status.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub codes: Vec<u16>,
    /// `Nxx` ranges — `[4]` selects 400..=499 — when the block wrote them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hundreds: Vec<u8>,
    /// 🧭 Matcher-guarded handlers, run in order until one answers.
    #[serde(default)]
    pub handlers: Vec<HandlerElement>,
}

impl ErrorRouteConfig {
    /// 🚨 Whether `status` falls in this route's codes or hundred-range.
    pub fn matches(&self, status: u16) -> bool {
        // 🌐 A route with no codes at all is the catch-all: it handles every
        // error status, which is what a bare `handle_errors { … }` means.
        (self.codes.is_empty() && self.hundreds.is_empty())
            || self.codes.contains(&status)
            || self
                .hundreds
                .iter()
                .any(|hundred| status / 100 == u16::from(*hundred))
    }
}

/// 🧰 One `vars [<matcher>] <name> <value>` rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VarsRule {
    /// Optional matcher; `None` runs for every request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matcher: Option<Matcher>,
    /// 🧩 Variable names to values, set when the rule matches.
    #[serde(default)]
    pub values: BTreeMap<String, String>,
}

/// Hand-written rather than derived so `ServerConfig::default()` agrees with
/// what deserializing `{}` produces. `#[derive(Default)]` ignores the
/// `#[serde(default = ...)]` attributes, which would silently hand out
/// `client_max_body_size: 0` (unlimited) and an empty `encodings` list
/// (compression off) — both the opposite of the documented default.
impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            name: None,
            names: Vec::new(),
            bind: None,
            listen: Vec::new(),
            proxy_protocol_listen: Vec::new(),
            plaintext_listen: Vec::new(),
            tls: None,
            routes: Vec::new(),
            log: None,
            log_channels: Vec::new(),
            named_logs: Vec::new(),
            client_max_body_size: default_body_limit(),
            limits: ResourceLimitsConfig::default(),
            security: SecurityConfig::default(),
            gzip_types: default_gzip_types(),
            encodings: default_encodings(),
            error_pages: BTreeMap::new(),
            error_routes: Vec::new(),
            vars_routes: Vec::new(),
        }
    }
}

fn default_body_limit() -> u64 {
    1024 * 1024 // 1MB
}

/// 🧱 Bounds one virtual host's downstream resource consumption.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ResourceLimitsConfig {
    /// ⏱️ Maximum time spent reading an HTTP/1 request header.
    pub header_timeout_ms: Option<u64>,
    /// ⏱️ Maximum pause allowed while receiving request-body chunks.
    pub body_timeout_ms: Option<u64>,
    /// 💤 Maximum inactive downstream interval for ordinary requests.
    pub idle_timeout_ms: Option<u64>,
    /// ⌛ Maximum wall-clock duration after request headers are accepted.
    pub request_timeout_ms: Option<u64>,
    /// 🧾 Maximum number of decoded request fields, excluding pseudo-headers.
    pub max_header_count: Option<usize>,
    /// 📏 Maximum decoded request-header bytes, including names and values.
    pub max_header_bytes: Option<usize>,
    /// 🔌 Maximum simultaneous downstream transport connections per listener.
    pub max_connections: Option<usize>,
    /// 📥 Maximum downstream request-body throughput in bytes per second.
    pub upload_bytes_per_sec: Option<u64>,
    /// 📤 Maximum downstream response-body throughput in bytes per second.
    pub download_bytes_per_sec: Option<u64>,
    /// 🌊 Overrides ordinary deadlines for SSE, immediate-flush, and WebSocket traffic.
    #[serde(default)]
    pub long_connections: LongConnectionLimits,
}

/// 🌊 Deadline overrides for intentionally long-lived responses and tunnels.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct LongConnectionLimits {
    /// 💤 Long-connection inactivity timeout; zero explicitly disables it.
    pub idle_timeout_ms: Option<u64>,
    /// ⌛ Long-connection wall-clock timeout; zero explicitly disables it.
    pub request_timeout_ms: Option<u64>,
}

/// 🔐 Configures downstream TLS for one server.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// 🌐 Enables automatic public certificate management.
    #[serde(default)]
    pub auto: bool,

    /// 🏛️ Enables certificates signed by Pingclair's persistent local authority.
    #[serde(default)]
    pub internal: bool,

    /// 📜 Identifies the certificate file path.
    pub cert: Option<String>,

    /// 🔑 Identifies the private key file path.
    pub key: Option<String>,

    /// 📧 Identifies the ACME account email for Let's Encrypt.
    pub acme_email: Option<String>,

    /// 🚀 Enables HTTP/3.
    #[serde(default)]
    pub http3: bool,

    /// 🪪 Mutual TLS: what to ask of the client's own certificate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_auth: Option<ClientAuthConfig>,

    /// 📡 DNS-01 settings for this site, when it asks for the DNS challenge.
    ///
    /// Present means the site wants DNS-01 rather than HTTP-01 — including a
    /// wildcard site, which has no other option.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_challenge: Option<DnsChallengeConfig>,

    /// 🏷️ The server name to assume when a client sends no SNI.
    ///
    /// TLS 1.2 made SNI optional and plenty of clients still omit it: older
    /// command-line tools, health checkers, and anything connecting to a bare
    /// IP. Without a name there is nothing to select a certificate by, so the
    /// handshake has to fail — which is why naming one here is the difference
    /// between "this endpoint does not work for that client" and "it does".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_sni: Option<String>,
}

/// 🏛️ One certificate authority declared by the global `pki` block.
///
/// Upstream lets a server *be* a CA and hand certificates to other clients over
/// RFC 8555. This build parses, validates and serialises that configuration and
/// refuses to perform it — see the runtime refusal in `run.rs`. Keeping the
/// shape means a configuration written for upstream still translates, which is
/// what `adapt` is for; it does not mean the server will act as a CA.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PkiAuthority {
    /// 🏷️ The identifier a site's `acme_server { ca … }` refers to.
    /// Upstream calls the unnamed one `local`.
    pub id: String,

    /// 📛 Human-readable name, shown in the certificates it signs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// 📜 Common name for the root certificate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_cn: Option<String>,

    /// 📜 Common name for the intermediate certificate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intermediate_cn: Option<String>,

    /// 🔑 An existing root to sign with, rather than generating one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<PkiKeyPair>,

    /// 🔑 An existing intermediate to sign with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intermediate: Option<PkiKeyPair>,
}

/// 🔑 A certificate and key an authority signs with, loaded from disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PkiKeyPair {
    pub cert: Option<String>,
    pub key: Option<String>,
    /// 📄 How the two above are stored. Upstream's only Caddyfile spelling is
    /// `pem_file`; the field exists so a different one is refused rather than
    /// silently read as PEM.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
}

/// 🏛️ A site acting as an ACME server for other clients.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AcmeServerConfig {
    /// 🏷️ Which `pki` authority signs what this server issues.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca: Option<String>,

    /// ⏱️ How long the certificates it issues are valid for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifetime_secs: Option<u64>,

    /// 🌳 Sign with the root directly instead of the intermediate.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub sign_with_root: bool,

    /// 🧩 Which challenges this server offers. Empty means upstream's default
    /// set, which is why "written with no arguments" and "not written" have to
    /// stay distinguishable — hence the `Option`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenges: Option<Vec<String>>,

    /// ✅ Names this server will issue for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow: Option<AcmeServerPolicy>,

    /// 🚫 Names this server refuses, checked after `allow`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny: Option<AcmeServerPolicy>,
}

/// 🧭 One half of an ACME server's issuance policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AcmeServerPolicy {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domains: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ip_ranges: Vec<String>,
}

/// 📡 Which DNS provider answers a DNS-01 challenge, and how it is addressed.
///
/// The arguments are the provider's own, not ours: upstream hands whatever
/// follows the name straight to the provider module, and a Cloudflare token
/// and a Route 53 hosted-zone ID have nothing in common. Keeping them as an
/// opaque list is what lets the parser stay honest about not knowing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct DnsProviderConfig {
    /// 🏷️ The provider's module name, for example `cloudflare`.
    pub name: String,

    /// 🎛️ Everything written after the name, in order.
    ///
    /// 🙈 Secrets, as far as this server is concerned. The arguments are the
    /// provider's own and this code cannot tell which of them is a credential —
    /// for Cloudflare the whole thing is an API token — so all of them are
    /// treated as one. Guessing would mean guessing wrong for the next provider.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arguments: Vec<crate::config::SecretString>,
}

/// 📡 The DNS-01 challenge settings for one site, or for the whole server.
///
/// DNS-01 is the only challenge that can prove control of a wildcard, which is
/// why it is worth its own configuration rather than a boolean: a certificate
/// for `*.example.com` cannot be obtained any other way.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct DnsChallengeConfig {
    /// 🏢 The provider that publishes the TXT record. `None` means "whatever
    /// the global `dns` option named", which is how upstream's bare
    /// `acme_dns` works.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<DnsProviderConfig>,

    /// 🔎 The resolvers used to *check* the record has propagated. These are
    /// deliberately not the system resolvers: a recursive resolver that has
    /// cached the old (absent) record will keep saying so, and the ACME server
    /// is asking authoritative servers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolvers: Vec<String>,

    /// ⏱️ The TTL to publish on the TXT record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u64>,

    /// ⏳ How long to wait before even starting to check for propagation.
    /// Some providers accept a record and serve it seconds later.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub propagation_delay_secs: Option<u64>,

    /// ⌛ How long to keep checking before giving up.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub propagation_timeout_secs: Option<u64>,

    /// 🔀 A delegated domain to write the record into instead, for operators
    /// who keep ACME records in a zone separate from the served one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge_override_domain: Option<String>,
}

/// 🪪 How strictly a client certificate is demanded and checked.
///
/// The four modes are upstream's, and the distinction between them is the whole
/// point: `request` asks and accepts whatever comes back, `require` insists on a
/// certificate but does not check it, `verify_if_given` checks one only if the
/// client offers it, and `require_and_verify` does both. Two of these are
/// commonly mistaken for security controls when they are not, which is why the
/// spelling has to be exact rather than a boolean.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuthMode {
    /// 🙋 Ask for a certificate; accept the connection either way.
    Request,
    /// ✋ Insist on a certificate, but do not build a trust path for it.
    #[default]
    Require,
    /// 🔍 Verify a certificate if one is offered; allow the connection if not.
    VerifyIfGiven,
    /// 🛡️ Insist on a certificate and verify it against the trust pool.
    RequireAndVerify,
}

/// 🏛️ Where the certificates a client is checked against come from.
///
/// 🛡️ Externally tagged and depth-bounded on purpose. `Combined` makes this
/// recursive, and an untagged recursive type is precisely the shape that
/// produced a remotely triggerable stack overflow in this codebase once
/// already — the Admin API deserialises straight into these types, so the
/// nesting an attacker can express is the nesting the parser has to survive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "provider", rename_all = "snake_case", deny_unknown_fields)]
pub enum TrustPool {
    /// 📜 Certificates given directly, base64 DER as upstream spells them.
    Inline {
        #[serde(default)]
        trust_der: Vec<String>,
    },
    /// 📂 PEM bundles read from disk.
    File {
        #[serde(default)]
        pem_files: Vec<String>,
    },
    /// 🖥️ The host's own trust store.
    System,
    /// 🏛️ The root of a `pki` authority declared in the global block.
    PkiRoot {
        #[serde(default)]
        authority: String,
    },
    /// 🏛️ The intermediate of a `pki` authority.
    PkiIntermediate {
        #[serde(default)]
        authority: String,
    },
    /// 🧩 Several pools treated as one.
    Combined {
        #[serde(default)]
        sources: Vec<TrustPool>,
    },
}

/// 🪪 Mutual TLS configuration for one site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ClientAuthConfig {
    /// 🎚️ How strictly the certificate is demanded and checked.
    #[serde(default)]
    pub mode: ClientAuthMode,

    /// 🏛️ The trust pool clients are verified against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_pool: Option<TrustPool>,

    /// 📜 Upstream's deprecated flat spellings, kept because configurations in
    /// the wild still use them. They are mutually exclusive with `trust_pool`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_ca_certs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_ca_cert_files: Vec<String>,

    /// 🍃 Leaf certificates pinned individually, rather than by their issuer.
    ///
    /// Pinning a leaf answers a different question from trusting a CA: not
    /// "was this signed by someone I trust" but "is this the exact
    /// certificate I was told to expect". Both can apply at once, and when
    /// they do the client must satisfy both.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_leaf_certs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_leaf_cert_files: Vec<String>,

    /// 🍃 Directories scanned for pinned leaf certificates.
    ///
    /// Every `.pem` file underneath, recursively. Kept as directories rather
    /// than expanded into paths while adapting, for two reasons: adapting a
    /// configuration must not depend on the filesystem it is adapted on, and
    /// an operator who drops a certificate into the folder expects the next
    /// reload to see it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_leaf_cert_folders: Vec<String>,
}

/// Route configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfig {
    /// Path pattern to match
    pub path: String,

    /// Handler for this route
    pub handler: HandlerConfig,

    /// Allowed methods (None = all)
    #[serde(default)]
    pub methods: Option<Vec<String>>,

    /// Matcher for this route
    #[serde(default)]
    pub matcher: Option<Matcher>,
}

/// Route matcher
///
/// 🏗️ SERIALIZATION: **externally tagged** — `{"not": {"path": {"patterns":
/// ["/admin/*"]}}}`. The tag is what makes the enum recoverable. Under the
/// `untagged` representation this type used to carry, a variant was
/// identified purely by the shape of its payload, and half of these variants
/// do not have a distinguishable shape:
///
/// - `Not(inner)` serialized as *just the inner matcher*, so a round trip
///   read it back as the inner matcher and **dropped the negation** — the
///   one transformation that inverts a routing decision.
/// - `Or` and `And` are both two-element arrays, so every `Or` came back
///   as an `And`.
/// - `Query` and `Header` are both `{name, condition}`, so every `Query`
///   came back as a `Header`.
/// - `RemoteIp` and `Protocol` are both arrays of strings, like `Host`.
///
/// A Pingclairfile never went through this path — the compiler builds these
/// values directly — but JSON/TOML configs and Admin API hot reload did.
///
/// Deserialization still accepts the old shapes so `0.1.7` configs load
/// unchanged; see the `Deserialize` impl.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Matcher {
    /// Match by path
    Path { patterns: Vec<String> },

    /// Match by header
    Header {
        name: String,
        condition: MatcherCondition,
    },

    /// Match by HTTP method
    Method { methods: Vec<String> },

    /// Match by query parameter
    Query {
        name: String,
        condition: MatcherCondition,
    },

    /// Match by host
    Host(Vec<String>),

    /// Match by remote IP
    RemoteIp(Vec<String>),

    /// Match by protocol
    Protocol(Vec<String>),

    /// Match by request-scoped variable (`vars` matcher).
    Vars { name: String, values: Vec<String> },

    /// Match the request path against a regular expression; captures are
    /// written back as `{re.*}` placeholders when the matcher has a name.
    PathRegexp {
        name: Option<String>,
        pattern: String,
    },

    /// Match a header against a regular expression; captures are written
    /// back as `{re.*}` placeholders when the matcher has a name.
    HeaderRegexp {
        name: Option<String>,
        field: String,
        pattern: String,
    },

    /// 📂 Match by file existence under a document root, exactly like
    /// Caddy's `file` matcher.
    ///
    /// A match publishes `{http.matchers.file.relative}`, `.absolute`,
    /// `.type` and `.remainder` into the request-scoped variables so the
    /// rewrite that follows a `php_fastcgi` expansion can target the matched
    /// file. A candidate spelled `=404` raises that status instead of
    /// matching, matching the upstream matcher's error fallback.
    File {
        /// URI candidates tried in order; `{path}` expands to the request
        /// path, and a trailing slash demands a directory.
        try_files: Vec<String>,
        /// Filesystem root the candidates are resolved against; `None`
        /// means the current directory, like a file server without a root.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        root: Option<String>,
        /// Selection policy: `first_exist` (default), `first_exist_fallback`,
        /// `smallest_size`, `largest_size`, or `most_recently_modified`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        try_policy: Option<String>,
        /// ASCII delimiters that split the path into a script and path info.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        split_path: Vec<String>,
    },

    /// AND combination
    And(Box<Matcher>, Box<Matcher>),

    /// OR combination
    Or(Box<Matcher>, Box<Matcher>),

    /// NOT
    Not(Box<Matcher>),
}

impl<'de> Deserialize<'de> for Matcher {
    /// Reads the tagged form, falling back to the shapes a `0.1.7` config
    /// could hold.
    ///
    /// The two forms cannot be confused: a tagged matcher is a map whose only
    /// key is a variant name, and no legacy shape has a key called `path`,
    /// `host`, `not`, and so on. The tagged form is tried first so a config
    /// that has been rewritten always wins.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Mirrors `Matcher` purely to borrow serde's derived externally
        // tagged reader. Kept inside the function so the two lists cannot
        // drift apart unnoticed and so it never reaches the public API.
        #[derive(Deserialize)]
        #[serde(rename_all = "snake_case")]
        enum Tagged {
            Path {
                patterns: Vec<String>,
            },
            Header {
                name: String,
                condition: MatcherCondition,
            },
            Method {
                methods: Vec<String>,
            },
            Query {
                name: String,
                condition: MatcherCondition,
            },
            Host(Vec<String>),
            RemoteIp(Vec<String>),
            Protocol(Vec<String>),
            Vars {
                name: String,
                values: Vec<String>,
            },
            PathRegexp {
                name: Option<String>,
                pattern: String,
            },
            HeaderRegexp {
                name: Option<String>,
                field: String,
                pattern: String,
            },
            File {
                try_files: Vec<String>,
                root: Option<String>,
                try_policy: Option<String>,
                split_path: Vec<String>,
            },
            And(Box<Matcher>, Box<Matcher>),
            Or(Box<Matcher>, Box<Matcher>),
            Not(Box<Matcher>),
        }

        /// The shapes a `0.1.7` config could actually contain.
        ///
        /// Deliberately *not* one variant per matcher: several matchers
        /// shared a shape back then, and the reading below reproduces the
        /// one `0.1.7` performed rather than guessing at the author's
        /// intent. A file that has always been read as a `Header` must not
        /// quietly start behaving as a `Query` because this code now knows
        /// the difference — the tagged form is how you say which you meant.
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Legacy {
            Path {
                patterns: Vec<String>,
            },
            Method {
                methods: Vec<String>,
            },
            /// Also how a `Query` was written; `0.1.7` read it as a `Header`.
            Header {
                name: String,
                condition: MatcherCondition,
            },
            /// Also how `RemoteIp` and `Protocol` were written.
            Host(Vec<String>),
            /// Also how an `Or` was written.
            And(Box<Matcher>, Box<Matcher>),
        }

        #[derive(Deserialize)]
        #[serde(
            untagged,
            expecting = "a tagged matcher such as {\"path\": {\"patterns\": [\"/api/*\"]}}, or a 0.1.7 untagged matcher"
        )]
        enum Repr {
            Tagged(Tagged),
            Legacy(Legacy),
        }

        Ok(match Repr::deserialize(deserializer)? {
            Repr::Tagged(Tagged::Path { patterns }) => Matcher::Path { patterns },
            Repr::Tagged(Tagged::Header { name, condition }) => Matcher::Header { name, condition },
            Repr::Tagged(Tagged::Method { methods }) => Matcher::Method { methods },
            Repr::Tagged(Tagged::Query { name, condition }) => Matcher::Query { name, condition },
            Repr::Tagged(Tagged::Host(hosts)) => Matcher::Host(hosts),
            Repr::Tagged(Tagged::RemoteIp(ips)) => Matcher::RemoteIp(ips),
            Repr::Tagged(Tagged::Protocol(protocols)) => Matcher::Protocol(protocols),
            Repr::Tagged(Tagged::Vars { name, values }) => Matcher::Vars { name, values },
            Repr::Tagged(Tagged::PathRegexp { name, pattern }) => {
                Matcher::PathRegexp { name, pattern }
            }
            Repr::Tagged(Tagged::HeaderRegexp {
                name,
                field,
                pattern,
            }) => Matcher::HeaderRegexp {
                name,
                field,
                pattern,
            },
            Repr::Tagged(Tagged::File {
                try_files,
                root,
                try_policy,
                split_path,
            }) => Matcher::File {
                try_files,
                root,
                try_policy,
                split_path,
            },
            Repr::Tagged(Tagged::And(left, right)) => Matcher::And(left, right),
            Repr::Tagged(Tagged::Or(left, right)) => Matcher::Or(left, right),
            Repr::Tagged(Tagged::Not(inner)) => Matcher::Not(inner),

            Repr::Legacy(Legacy::Path { patterns }) => Matcher::Path { patterns },
            Repr::Legacy(Legacy::Method { methods }) => Matcher::Method { methods },
            Repr::Legacy(Legacy::Header { name, condition }) => Matcher::Header { name, condition },
            Repr::Legacy(Legacy::Host(hosts)) => Matcher::Host(hosts),
            Repr::Legacy(Legacy::And(left, right)) => Matcher::And(left, right),
        })
    }
}

/// Matcher condition
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatcherCondition {
    Exists,
    Equals(String),
    Contains(String),
    StartsWith(String),
    EndsWith(String),
    Regex(String),
}

/// 🧭 One element of a `Pipeline`/`Handle`/`HandlePath` group.
///
/// The optional matcher guards the handler, matching Caddy's model of one
/// route per subdirective. The handler is flattened into the same JSON map,
/// so an element without a matcher keeps the exact shape a pipeline element
/// has always had — only a matcher-guarded element gains the `matcher` key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandlerElement {
    /// 🎯 Optional matcher; `None` runs the element for every request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matcher: Option<Matcher>,
    /// 🧩 The guarded handler.
    #[serde(flatten)]
    pub handler: HandlerConfig,
}

impl HandlerElement {
    /// 🧩 Builds an unconditional element.
    pub fn plain(handler: HandlerConfig) -> Self {
        Self {
            matcher: None,
            handler,
        }
    }

    /// 🎯 Builds a matcher-guarded element.
    pub fn with_matcher(matcher: Matcher, handler: HandlerConfig) -> Self {
        Self {
            matcher: Some(matcher),
            handler,
        }
    }
}

/// 🔑 Selects the identity charged by one rate-limit policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitKey {
    /// 🌐 Charges each verified client IP independently.
    Ip,
    /// 🌍 Charges every request reaching this limiter to one shared bucket.
    Global,
    /// 🛣️ Charges the matched route as one bucket.
    Route,
    /// 🎫 Charges the bearer token or `X-API-Key` value without retaining the secret.
    ApiKey,
    /// 🏷️ Charges the value of an arbitrary request header.
    Header(String),
    /// 🏢 Charges the value of a tenant header.
    Tenant(String),
}

/// Handler configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HandlerConfig {
    /// Static file server
    FileServer {
        root: String,
        #[serde(default)]
        index: Vec<String>,
        #[serde(default)]
        browse: bool,
        #[serde(default)]
        browse_limit: Option<usize>,
        #[serde(default = "default_bool_true")]
        compress: bool,

        /// 🗜️ Encodings whose sidecar files may be served, in preference
        /// order (`app.js.br` for `app.js`). Empty means never look, which is
        /// upstream's default: a stale sidecar is a wrong answer, so hunting
        /// for one has to be asked for.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        precompressed: Vec<String>,

        /// 🙈 Paths this server pretends do not exist. A pattern with no
        /// separator hides any path *component* that matches it, so `.git`
        /// hides `/a/.git/b`; one with a separator is a path prefix.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        hide: Vec<String>,

        /// 🔢 Overrides the status of a successful response, for the
        /// maintenance-page shape where every file is served as 503.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        status: Option<u16>,

        /// ➡️ On a miss, hand the request to the next handler instead of
        /// answering 404.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        pass_thru: bool,

        /// 🔁 Redirect a directory without a trailing slash to the slashed
        /// form, and a file with one to the bare form. On by default, exactly
        /// as upstream; `disable_canonical_uris` turns it off.
        #[serde(default = "default_bool_true")]
        canonical_uris: bool,

        /// 🏷️ Extensions of sidecar files holding a precomputed ETag, tried
        /// in order before one is derived from size and mtime.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        etag_file_extensions: Vec<String>,
    },

    /// 🏛️ A site that acts as an ACME server for other clients.
    ///
    /// Parsed, validated and serialised; never performed. `run.rs` refuses to
    /// start when a site carries this, because a server that answers ACME
    /// requests and issues nothing is worse than one that says so.
    AcmeServer(Box<AcmeServerConfig>),

    /// Caddy-compatible template rendering (`{{now | date "..."}}`)
    Templates {
        /// Site root used to resolve `include` paths.
        #[serde(default)]
        root: Option<String>,
    },

    /// Reverse proxy
    ReverseProxy(Box<ReverseProxyConfig>),

    /// 🌊 Copies the upstream response through to the client, optionally with
    /// a different status. The body keeps streaming chunk by chunk and is
    /// never buffered whole.
    CopyResponse {
        /// Replacement status code; `None` keeps the upstream status.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        status_code: Option<u16>,
    },

    /// 🧾 Copies selected upstream response headers onto the downstream
    /// response; `include` wins when both lists are present.
    CopyResponseHeaders {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        include: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        exclude: Vec<String>,
    },

    /// 🧭 Wraps the response of later handlers in the same request with the
    /// given response handlers, like Caddy's `intercept`.
    Intercept {
        /// Response handlers evaluated against the wrapped response.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        handlers: Vec<ResponseHandlerConfig>,
    },

    /// 🔐 Caddy's `forward_auth`: one auth round trip before the request
    /// continues to later handlers. A 2xx copies identity headers onto the
    /// request and moves on; anything else is answered directly.
    ForwardAuth(Box<ForwardAuthConfig>),

    /// Redirect
    Redirect {
        to: String,
        #[serde(default = "default_redirect_code")]
        code: u16,
    },

    /// URI rewrite (internal - does not send redirect to client)
    /// Similar to Caddy's uri and rewrite directives
    Rewrite {
        /// Strip prefix from path (e.g., "/api" removes "/api/users" -> "/users")
        #[serde(default)]
        strip_prefix: Option<String>,
        /// Strip suffix from path
        #[serde(default)]
        strip_suffix: Option<String>,
        /// Replace path entirely with this value (supports {placeholders})
        #[serde(default)]
        replace: Option<String>,
        /// Regex pattern to match
        #[serde(default)]
        regex: Option<String>,
        /// Replacement string for regex (supports capture groups $1, $2, etc)
        #[serde(default)]
        regex_replace: Option<String>,

        /// 🔤 Replaces the request method, which is what the `method`
        /// directive compiles to.
        ///
        /// A rewrite is a setter for the parts of a request a later handler
        /// reads, and the method is one of those parts — so it lives here
        /// rather than in a handler of its own, exactly as upstream models it.
        /// The value is a template and is upper-cased after resolution, so
        /// `method {http.request.header.X-Verb}` behaves.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        method: Option<String>,
    },

    /// 🔪 Closes the connection without writing anything at all.
    ///
    /// Not an error page, not an empty 200 — no response. The client sees a
    /// connection that ended. This is what an operator reaches for when the
    /// right answer to a request is to give the sender nothing to learn from,
    /// which is why it must never be confused with a 444-style empty status:
    /// a status line is still an answer.
    Abort,

    /// 📊 Serves the Prometheus scrape endpoint from inside a site.
    ///
    /// The admin API has always exposed `/metrics`; this puts the same numbers
    /// on a normal route, so a scrape can reach them without the admin socket
    /// being reachable at all. That is the whole point of the directive
    /// upstream: metrics and administration are different trust boundaries, and
    /// wiring them to the same listener forces an operator to expose one to get
    /// the other.
    ///
    /// 🛡️ Nothing here restricts who may scrape. The route is as open as the
    /// site it sits in, so an endpoint on a public site wants a matcher or a
    /// `basic_auth` in front of it — the same as upstream, which also leaves
    /// that to the operator.
    Metrics {
        /// 📉 Records that the operator does not want OpenMetrics negotiation.
        ///
        /// ⚠️ Pingclair's exporter only ever writes the Prometheus text
        /// exposition format, so setting this asks for the behaviour already in
        /// effect and leaving it unset does **not** buy negotiation. It is read
        /// and kept so the configuration round-trips and so this divergence has
        /// somewhere to be written down, rather than a name the parser throws
        /// away. See `TRIAGE.md`.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        disable_openmetrics: bool,
    },

    /// 🏷️ Rewrites headers on the **request**, before later handlers read it.
    ///
    /// Distinct from [`HandlerConfig::Headers`], which rewrites the response.
    /// The two are separate directives upstream for the same reason they are
    /// separate variants here: a request header is an input to routing,
    /// authentication and the upstream call, so changing it changes what
    /// happens next — while a response header only changes what the client is
    /// told about something that already happened.
    RequestHeaders {
        #[serde(default)]
        set: BTreeMap<String, String>,
        #[serde(default)]
        add: BTreeMap<String, String>,
        #[serde(default)]
        remove: Vec<String>,
        /// 🔁 Regex search-and-replace over a header's existing values, in
        /// the order written.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        replace: Vec<HeaderReplacement>,
    },

    /// 📥 Bounds this route's request body, overriding the site's limit.
    ///
    /// The site-wide `client_max_body_size` is the floor an operator sets
    /// once; this is the exception for the one route that uploads. It is a
    /// handler rather than a setting because the format makes it one — and
    /// because a matcher can then decide *which* requests get the exception,
    /// which a per-site number cannot express.
    RequestBody {
        /// Maximum body size in bytes. `None` leaves the site's limit alone.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_size: Option<u64>,
    },

    /// Respond with static content
    Respond {
        #[serde(default = "default_status_code")]
        status: u16,
        body: Option<String>,
        #[serde(default)]
        headers: BTreeMap<String, String>,
    },

    /// 🚨 Static error response raised by the `error` directive.
    Error {
        #[serde(default = "default_error_status")]
        status: u16,
        /// 💬 Message rendered as the response body; the status's canonical
        /// text is used when none is given.
        #[serde(default)]
        message: Option<String>,
    },

    /// Headers modification, on the **response**.
    Headers {
        #[serde(default)]
        set: BTreeMap<String, String>,
        #[serde(default)]
        add: BTreeMap<String, String>,
        #[serde(default)]
        remove: Vec<String>,
        /// 🔁 Regex search-and-replace over values the response already
        /// carries, in the order written. Distinct from `set`, which decides
        /// the value without looking at what was there.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        replace: Vec<HeaderReplacement>,
        /// ❓ Values written only when the response does not already carry
        /// that header — the `?` modifier.
        ///
        /// Response-only, because "is it already there" needs a message to
        /// look at. The request-side equivalent is a matcher.
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        default_set: BTreeMap<String, String>,
    },

    /// 🚫 Marks the request as excluded from access logging (`log_skip`).
    LogSkip,

    /// 🧰 Sets request-scoped variables, visible to `{http.vars.*}`.
    Vars {
        #[serde(default)]
        values: BTreeMap<String, String>,
    },

    /// 🧵 A sequential group: every element whose matcher accepts the request
    /// runs, in order, until one of them answers.
    ///
    /// Both `route` and `handle` compile to this. They differ only in how the
    /// block's contents were arranged — `route` keeps the order they were
    /// written in, `handle` sorts them into the format's directive order — and
    /// that difference is settled while adapting, not at request time.
    ///
    /// 🧭 `handle` blocks are still mutually exclusive **with each other**;
    /// that exclusivity lives one level up, in the route each block became,
    /// which is also where upstream puts it.
    ///
    /// 📌 The `handle` alias is for configurations serialised before
    /// 2026-08-12, when a `handle` block compiled to a first-match group by
    /// mistake. Loading them as sequential is the corrected reading of what
    /// they always meant.
    #[serde(alias = "handle")]
    Pipeline { handlers: Vec<HandlerElement> },

    /// 🎯 A mutually exclusive group: the **first matching** element owns the
    /// request and the rest never run, even if it passes through.
    ///
    /// This is what `try_files` needs — a list of candidate rewrites of which
    /// exactly one may apply — and it is *not* what the `handle` directive
    /// means, despite the name this variant used to carry.
    ///
    /// > 🤡 The two were the same variant until 2026-08-12, and the conflation
    /// > cost real behaviour: a `handle` block ran only its first matching
    /// > directive, so `handle /x/* { header X-A b; respond "ok" }` set the
    /// > header and then answered nothing. A container whose name means two
    /// > things will eventually be given the wrong one.
    #[serde(rename = "first_match")]
    FirstMatch { handlers: Vec<HandlerElement> },

    /// HTTP Basic Authentication
    /// Requires valid credentials before allowing access
    BasicAuth {
        /// Realm name shown to user
        #[serde(default = "default_auth_realm")]
        realm: String,
        /// List of allowed username:password_hash pairs
        /// 🔑 Credentials, each a hash of its declared algorithm.
        credentials: Vec<BasicAuthCredential>,
    },

    /// Rate limiting handler
    /// Limits requests per time window with optional burst
    RateLimit {
        /// Maximum requests per window
        #[serde(default = "default_rate_limit_requests")]
        requests: u64,
        /// Window duration in seconds
        #[serde(default = "default_rate_limit_window")]
        window_secs: u64,
        /// Rate limit by IP address (default: true)
        #[serde(default = "default_bool_true")]
        by_ip: bool,
        /// Extra burst allowance
        #[serde(default)]
        burst: u64,
        /// 🔑 Overrides the legacy `by_ip` switch with an explicit key source.
        #[serde(default)]
        key: Option<RateLimitKey>,
        /// 🧪 Reports exact quota state without rejecting over-limit requests.
        #[serde(default)]
        dry_run: bool,
    },

    /// Error handling
    /// Define handlers for specific error codes
    HandleErrors {
        /// Map of internal error codes to handlers
        /// Note: This is a placeholder for future implementation
        #[serde(default)]
        errors: BTreeMap<u16, Vec<HandlerConfig>>,
    },

    /// Handle with path stripping
    /// Strips the prefix from the path before executing valid handlers
    /// Similar to Caddy's handle_path directive
    HandlePath {
        /// Prefix to strip
        prefix: String,
        /// Matcher-guarded elements to execute with the stripped path
        handlers: Vec<HandlerElement>,
    },

    /// CORS (Cross-Origin Resource Sharing) handler
    /// Automatically handles preflight OPTIONS requests and adds CORS headers
    Cors {
        /// Allowed origins (e.g., ["https://example.com", "*"])
        #[serde(default)]
        allowed_origins: Vec<String>,
        /// Allowed methods (e.g., ["GET", "POST"])
        #[serde(default = "default_cors_methods")]
        allowed_methods: Vec<String>,
        /// Allowed headers
        #[serde(default = "default_cors_headers")]
        allowed_headers: Vec<String>,
        /// Exposed headers
        #[serde(default)]
        exposed_headers: Vec<String>,
        /// Allow credentials
        #[serde(default)]
        allow_credentials: bool,
        /// Max age in seconds for preflight cache
        #[serde(default = "default_cors_max_age")]
        max_age: u64,
    },

    /// Request access control evaluated before the route's terminal handler.
    /// Deny rules take precedence; populated allow lists are mandatory.
    AccessControl(AccessControlConfig),

    /// 🗂️ Rewrites the request to the first candidate that exists on disk.
    ///
    /// The candidates are URI paths, not filesystem paths: each one is looked
    /// up under [`root`](Self::TryFiles::root) and, when it exists, becomes
    /// the request's new path. Nothing is served here — the handler that runs
    /// next does that, which is why the single-page-application pattern is
    /// `try_files` followed by `file_server`. When no candidate exists the
    /// request continues with its path untouched.
    ///
    /// 📌 This is a rewrite rather than a file server because that is the only
    /// arrangement in which `root`, `index`, compression, range requests, and
    /// `Etag` keep working: the file server stays the one thing that reads
    /// files, and `try_files` only decides which path it is asked for.
    TryFiles {
        /// Candidate URI paths, tried in order. `{path}` expands to the
        /// request path; validation refuses any other placeholder, and
        /// refuses `..` in any segment.
        files: Vec<String>,
        /// Document root the candidates are resolved against. Filled in from
        /// the site's `root` directive; `None` means the working directory,
        /// matching a file server that was given no root either.
        #[serde(default)]
        root: Option<String>,
        /// Handler to run when no candidate exists. The Pingclairfile
        /// adapter never produces one — it exists for JSON configurations,
        /// which had it before `try_files` was reachable from the DSL.
        fallback: Option<Box<HandlerConfig>>,
    },

    /// Plugin invocation
    Plugin { name: String, args: Vec<String> },
}

/// 🔐 One `copy_headers` mapping: the auth response header `from` is copied
/// onto the forwarded request as `to` (defaulting to `from`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForwardAuthHeaderMap {
    pub from: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
}

/// 🔐 The auth round trip Caddy's `forward_auth` shortcut configures.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForwardAuthConfig {
    /// Auth gateway dial address.
    pub upstream: String,
    /// URI the auth gateway is asked for; placeholders are expanded per
    /// request.
    pub uri: String,
    /// Response headers copied onto the forwarded request, with renames.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub copy_headers: Vec<ForwardAuthHeaderMap>,
}

impl ForwardAuthConfig {
    /// 🔐 Normalizes the legacy handler into the reverse-proxy subrequest Caddy defines.
    pub fn as_reverse_proxy_subrequest(&self) -> ReverseProxyConfig {
        let mut headers_up = BTreeMap::new();
        headers_up.insert(
            "X-Forwarded-Method".to_string(),
            "{http.request.method}".to_string(),
        );
        headers_up.insert(
            "X-Forwarded-Uri".to_string(),
            "{http.request.uri}".to_string(),
        );
        ReverseProxyConfig {
            upstreams: vec![self.upstream.clone()],
            rewrite_method: Some("GET".to_string()),
            rewrite_uri: Some(self.uri.clone()),
            headers_up,
            subrequest: Some(Box::new(ReverseProxySubrequestConfig {
                continue_status_classes: vec![2],
                copy_headers: self.copy_headers.clone(),
            })),
            ..ReverseProxyConfig::default()
        }
    }
}

fn default_bool_true() -> bool {
    true
}

fn default_redirect_code() -> u16 {
    302
}

fn default_cors_methods() -> Vec<String> {
    vec![
        "GET".into(),
        "POST".into(),
        "PUT".into(),
        "DELETE".into(),
        "OPTIONS".into(),
    ]
}

fn default_cors_headers() -> Vec<String> {
    vec![
        "Content-Type".into(),
        "Authorization".into(),
        "X-Requested-With".into(),
    ]
}

fn default_cors_max_age() -> u64 {
    86400 // 24 hours
}

fn default_status_code() -> u16 {
    200
}

/// 🚨 A bare `error` raises 500, exactly as upstream defaults it.
fn default_error_status() -> u16 {
    500
}

fn default_auth_realm() -> String {
    "Restricted".to_string()
}

fn default_rate_limit_requests() -> u64 {
    100
}

fn default_rate_limit_window() -> u64 {
    60
}

/// 🔐 Hash algorithm a `basic_auth` credential declares.
///
/// The algorithm is a property of the configuration, never guessed from the
/// hash text: a `$argon2id$` string used to fall through the `$2`-prefix
/// check and authenticate anyone who typed the hash itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BasicAuthAlgorithm {
    /// 🔑 bcrypt, Caddy's default `basic_auth` algorithm.
    Bcrypt,
    /// 🔒 Argon2id, chosen with `basic_auth argon2id { … }`.
    Argon2id,
}

/// 🔁 One regex search-and-replace over the values of a request header.
///
/// The `request_header <field> <find> <replace>` form. It edits values that
/// are already there rather than setting a new one, which is why it cannot be
/// expressed as a `set`: the result depends on what the client sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderReplacement {
    /// Header name whose values are rewritten.
    pub field: String,
    /// Regular expression matched against each existing value.
    pub search_regexp: String,
    /// Replacement text; `$1`-style capture references are honoured.
    pub replace: String,
}

/// 🔐 Basic Auth credential.
#[derive(Debug, Clone, Serialize)]
pub struct BasicAuthCredential {
    /// 👤 Username presented by the client.
    pub username: String,
    /// 🔑 The password hash, in the declared algorithm's format.
    pub password: String,
    /// 🔑 Algorithm the password hash was produced with.
    pub algorithm: BasicAuthAlgorithm,
}

impl<'de> Deserialize<'de> for BasicAuthCredential {
    /// 🧩 Loads the current shape and the legacy one side by side.
    ///
    /// Documents written before the algorithm was a field said
    /// `"hashed": true` to mean bcrypt, and the old plaintext spelling
    /// (`"hashed": false` or absent) is refused rather than revived — a
    /// literal password compared against itself is the exact trap this
    /// change removes.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Raw {
            username: String,
            password: String,
            #[serde(default)]
            algorithm: Option<BasicAuthAlgorithm>,
            #[serde(default)]
            hashed: Option<bool>,
        }

        let raw = Raw::deserialize(deserializer)?;
        let algorithm = match (raw.algorithm, raw.hashed) {
            (Some(algorithm), _) => algorithm,
            (None, Some(true)) => BasicAuthAlgorithm::Bcrypt,
            (None, _) => {
                return Err(serde::de::Error::custom(
                    "basic_auth credentials must declare a hash algorithm; plaintext \
                     passwords are refused (hash one with `pingclair hash-password`)",
                ));
            }
        };
        Ok(Self {
            username: raw.username,
            password: raw.password,
            algorithm,
        })
    }
}

/// Reverse proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReverseProxyConfig {
    /// Upstream URLs
    pub upstreams: Vec<String>,

    /// 🧵 FastCGI transport chosen by `transport fastcgi` or the
    /// `php_fastcgi` shortcut. `None` means the ordinary HTTP transports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fastcgi: Option<Box<FastCgiTransportConfig>>,

    /// 🧭 Upstream discovery that happens after configuration, from DNS
    /// records rather than a fixed list. When present, `upstreams` usually
    /// stays empty; both may coexist, with dynamic peers joining the pool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dynamic_upstream: Option<Box<DynamicUpstreamConfig>>,

    /// 🧭 Request method change applied before proxying, from Caddy's
    /// `method` subdirective; `None` forwards the client's method untouched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rewrite_method: Option<String>,

    /// 🧭 URI template applied to the upstream request target; placeholders
    /// are expanded per request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rewrite_uri: Option<String>,

    /// 🧱 How much of the request body to read into memory before writing any
    /// of it to the upstream. `None` or `0` streams, which is the default;
    /// `-1` is `unlimited`.
    ///
    /// 🛡️ `unlimited` does not mean unbounded memory here: the runtime holds
    /// up to its own ceiling and streams the rest. See
    /// `pingclair-proxy/src/body_buffer.rs` for why, including why nothing
    /// spills to a temporary file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_buffer_bytes: Option<i64>,

    /// 🧱 The same ceiling for the response body, applied between the upstream
    /// and the client. `None` or `0` streams; `-1` is `unlimited`, bounded by
    /// the runtime's own ceiling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_buffer_bytes: Option<i64>,

    /// 🧭 Transport tuning options that have no runtime equivalent yet. They
    /// stay visible in the compiled configuration and are logged at startup
    /// so an operator is never silently told a knob took effect.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub transport_options: BTreeMap<String, String>,

    /// 🧭 Response handlers evaluated against the upstream response before
    /// the client sees it; the first matching entry wins, matcherless
    /// entries last, mirroring Caddy's `handle_response`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub handle_response: Vec<ResponseHandlerConfig>,

    /// 🔁 Turns this proxy exchange into a bounded inline subrequest.
    ///
    /// A matching response class mutates the original request and continues
    /// the handler pipeline. Every other response is streamed to the client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subrequest: Option<Box<ReverseProxySubrequestConfig>>,

    /// Per-upstream weight and backup role. When empty, every address in
    /// `upstreams` is a primary with weight one (the legacy JSON form).
    #[serde(default)]
    pub upstream_options: Vec<ProxyUpstream>,

    /// Load balancing configuration
    #[serde(default)]
    pub load_balance: LoadBalanceConfig,

    /// 🩺 Active upstream health-check configuration.
    #[serde(default)]
    pub health_check: Option<Box<HealthCheckConfig>>,

    /// Headers to add to upstream request
    #[serde(default)]
    pub headers_up: BTreeMap<String, String>,

    /// Headers to add to downstream response
    #[serde(default)]
    pub headers_down: BTreeMap<String, String>,

    /// Flush interval in milliseconds (-1 for immediate)
    pub flush_interval: Option<i64>,

    /// Read timeout in milliseconds
    pub read_timeout: Option<i64>,

    /// Write timeout in milliseconds
    pub write_timeout: Option<i64>,

    /// 🔌 Maximum time allowed for upstream connection establishment.
    pub connect_timeout: Option<i64>,

    /// ⏱️ Maximum time allowed before the upstream response header arrives.
    pub first_byte_timeout: Option<i64>,

    /// 🌊 Maximum pause allowed between upstream response-body reads.
    pub between_reads_timeout: Option<i64>,

    /// 🔁 Bounded redispatch policy for this reverse-proxy route.
    #[serde(default)]
    pub retry: Box<RetryConfig>,

    /// 🚦 Route and per-upstream admission limits.
    #[serde(default)]
    pub overload: Box<OverloadConfig>,

    /// 🔌 Per-upstream circuit-breaker policy.
    #[serde(default)]
    pub circuit_breaker: Box<CircuitBreakerConfig>,

    /// 🔐 How this route authenticates and verifies its TLS upstreams.
    #[serde(default)]
    pub upstream_tls: Box<UpstreamTlsConfig>,

    /// 🗄️ Response caching for this route, off unless configured.
    #[serde(default)]
    pub cache: Option<Box<CacheConfig>>,
}

/// 🔁 Runtime-neutral continuation policy for one inline reverse-proxy subrequest.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ReverseProxySubrequestConfig {
    /// 🎯 One-digit HTTP status classes that authorize pipeline continuation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub continue_status_classes: Vec<u16>,
    /// 🔐 Response headers copied onto the continued request after deleting each destination.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub copy_headers: Vec<ForwardAuthHeaderMap>,
}

/// 🧵 The FastCGI transport: how PHP-FPM is spoken to.
///
/// Caddy's `transport fastcgi { … }` block and the `php_fastcgi` shortcut
/// both compile into this shape. `dial_timeout`, `read_timeout` and
/// `write_timeout` are millisecond durations; `root` defaults to the site's
/// `root` directive at compile time.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct FastCgiTransportConfig {
    /// 📂 Document root reported to the responder as `DOCUMENT_ROOT`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
    /// 🪚 ASCII path split delimiters (`.php`, `.php5`); comparison is
    /// case-insensitive and non-ASCII entries are refused at load time.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub split_path: Vec<String>,
    /// 🧰 Extra environment variables sent to the responder.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// 🔗 Resolve `root` symlinks before reporting `DOCUMENT_ROOT`; PHP's
    /// opcache caches the path, so a changing symlink needs the real path.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub resolve_root_symlink: bool,
    /// 🔌 Connect deadline in milliseconds; default 3s like upstream.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dial_timeout_ms: Option<u64>,
    /// ⏱️ Read deadline in milliseconds per record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_timeout_ms: Option<u64>,
    /// ⏱️ Write deadline in milliseconds per record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_timeout_ms: Option<u64>,
    /// ⚠️ Keep the responder's stderr for the access log; discarded when off.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub capture_stderr: bool,
}

/// 🧭 A matcher evaluated against an upstream response: status and headers.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ResponseMatcher {
    /// Status codes; a one-digit value such as `2` means the whole class.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub status_codes: Vec<u16>,
    /// Header name → value patterns (`*` means "header present").
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, Vec<String>>,
}

/// One ordered `handle_response` entry.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResponseHandlerConfig {
    /// Response matcher; `None` matches every response and is evaluated last.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matcher: Option<ResponseMatcher>,
    /// `replace_status` shorthand: a literal status or a placeholder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_code: Option<String>,
    /// Response subroute handlers, executed in order. A terminal handler
    /// (`respond`, `copy_response`, `error`) replaces or forwards the
    /// response; header-only entries mutate it in place.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub handlers: Vec<HandlerConfig>,
}

/// 🧭 The two DNS record families Caddy's `dynamic` source understands.
///
/// 🚨 This enum must stay externally tagged in JSON: an untagged shape would
/// invite the same ambiguous-deserialization class of bug the matcher types
/// guard against, and the adapter always writes one concrete variant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DynamicUpstreamConfig {
    /// 📜 A-record discovery: every address of `name` on one fixed `port`.
    A(DynamicAddrUpstream),
    /// 🧾 SRV-record discovery: the target host and port of every record.
    Srv(DynamicSrvUpstream),
}

/// 📜 A dynamic upstream resolved from the A/AAAA records of one name.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DynamicAddrUpstream {
    /// 🌐 Hostname whose address records supply the peers.
    pub name: String,
    /// 🔌 Port every discovered peer is dialed on.
    pub port: u16,
    /// ⏱️ Refresh interval in seconds; `None` follows the global `dns_refresh`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_secs: Option<u64>,
    /// 📡 Explicit DNS server addresses; empty means the system resolver.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolvers: Vec<String>,
    /// ⏱️ Per-lookup timeout in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dial_timeout_ms: Option<u64>,
    /// ⏱️ RFC 6555 fast-fallback delay in milliseconds; negative disables it.
    /// 🚫 Retained for JSON decoding compatibility; validation rejects a value
    /// because Hickory exposes no equivalent resolver-dial fallback hook.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_delay_ms: Option<i64>,
    /// 🧭 Address family filter: `ipv4`, `ipv6`, or `None` for both.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub versions: Option<String>,
}

/// 🧾 A dynamic upstream resolved from SRV records (RFC 2782).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DynamicSrvUpstream {
    /// 🧭 The full SRV name, or the `name` part when `service`/`proto` are set.
    pub name: String,
    /// 🏷️ Service label; the lookup name becomes `_service._proto.name`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// 🌐 Protocol label (`tcp` or `udp`) used when `service` is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proto: Option<String>,
    /// ⏱️ Refresh interval in seconds; `None` follows the global `dns_refresh`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_secs: Option<u64>,
    /// 📡 Explicit DNS server addresses; empty means the system resolver.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolvers: Vec<String>,
    /// ⏱️ Per-lookup timeout in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dial_timeout_ms: Option<u64>,
    /// ⏱️ RFC 6555 fast-fallback delay in milliseconds; negative disables it.
    /// 🚫 Retained for JSON decoding compatibility; validation rejects a value
    /// because Hickory exposes no equivalent resolver-dial fallback hook.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_delay_ms: Option<i64>,
    /// 🌤️ Milliseconds to keep serving last-known-good peers after a lookup
    /// failure; `None` fails the request instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grace_period_ms: Option<u64>,
}

/// 🗄️ Stores upstream responses so identical requests skip the origin.
///
/// Caching is opt-in per route. There is no global default because a wrong
/// cache does not fail loudly — it serves the wrong bytes to the wrong person,
/// and keeps doing it until the entry expires.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CacheConfig {
    /// ⏳ How long a stored response stays fresh, in seconds.
    ///
    /// Required rather than defaulted: picking a lifetime for someone else's
    /// content is exactly the decision an operator has to make deliberately.
    pub ttl_secs: u64,
    /// 📏 Hard ceiling on stored response bytes, process-wide.
    ///
    /// Unlike `ttl_secs` this one *is* defaulted, because the two questions are
    /// different. A wrong TTL serves stale content and only the operator knows
    /// the right answer; an absent ceiling lets the process grow until the box
    /// dies, and "some limit" beats "no limit" whatever the number is. The
    /// default is deliberately modest so that turning caching on cannot, by
    /// itself, be the thing that gets a server OOM-killed.
    ///
    /// The store is shared, so this bounds the whole process rather than one
    /// route: two routes with caching enabled draw on the same budget.
    #[serde(default = "default_cache_max_size_bytes")]
    pub max_size_bytes: usize,
}

/// 📏 128 MiB, the same order as nginx's `keys_zone` examples and small enough
/// to be survivable on the 512 MiB-class hosts this project benchmarks on.
pub fn default_cache_max_size_bytes() -> usize {
    128 * 1024 * 1024
}

/// 🔁 Controls safe, request-local upstream redispatch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RetryConfig {
    /// 🔢 Maximum upstream attempts, including the initial attempt.
    #[serde(default = "default_retry_attempts")]
    pub max_attempts: usize,
    /// ⌛ Maximum elapsed time across every attempt and backoff.
    #[serde(default)]
    pub total_timeout_ms: Option<u64>,
    /// 💤 Fixed delay before each retry.
    #[serde(default)]
    pub backoff_ms: u64,
    /// 🔄 Upstream status codes that trigger redispatch before response commit.
    #[serde(default)]
    pub status_codes: Vec<u16>,
    /// 🛡️ Idempotent methods eligible for status-code redispatch.
    #[serde(default = "default_retry_methods")]
    pub methods: Vec<String>,
    /// 🧭 Request-path glob patterns (`/foo*`) that must match for a status
    /// redispatch to be permitted, mirroring Caddy's `lb_retry_match path`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path_patterns: Vec<String>,
    /// 🧾 Retry-match expressions, kept verbatim for diagnostics only.
    ///
    /// ⚠️ Not evaluated — [`RetryConfig::retry_match`] is what decides. This
    /// field exists so an operator can see the text they wrote next to the
    /// predicate it became, and so a spelling nobody has taught the parser yet
    /// is visible rather than absent.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expressions: Vec<String>,

    /// 🔁 One entry per `lb_retry_match`, **any** of which permits a retry.
    ///
    /// Each `lb_retry_match` upstream is an independent matcher set and they
    /// are OR'd; conditions written *inside* one are AND'd. Folding them all
    /// into flat `status_codes`/`methods`/`path_patterns` lists — which is what
    /// this did until 2026-08-13 — loses that structure completely: two blocks
    /// saying "retry POSTs" and "retry anything under /foo" became one rule
    /// demanding both at once, and a third block could overwrite the method
    /// list of the first.
    ///
    /// 🏎️ Evaluated only after an attempt has already failed, so this is not a
    /// per-request cost; it is a per-retry-decision cost. Regexes are still
    /// compiled at load — `ProxyState` holds them — because "only on failure"
    /// is exactly when the machine is least able to afford compiling one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retry_match: Vec<RetryPredicate>,
}

/// 🧱 Deepest predicate tree accepted.
///
/// A retry rule this deep is not a configuration anyone wrote on purpose, and
/// an unbounded one is a stack overflow reachable from whoever can post a
/// config to the Admin API. This repository has already shipped that exact
/// shape once through `#[serde(untagged)]` on a recursive type, which is why
/// the enum below is tagged and why the limit is checked in `validate_config`
/// rather than trusted to a caller.
pub const MAX_RETRY_PREDICATE_DEPTH: usize = 8;

/// 🔁 One condition on whether a failed attempt may be retried.
///
/// This is a deliberately small language, not CEL. It carries exactly the
/// shapes `lb_retry_match` can express, each as a named case the runtime knows
/// how to answer — so "the configuration parsed" and "the runtime will act on
/// it" stop being two different questions. An expression the parser does not
/// recognise is refused at load rather than stored and ignored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum RetryPredicate {
    /// Every condition must hold (`&&`).
    All { of: Vec<RetryPredicate> },
    /// Any condition may hold (`||`).
    Any { of: Vec<RetryPredicate> },
    /// The upstream answered with one of these statuses.
    Status { any_of: Vec<u16> },
    /// The upstream answered with this status or higher (`>= 500`).
    StatusAtLeast { code: u16 },
    /// 🔌 The attempt never produced a status — a dial, TLS or read failure.
    TransportError,
    /// A response header equals this value, or exists at all when `value` is
    /// `*`.
    ResponseHeader { name: String, value: String },
    /// The request method is one of these, compared case-insensitively.
    Method { any_of: Vec<String> },
    /// The request path matches one of these globs (`/foo*`).
    Path { any_of: Vec<String> },
    /// The request path matches this regular expression.
    PathRegexp { pattern: String },
    /// The request `Host` is one of these.
    Host { any_of: Vec<String> },
    /// The request arrived over this scheme (`http` / `https`).
    Protocol { name: String },
    /// A query parameter has one of these values, or exists when `*`.
    Query { key: String, any_of: Vec<String> },
    /// A request header has one of these values, or exists when `*`.
    RequestHeader { name: String, any_of: Vec<String> },
    /// A request header matches this regular expression.
    HeaderRegexp { name: String, pattern: String },
}

impl RetryPredicate {
    /// 🧱 How deeply this tree nests, counting itself as one.
    pub fn depth(&self) -> usize {
        match self {
            Self::All { of } | Self::Any { of } => {
                1 + of.iter().map(Self::depth).max().unwrap_or(0)
            }
            _ => 1,
        }
    }

    /// 🔤 Visits every regular expression in the tree, so the caller can
    /// compile them once at load instead of once per retry decision.
    pub fn for_each_regex(&self, visit: &mut impl FnMut(&str)) {
        match self {
            Self::All { of } | Self::Any { of } => {
                for child in of {
                    child.for_each_regex(visit);
                }
            }
            Self::PathRegexp { pattern } | Self::HeaderRegexp { pattern, .. } => visit(pattern),
            _ => {}
        }
    }
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: default_retry_attempts(),
            total_timeout_ms: None,
            backoff_ms: 0,
            status_codes: Vec::new(),
            methods: default_retry_methods(),
            path_patterns: Vec::new(),
            expressions: Vec::new(),
            retry_match: Vec::new(),
        }
    }
}

fn default_retry_attempts() -> usize {
    16
}

fn default_retry_methods() -> Vec<String> {
    ["GET", "HEAD", "OPTIONS", "TRACE", "PUT", "DELETE"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

/// 🚦 Bounds concurrent work before an upstream request starts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OverloadConfig {
    /// 🧱 Maximum requests executing inside this reverse-proxy route.
    #[serde(default)]
    pub max_in_flight: Option<usize>,
    /// 🕰️ Maximum requests waiting for one route execution slot.
    #[serde(default)]
    pub max_pending: usize,
    /// ⌛ Maximum time a pending request may wait.
    #[serde(default = "default_pending_timeout_ms")]
    pub pending_timeout_ms: u64,
    /// 🔌 Maximum requests simultaneously occupying one selected upstream.
    #[serde(default)]
    pub upstream_max_connections: Option<usize>,
}

impl Default for OverloadConfig {
    fn default() -> Self {
        Self {
            max_in_flight: None,
            max_pending: 0,
            pending_timeout_ms: default_pending_timeout_ms(),
            upstream_max_connections: None,
        }
    }
}

fn default_pending_timeout_ms() -> u64 {
    1_000
}

/// 🔌 Opens a per-upstream circuit after bounded failure evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CircuitBreakerConfig {
    /// 🔻 Consecutive failures required to open the circuit.
    #[serde(default)]
    pub consecutive_failures: Option<u32>,
    /// 📉 Failure percentage required to open the circuit.
    #[serde(default)]
    pub error_rate_percent: Option<u8>,
    /// 🧪 Minimum observations required before error-rate evaluation.
    #[serde(default = "default_breaker_minimum_requests")]
    pub minimum_requests: usize,
    /// 🪟 Maximum observations retained in the rolling error window.
    #[serde(default = "default_breaker_window_requests")]
    pub window_requests: usize,
    /// ⏳ Time an open circuit waits before admitting half-open probes.
    #[serde(default = "default_breaker_open_duration_ms")]
    pub open_duration_ms: u64,
    /// 🚪 Successful half-open probes required to close the circuit.
    #[serde(default = "default_breaker_half_open_requests")]
    pub half_open_requests: usize,
    /// 🚨 Response statuses counted as failures; empty means every 5xx status.
    #[serde(default)]
    pub failure_statuses: Vec<u16>,
}

impl CircuitBreakerConfig {
    /// 🔌 Reports whether either opening threshold enables the breaker.
    pub fn enabled(&self) -> bool {
        self.consecutive_failures.is_some() || self.error_rate_percent.is_some()
    }
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            consecutive_failures: None,
            error_rate_percent: None,
            minimum_requests: default_breaker_minimum_requests(),
            window_requests: default_breaker_window_requests(),
            open_duration_ms: default_breaker_open_duration_ms(),
            half_open_requests: default_breaker_half_open_requests(),
            failure_statuses: Vec::new(),
        }
    }
}

fn default_breaker_minimum_requests() -> usize {
    20
}

fn default_breaker_window_requests() -> usize {
    100
}

fn default_breaker_open_duration_ms() -> u64 {
    30_000
}

fn default_breaker_half_open_requests() -> usize {
    1
}

/// 🔐 Describes how a reverse-proxy route speaks TLS to its upstreams.
///
/// Every field is inert unless the connection is actually TLS — either the
/// upstream address carries an `https://`/`h2://` scheme, or [`Self::enable`]
/// forces it. The defaults verify the upstream chain against the system trust
/// store and present no client certificate, which is what a plain
/// `reverse_proxy https://host` already did before this block existed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct UpstreamTlsConfig {
    /// 🔒 Speaks TLS even when the upstream address declares no scheme.
    #[serde(default)]
    pub enable: bool,

    /// 🏷️ Overrides the SNI sent and the name the upstream chain must match.
    ///
    /// Without this the proxy uses the upstream's configured hostname, which is
    /// the correct default; set it only when the address is an IP or an
    /// internal alias that the certificate does not name.
    #[serde(default)]
    pub server_name: Option<String>,

    /// 📜 PEM bundles that **replace** the system trust store for this route.
    ///
    /// Replacement, not addition: naming a private CA here means public CAs no
    /// longer verify for this route. That is deliberate — an internal upstream
    /// should not be satisfiable by a publicly issued certificate.
    #[serde(default)]
    pub trusted_ca_certs: Vec<String>,

    /// 🎫 PEM chain presented to the upstream for mutual TLS.
    #[serde(default)]
    pub client_cert: Option<String>,

    /// 🔑 PEM private key matching [`Self::client_cert`].
    #[serde(default)]
    pub client_key: Option<String>,

    /// ⚠️ Disables upstream certificate and hostname verification.
    ///
    /// This turns the upstream leg into unauthenticated encryption: anything
    /// able to answer on the upstream address is trusted. It exists for
    /// bootstrapping against a self-signed origin; `trusted_ca_certs` is the
    /// correct answer in every other case.
    #[serde(default)]
    pub insecure_skip_verify: bool,
}

impl UpstreamTlsConfig {
    /// 🔍 Reports whether anything here changes the default TLS behaviour.
    ///
    /// A route whose block is entirely defaults needs no compiled state, so the
    /// runtime can keep using the shared system-trust path.
    pub fn is_customized(&self) -> bool {
        self.enable
            || self.server_name.is_some()
            || !self.trusted_ca_certs.is_empty()
            || self.client_cert.is_some()
            || self.client_key.is_some()
            || self.insecure_skip_verify
    }

    /// 🎫 Returns the client certificate and key when mutual TLS is requested.
    ///
    /// Returns an error describing the missing half when only one is present,
    /// because a half-configured client identity silently degrades to an
    /// anonymous handshake and the upstream's rejection looks like a network
    /// fault.
    pub fn client_identity(&self) -> Result<Option<(&str, &str)>, &'static str> {
        match (self.client_cert.as_deref(), self.client_key.as_deref()) {
            (Some(cert), Some(key)) => Ok(Some((cert, key))),
            (None, None) => Ok(None),
            (Some(_), None) => {
                Err("tls_client_auth needs a key file, but only a certificate was configured")
            }
            (None, Some(_)) => {
                Err("tls_client_auth needs a certificate file, but only a key was configured")
            }
        }
    }
}

/// Load balancing configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LoadBalanceConfig {
    /// Strategy: round_robin, random, least_conn, ip_hash, header, cookie,
    /// query, first
    #[serde(default = "default_lb_strategy")]
    pub strategy: String,
    /// 🔑 Which request field supplies the consistent-hash key, for the
    /// strategies that hash something other than the client address.
    ///
    /// `None` for `ip_hash` and for every non-hashing strategy. The field is
    /// the header name, cookie name, or query parameter name depending on the
    /// strategy, which is why one field serves all three: they differ only in
    /// where the value is read from, never in what is done with it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash_key: Option<String>,
}

/// An upstream's selection properties.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyUpstream {
    /// Dial address, including an optional http/https scheme.
    pub address: String,
    /// Relative selection weight among primary (or backup) peers.
    #[serde(default = "default_upstream_weight")]
    pub weight: u32,
    /// Backup peers are only selected after every primary is unavailable.
    #[serde(default)]
    pub backup: bool,
}

fn default_upstream_weight() -> u32 {
    1
}

/// Route-level IP, Referer-host, and User-Agent access policy.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AccessControlConfig {
    /// CIDR or literal IP ranges that may access the route.
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    /// CIDR or literal IP ranges that are always rejected.
    #[serde(default)]
    pub denied_ips: Vec<String>,
    /// Referer hosts that may access the route. `*.example.com` matches
    /// subdomains; an empty Referer does not satisfy a populated allow list.
    #[serde(default)]
    pub allowed_referers: Vec<String>,
    /// Referer hosts that are always rejected.
    #[serde(default)]
    pub denied_referers: Vec<String>,
    /// Regular expressions that may match the User-Agent header.
    #[serde(default)]
    pub allowed_user_agents: Vec<String>,
    /// Regular expressions that always reject the User-Agent header.
    #[serde(default)]
    pub denied_user_agents: Vec<String>,
}

fn default_lb_strategy() -> String {
    "round_robin".to_string()
}

/// 🩺 Active upstream health-check configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    /// 🛣️ Request path sent to the probe endpoint.
    pub path: String,

    /// ⏲️ Base interval between probe rounds, in seconds.
    #[serde(default = "default_health_interval")]
    pub interval: u64,

    /// ⌛ Hard timeout for one probe, in seconds.
    #[serde(default = "default_health_timeout")]
    pub timeout: u64,

    /// 🧯 Legacy failure threshold retained for JSON compatibility.
    #[serde(default = "default_health_threshold")]
    pub threshold: u32,

    /// 📨 HTTP method used for the probe.
    #[serde(default = "default_health_method")]
    pub method: String,

    /// 🏷️ Optional Host header and TLS server name override.
    #[serde(default)]
    pub host: Option<String>,

    /// 🧾 Additional request headers sent by the probe.
    ///
    /// One name maps to *several* values because HTTP allows it and the format
    /// above uses it: `health_headers { Same-Key 1; Same-Key 2 }` sends both
    /// lines, and a single-valued map silently kept only the second. Order
    /// within a name is preserved and is the order they were written.
    #[serde(default, deserialize_with = "deserialize_probe_headers")]
    pub headers: BTreeMap<String, Vec<String>>,

    /// ✅ Exact response statuses accepted as healthy.
    #[serde(default = "default_health_statuses")]
    pub expected_statuses: Vec<u16>,

    /// 🔎 Optional UTF-8 response-body fragment required for success.
    #[serde(default)]
    pub expected_body: Option<String>,

    /// 🔌 Optional health endpoint port on each backend IP.
    #[serde(default)]
    pub port: Option<u16>,

    /// 🌱 Consecutive successful probes required before recovery.
    #[serde(default = "default_health_success_threshold")]
    pub consecutive_success: u32,

    /// 🧯 Consecutive failed probes required before removal.
    #[serde(default)]
    pub consecutive_failure: Option<u32>,

    /// ♻️ Whether probes may reuse an established upstream connection.
    #[serde(default)]
    pub reuse_connection: bool,

    /// 🧱 Maximum response-body bytes a probe may read.
    #[serde(default = "default_health_body_limit")]
    pub max_response_body_bytes: usize,

    /// 🌤️ Time in milliseconds for a recovered backend to regain full traffic.
    #[serde(default)]
    pub slow_start_ms: u64,
}

fn default_health_interval() -> u64 {
    30
}

fn default_health_timeout() -> u64 {
    5
}

fn default_health_threshold() -> u32 {
    3
}

fn default_health_method() -> String {
    "GET".to_string()
}

fn default_health_statuses() -> Vec<u16> {
    vec![200]
}

fn default_health_success_threshold() -> u32 {
    1
}

fn default_health_body_limit() -> usize {
    64 * 1024
}

/// Admin API configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminConfig {
    /// Listen address
    pub listen: String,

    /// Enable admin API
    #[serde(default = "default_admin_enabled")]
    pub enabled: bool,

    /// 🔑 API key for authentication.
    ///
    /// 🙈 Wrapped so a `{:?}` on this struct — or on anything containing it,
    /// which includes the whole configuration — cannot print the key.
    pub api_key: Option<crate::config::SecretString>,

    /// 🌐 `Origin`/`Host` values allowed to reach the admin API.
    ///
    /// Empty means Caddy's default: the listen address itself, plus loopback.
    /// The check exists because the admin API can rewrite the whole
    /// configuration, so a browser page on any origin being able to POST to it
    /// would be a full compromise via a single visited link.
    #[serde(default)]
    pub origins: Vec<String>,

    /// 🛡️ Whether to enforce the origin check even on loopback.
    ///
    /// Off by default, matching Caddy: a developer curling their own admin
    /// endpoint sends no `Origin` at all, and refusing that would make the API
    /// unusable from the command line for no security gain.
    #[serde(default)]
    pub enforce_origin: bool,
}

fn default_admin_enabled() -> bool {
    true
}

/// Global logging configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LoggingConfig {
    /// Log level
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Log format (json, pretty)
    #[serde(default = "default_log_format")]
    pub format: String,

    /// Log file path
    pub file: Option<String>,

    /// 🪵 Named access-log channels declared in the global block.
    ///
    /// A channel is a sink plus its format, rotation and header policy. Servers
    /// reference channels by name, and several servers referencing one channel
    /// share a single writer — which is the point: two writers on one file
    /// would interleave, so "the same channel" has to mean the same queue.
    ///
    /// The common case is an empty map and a per-server inline `log` block;
    /// channels exist for the shapes an inline block cannot express, such as
    /// sending 4xx/5xx somewhere separate from the ordinary access log.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub channels: BTreeMap<String, LogConfig>,

    /// 🪵 The default logger, configured by an unnamed global `log { … }`
    /// block. Process-level runtime logging is still environment-driven;
    /// accepting the block is what makes the format's own grammar compile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<LogConfig>,
}

/// Security headers configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecurityConfig {
    /// Enable basic security headers
    #[serde(default = "default_security_enabled")]
    pub enabled: bool,

    /// X-Frame-Options header
    #[serde(default = "default_x_frame_options")]
    pub x_frame_options: String,

    /// X-Content-Type-Options header
    #[serde(default = "default_x_content_type_options")]
    pub x_content_type_options: String,

    /// X-XSS-Protection header
    #[serde(default = "default_x_xss_protection")]
    pub x_xss_protection: String,

    /// X-Permitted-Cross-Domain-Policies header
    #[serde(default = "default_x_permitted_cross_domain")]
    pub x_permitted_cross_domain: String,

    /// Referrer-Policy header
    #[serde(default = "default_referrer_policy")]
    pub referrer_policy: String,

    /// Permissions-Policy header
    #[serde(default = "default_permissions_policy")]
    pub permissions_policy: String,

    /// Strict-Transport-Security header
    #[serde(default)]
    pub hsts: Option<HstsConfig>,

    /// Content-Security-Policy header
    #[serde(default)]
    pub csp: Option<String>,
}

/// HSTS (HTTP Strict Transport Security) configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HstsConfig {
    /// Max age in seconds
    #[serde(default = "default_hsts_max_age")]
    pub max_age: u64,

    /// Include subdomains
    #[serde(default = "default_hsts_include_subdomains")]
    pub include_subdomains: bool,

    /// Preload directive
    #[serde(default = "default_hsts_preload")]
    pub preload: bool,
}

fn default_security_enabled() -> bool {
    true
}

fn default_x_frame_options() -> String {
    "DENY".to_string()
}

fn default_x_content_type_options() -> String {
    "nosniff".to_string()
}

fn default_x_xss_protection() -> String {
    "1; mode=block".to_string()
}

fn default_x_permitted_cross_domain() -> String {
    "none".to_string()
}

fn default_referrer_policy() -> String {
    "strict-origin-when-cross-origin".to_string()
}

fn default_permissions_policy() -> String {
    "geolocation=(), microphone=(), camera=()".to_string()
}

fn default_hsts_max_age() -> u64 {
    31536000 // 1 year
}

fn default_hsts_include_subdomains() -> bool {
    true
}

fn default_hsts_preload() -> bool {
    false
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "pretty".to_string()
}

/// Per-server log configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    /// Log output destination
    pub output: LogOutput,

    /// Log format
    pub format: LogFormat,

    /// Log level (overrides global)
    pub level: Option<String>,

    /// 🙈 Access-log field names to omit, from
    /// `format filter { fields { <name> delete } }`.
    ///
    /// `#[serde(default)]` so configs written before this field existed
    /// still load.
    #[serde(default)]
    pub exclude_fields: Vec<String>,

    /// 🔄 File rotation policy. Ignored for stdout and stderr, which are
    /// somebody else's problem to rotate.
    #[serde(default)]
    pub rotation: LogRotation,

    /// 🏷️ Request and response header names to record, lowercased.
    ///
    /// Values are masked when [`crate::server::is_sensitive_header`] says so,
    /// which is why an operator can safely name `authorization` here: the
    /// field appears, the secret does not.
    #[serde(default)]
    pub request_headers: Vec<String>,
    #[serde(default)]
    pub response_headers: Vec<String>,

    /// 🔐 Whether to record the negotiated TLS version and cipher.
    #[serde(default)]
    pub include_tls: bool,

    /// 🏠 Hostnames this logger serves, from `log { hostnames … }`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hostnames: Vec<String>,

    /// 🔌 Log sources this logger accepts, from global `log { include … }`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include: Vec<String>,

    /// 🚫 Log sources this logger excludes, from global `log { exclude … }`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude: Vec<String>,

    /// 🎲 Sampling policy from `log { sampling { … } }`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sampling: Option<LogSampling>,
}

/// 🎲 Keeps the first `first` events, then every `thereafter`-th event in a
/// rolling interval — the shape Caddy's `sampling` block declares.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogSampling {
    pub interval_secs: u64,
    pub first: usize,
    pub thereafter: usize,
}

/// 🪵 A named per-site access logger from `log <name> { … }`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamedLogConfig {
    /// 🔖 The logger's handle, used by `log_name`/`include` associations.
    pub name: String,
    /// 🧾 The logger's output, format, level and rotation policy.
    #[serde(flatten)]
    pub config: LogConfig,
}

/// 🔄 When to start a new log file, and how many old ones to keep.
///
/// Rotation exists for one reason: a log that only grows eventually fills the
/// device, and a full device is precisely the failure the bounded writer was
/// built to survive. Surviving it is better than causing it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct LogRotation {
    /// 📏 Roll over once the active file reaches this many bytes. `None`
    /// disables size-based rotation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_size_bytes: Option<u64>,

    /// ⏳ Roll over when the active file is this old, in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age_secs: Option<u64>,

    /// 🗃️ How many rotated files to keep. `None` keeps them all, which is
    /// rotation without retention — it slows the disk filling up rather than
    /// preventing it, so it is worth saying out loud.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keep: Option<usize>,

    /// 🗜️ Gzip rotated files. Costs CPU once per rotation and typically wins
    /// an order of magnitude on text logs.
    #[serde(default)]
    pub compress: bool,

    /// 🧱 File mode for the active log file, from `output file { mode … }`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,

    /// 🧱 Directory mode, from `output file { dir_mode … }`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dir_mode: Option<String>,

    /// 🕐 Whether rotated names use local time (`roll_local_time`).
    #[serde(default, skip_serializing_if = "is_false")]
    pub roll_local_time: bool,

    /// ⏲️ Fixed rotation interval (`roll_interval`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roll_interval_secs: Option<u64>,

    /// 🕰️ Wall-clock rotation times (`roll_at`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roll_at: Option<String>,

    /// ⏱️ Minute-of-hour rotation times (`roll_minutes`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roll_minutes: Option<String>,

    /// 🗜️ Compression module from `roll_compression`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roll_compression: Option<String>,
}

fn is_false(value: &bool) -> bool {
    !*value
}

impl LogRotation {
    /// Whether any rotation trigger is configured at all.
    /// 🔄 Whether anything can ever trigger a roll.
    ///
    /// Every trigger has to be listed here, not only the size and age ones.
    /// While only those two counted, `roll_interval 12h` on its own left
    /// rotation switched off entirely — the option was inert twice over, once
    /// because nothing read it and once because nothing armed it.
    pub fn is_enabled(&self) -> bool {
        self.max_size_bytes.is_some()
            || self.max_age_secs.is_some()
            || self.roll_interval_secs.is_some()
            || self.roll_at.is_some()
            || self.roll_minutes.is_some()
    }
}

/// Log output destination
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogOutput {
    File(String),
    Stdout,
    Stderr,
}

/// Log format
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = PingclairConfig::default();
        assert!(!config.debug);
        assert!(config.servers.is_empty());
    }

    #[test]
    fn test_json_deserialize() {
        let json = r#"{
            "debug": true,
            "servers": []
        }"#;
        let config: PingclairConfig = serde_json::from_str(json).unwrap();
        assert!(config.debug);
    }

    /// 🔐 `local_certs` stays absent in legacy documents and survives a
    /// round trip when set, so JSON configuration can carry it without
    /// re-defaulting old files.
    #[test]
    fn test_local_certs_round_trip_and_legacy_default() {
        let legacy: PingclairConfig = serde_json::from_str(r#"{"global":{}}"#).unwrap();
        assert!(!legacy.global.local_certs);

        let config: PingclairConfig =
            serde_json::from_str(r#"{"global":{"local_certs":true}}"#).unwrap();
        assert!(config.global.local_certs);
        let rendered = serde_json::to_string(&config).unwrap();
        assert!(rendered.contains("\"local_certs\":true"), "{rendered}");
    }

    /// 🧩 Legacy `hashed: true` credentials load as bcrypt, the current
    /// `algorithm` shape round-trips, and the old plaintext spelling is
    /// refused rather than revived.
    #[test]
    fn basic_auth_credential_serde_keeps_legacy_documents_working() {
        let legacy: BasicAuthCredential =
            serde_json::from_str(r#"{"username":"alice","password":"$2y$04$x","hashed":true}"#)
                .unwrap();
        assert_eq!(legacy.algorithm, BasicAuthAlgorithm::Bcrypt);

        let current: BasicAuthCredential = serde_json::from_str(
            r#"{"username":"alice","password":"$argon2id$v=19$m=47104,t=1,p=1$a$b","algorithm":"argon2id"}"#,
        )
        .unwrap();
        assert_eq!(current.algorithm, BasicAuthAlgorithm::Argon2id);
        let rendered = serde_json::to_string(&current).unwrap();
        assert!(
            rendered.contains("\"algorithm\":\"argon2id\""),
            "{rendered}"
        );

        let plaintext = serde_json::from_str::<BasicAuthCredential>(
            r#"{"username":"alice","password":"secret","hashed":false}"#,
        );
        assert!(
            plaintext.is_err(),
            "legacy plaintext must be refused, got {plaintext:?}"
        );
    }

    /// 🚨 A status-selective error route matches its exact codes, its `Nxx`
    /// ranges, and — with no codes at all — every status.
    #[test]
    fn error_route_matches_exact_codes_ranges_and_everything() {
        let route = ErrorRouteConfig {
            codes: vec![404, 410],
            hundreds: vec![4],
            handlers: Vec::new(),
        };
        assert!(route.matches(404) && route.matches(410) && route.matches(499));
        assert!(!route.matches(500) && !route.matches(301));

        let catch_all = ErrorRouteConfig {
            codes: Vec::new(),
            hundreds: Vec::new(),
            handlers: Vec::new(),
        };
        assert!(catch_all.matches(404) && catch_all.matches(503));
    }

    #[test]
    fn test_server_config() {
        let config = ServerConfig {
            name: Some("example.com".to_string()),
            names: vec!["example.com".to_string()],
            bind: None,
            listen: vec!["127.0.0.1:8080".to_string()],
            proxy_protocol_listen: Vec::new(),
            plaintext_listen: Vec::new(),
            tls: None,
            routes: vec![],
            log: None,
            log_channels: Vec::new(),
            named_logs: Vec::new(),
            client_max_body_size: 1024 * 1024,
            limits: ResourceLimitsConfig::default(),
            security: Default::default(),
            gzip_types: default_gzip_types(),
            encodings: default_encodings(),
            error_pages: Default::default(),
            error_routes: Vec::new(),
            vars_routes: Vec::new(),
        };
        assert_eq!(config.name, Some("example.com".to_string()));
    }

    #[test]
    fn test_legacy_server_config_receives_default_gzip_types() {
        let config: ServerConfig = serde_json::from_str(r#"{"name":"example.com"}"#).unwrap();
        assert_eq!(config.gzip_types, default_gzip_types());
        assert!(config.gzip_types.contains(&"text/*".to_string()));
        assert_eq!(config.limits, ResourceLimitsConfig::default());
    }

    /// 🗜️ A `0.1.7` JSON config predates the `encodings` field entirely. It
    /// must keep compressing exactly as it did — gzip — rather than silently
    /// losing compression on upgrade.
    #[test]
    fn test_legacy_server_config_keeps_gzip_compression() {
        let config: ServerConfig = serde_json::from_str(r#"{"name":"example.com"}"#).unwrap();
        assert_eq!(config.encodings, vec![Encoding::Gzip]);
    }

    /// An explicitly empty list is `encode off`, and must survive a
    /// round-trip as "no compression" rather than being re-defaulted.
    #[test]
    fn test_empty_encodings_round_trips_as_compression_off() {
        let config: ServerConfig =
            serde_json::from_str(r#"{"name":"example.com","encodings":[]}"#).unwrap();
        assert!(config.encodings.is_empty());

        let round_tripped: ServerConfig =
            serde_json::from_str(&serde_json::to_string(&config).unwrap()).unwrap();
        assert!(round_tripped.encodings.is_empty());
    }

    #[test]
    fn test_encodings_serialize_as_wire_tokens() {
        let json = serde_json::to_string(&vec![Encoding::Zstd, Encoding::Gzip]).unwrap();
        assert_eq!(json, r#"["zstd","gzip"]"#);
    }

    /// `ServerConfig::default()` must agree with deserializing `{}` — a
    /// derived `Default` silently disagrees with the `#[serde(default = ...)]`
    /// attributes and hands out an unlimited body limit and no compression.
    #[test]
    fn test_default_matches_deserializing_an_empty_object() {
        let defaulted = ServerConfig::default();
        let deserialized: ServerConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(
            defaulted.client_max_body_size,
            deserialized.client_max_body_size
        );
        assert_eq!(defaulted.client_max_body_size, 1024 * 1024);
        assert_eq!(defaulted.encodings, deserialized.encodings);
        assert_eq!(defaulted.gzip_types, deserialized.gzip_types);
    }

    #[test]
    fn test_reverse_proxy_config() {
        let config = ReverseProxyConfig {
            upstreams: vec!["http://localhost:3000".to_string()],
            flush_interval: Some(-1),
            ..Default::default()
        };
        assert_eq!(config.flush_interval, Some(-1));
    }

    #[test]
    fn legacy_reverse_proxy_json_keeps_timeout_behavior() {
        let config: ReverseProxyConfig =
            serde_json::from_str(r#"{"upstreams":["127.0.0.1:9000"],"read_timeout":250}"#).unwrap();
        assert_eq!(config.read_timeout, Some(250));
        assert_eq!(config.connect_timeout, None);
        assert_eq!(config.first_byte_timeout, None);
        assert_eq!(config.between_reads_timeout, None);
        assert_eq!(*config.retry, RetryConfig::default());
        assert_eq!(config.retry.max_attempts, 16);
        assert!(config.retry.status_codes.is_empty());
        assert_eq!(*config.overload, OverloadConfig::default());
        assert_eq!(*config.circuit_breaker, CircuitBreakerConfig::default());
    }

    #[test]
    fn fastcgi_transport_round_trips_and_legacy_proxies_load_without_it() {
        let fastcgi = FastCgiTransportConfig {
            root: Some("/srv/www".to_string()),
            split_path: vec![".php".to_string()],
            env: BTreeMap::from([("FOO".to_string(), "bar".to_string())]),
            resolve_root_symlink: true,
            dial_timeout_ms: Some(3_000),
            read_timeout_ms: Some(10_000),
            write_timeout_ms: Some(20_000),
            capture_stderr: true,
        };
        let json = serde_json::to_string(&fastcgi).unwrap();
        let back: FastCgiTransportConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, fastcgi);

        // 🧭 A proxy document written before FastCGI existed loads unchanged,
        // with the transport absent rather than defaulted to something wrong.
        let legacy: ReverseProxyConfig =
            serde_json::from_str(r#"{"upstreams":["127.0.0.1:9000"]}"#).unwrap();
        assert!(legacy.fastcgi.is_none());
    }

    #[test]
    fn test_global_http3_defaults_to_true() {
        assert!(GlobalConfig::default().http3);
        assert!(GlobalConfig::default().trusted_proxies.is_empty());

        // Configs written before the switch existed must keep H3 enabled.
        let legacy: GlobalConfig = serde_json::from_str(r#"{"email":null}"#).unwrap();
        assert!(legacy.http3);

        let disabled: GlobalConfig = serde_json::from_str(r#"{"http3":false}"#).unwrap();
        assert!(!disabled.http3);
    }

    // ---- Matcher serialization ----

    fn round_trip(matcher: &Matcher) -> Matcher {
        let json = serde_json::to_string(matcher).expect("serialize");
        serde_json::from_str(&json).unwrap_or_else(|error| panic!("{json}: {error}"))
    }

    fn path(pattern: &str) -> Matcher {
        Matcher::Path {
            patterns: vec![pattern.to_string()],
        }
    }

    #[test]
    fn every_matcher_survives_a_json_round_trip() {
        let condition = MatcherCondition::Equals("v".into());
        for matcher in [
            path("/api/*"),
            Matcher::Header {
                name: "X-Test".into(),
                condition: condition.clone(),
            },
            Matcher::Method {
                methods: vec!["GET".into()],
            },
            Matcher::Query {
                name: "q".into(),
                condition: condition.clone(),
            },
            Matcher::Host(vec!["example.com".into()]),
            Matcher::RemoteIp(vec!["10.0.0.1".into()]),
            Matcher::Protocol(vec!["https".into()]),
            Matcher::And(Box::new(path("/a")), Box::new(path("/b"))),
            Matcher::Or(Box::new(path("/a")), Box::new(path("/b"))),
            Matcher::Not(Box::new(path("/admin/*"))),
            Matcher::File {
                try_files: vec!["{path}".into(), "index.php".into()],
                root: Some("/srv/www".into()),
                try_policy: Some("first_exist_fallback".into()),
                split_path: vec![".php".into()],
            },
        ] {
            assert_eq!(round_trip(&matcher), matcher, "{matcher:?}");
        }
    }

    /// 🧩 A pipeline element without a matcher keeps the exact JSON shape it
    /// has always had, so `0.1.7` documents still load unchanged.
    #[test]
    fn legacy_pipeline_elements_without_matcher_still_load() {
        let json = r#"{
            "type": "pipeline",
            "handlers": [
                {"type": "respond", "status": 200, "body": "ok", "headers": {}}
            ]
        }"#;
        let config: HandlerConfig = serde_json::from_str(json).expect("legacy pipeline loads");
        let HandlerConfig::Pipeline { handlers } = config else {
            panic!("expected a pipeline");
        };
        assert_eq!(handlers.len(), 1);
        assert!(handlers[0].matcher.is_none());
        assert!(matches!(handlers[0].handler, HandlerConfig::Respond { .. }));

        let serialized = serde_json::to_string(&HandlerConfig::Pipeline { handlers }).unwrap();
        assert!(
            !serialized.contains("\"matcher\""),
            "an unconditional element must not gain a matcher key: {serialized}"
        );
    }

    /// 🎯 A matcher-guarded element loads and round-trips with the matcher
    /// externally tagged alongside the handler's own `type` tag.
    #[test]
    fn matcher_guarded_pipeline_elements_round_trip() {
        let json = r#"{
            "type": "pipeline",
            "handlers": [
                {
                    "matcher": {"path": {"patterns": ["/admin/*"]}},
                    "type": "respond",
                    "status": 200,
                    "body": "x",
                    "headers": {}
                }
            ]
        }"#;
        let config: HandlerConfig = serde_json::from_str(json).expect("guarded element loads");
        let HandlerConfig::Pipeline { handlers } = config else {
            panic!("expected a pipeline");
        };
        assert_eq!(
            handlers[0].matcher,
            Some(path("/admin/*")),
            "the matcher must stay on the element"
        );

        let serialized = serde_json::to_string(&HandlerConfig::Pipeline { handlers }).unwrap();
        let again: HandlerConfig = serde_json::from_str(&serialized).expect("round trip");
        let HandlerConfig::Pipeline { handlers } = again else {
            panic!("expected a pipeline after round trip");
        };
        assert_eq!(handlers[0].matcher, Some(path("/admin/*")));
    }

    #[test]
    fn a_negation_is_not_lost_in_the_round_trip() {
        // The specific failure that motivated the tagged representation: an
        // untagged `Not` serialized as its own inner matcher, so `not path
        // /admin/*` came back as `path /admin/*` — the exact inversion of the
        // decision the operator wrote down.
        let matcher = Matcher::Not(Box::new(path("/admin/*")));
        let json = serde_json::to_string(&matcher).unwrap();

        assert_eq!(json, r#"{"not":{"path":{"patterns":["/admin/*"]}}}"#);
        assert!(
            matches!(round_trip(&matcher), Matcher::Not(_)),
            "the negation must still be there"
        );
    }

    #[test]
    fn matchers_that_share_a_payload_shape_stay_distinct() {
        // Each pair was indistinguishable under the untagged representation:
        // the first of the two always won on the way back in.
        let condition = MatcherCondition::Exists;
        let query = Matcher::Query {
            name: "q".into(),
            condition: condition.clone(),
        };
        let header = Matcher::Header {
            name: "q".into(),
            condition,
        };
        assert_eq!(round_trip(&query), query);
        assert_eq!(round_trip(&header), header);
        assert_ne!(round_trip(&query), header);

        let or = Matcher::Or(Box::new(path("/a")), Box::new(path("/b")));
        let and = Matcher::And(Box::new(path("/a")), Box::new(path("/b")));
        assert!(matches!(round_trip(&or), Matcher::Or(..)));
        assert!(matches!(round_trip(&and), Matcher::And(..)));

        let addresses = vec!["10.0.0.1".to_string()];
        assert!(matches!(
            round_trip(&Matcher::RemoteIp(addresses.clone())),
            Matcher::RemoteIp(_)
        ));
        assert!(matches!(
            round_trip(&Matcher::Protocol(addresses.clone())),
            Matcher::Protocol(_)
        ));
        assert!(matches!(
            round_trip(&Matcher::Host(addresses)),
            Matcher::Host(_)
        ));
    }

    #[test]
    fn deeply_nested_matchers_round_trip() {
        let matcher = Matcher::Not(Box::new(Matcher::And(
            Box::new(Matcher::Or(
                Box::new(path("/a")),
                Box::new(Matcher::Not(Box::new(Matcher::Host(vec![
                    "example.com".into(),
                ])))),
            )),
            Box::new(Matcher::Not(Box::new(Matcher::Method {
                methods: vec!["POST".into()],
            }))),
        )));

        assert_eq!(round_trip(&matcher), matcher);
    }

    #[test]
    fn legacy_untagged_configs_still_load() {
        // Every shape a `0.1.7` config could actually hold. These must keep
        // loading unchanged, tag or no tag.
        let cases: [(&str, Matcher); 5] = [
            (r#"{"patterns":["/api/*"]}"#, path("/api/*")),
            (
                r#"{"methods":["GET","POST"]}"#,
                Matcher::Method {
                    methods: vec!["GET".into(), "POST".into()],
                },
            ),
            (
                r#"{"name":"X-Test","condition":{"equals":"v"}}"#,
                Matcher::Header {
                    name: "X-Test".into(),
                    condition: MatcherCondition::Equals("v".into()),
                },
            ),
            (
                r#"["example.com","www.example.com"]"#,
                Matcher::Host(vec!["example.com".into(), "www.example.com".into()]),
            ),
            (
                r#"[{"patterns":["/a"]},{"patterns":["/b"]}]"#,
                Matcher::And(Box::new(path("/a")), Box::new(path("/b"))),
            ),
        ];

        for (json, expected) in cases {
            let parsed: Matcher =
                serde_json::from_str(json).unwrap_or_else(|e| panic!("{json}: {e}"));
            assert_eq!(parsed, expected, "{json}");
        }
    }

    #[test]
    fn a_legacy_shape_keeps_the_reading_it_always_had() {
        // `{name, condition}` was written by both `Header` and `Query`, and
        // `0.1.7` read it as a `Header`. Re-reading it as a `Query` now would
        // silently change how an existing config routes; the tagged form is
        // how an author says which one they meant.
        let legacy: Matcher = serde_json::from_str(r#"{"name":"q","condition":"exists"}"#).unwrap();
        assert!(matches!(legacy, Matcher::Header { .. }));

        let tagged: Matcher =
            serde_json::from_str(r#"{"query":{"name":"q","condition":"exists"}}"#).unwrap();
        assert!(matches!(tagged, Matcher::Query { .. }));
    }

    #[test]
    fn an_unrecognised_matcher_does_not_blow_the_stack() {
        // Regression, and the reason this is more than a correctness fix.
        //
        // `Not(Box<Matcher>)` was a *newtype* variant of an untagged enum, so
        // testing it meant deserializing the whole payload as a `Matcher`
        // again — with no input consumed. Any value that matched no other
        // variant therefore recursed forever, and since serde's untagged
        // replay does not go back through serde_json's parser, serde_json's
        // own recursion limit never saw it. A single unrecognised matcher
        // posted to the Admin API aborted the process with a stack overflow.
        //
        // The tagged form terminates because the tag selects one variant, and
        // the legacy fallback only recurses through a sequence, which always
        // consumes input.
        assert!(serde_json::from_str::<Matcher>(r#"{"nonsense":["/x"]}"#).is_err());

        // Deep nesting must still be refused rather than ridden all the way
        // down: serde_json caps parse depth, and every recursion here costs
        // one array level.
        let deep = format!("{}{}", "[".repeat(400), "]".repeat(400));
        assert!(serde_json::from_str::<Matcher>(&deep).is_err());
    }

    #[test]
    fn a_matcher_that_is_neither_form_is_rejected() {
        // Fail closed: an unreadable matcher must not degrade into one that
        // matches everything.
        for json in [
            r#"{"nope":{"patterns":["/a"]}}"#,
            r#"{"path":{"wrong_field":[]}}"#,
            r#""just-a-string""#,
            r#"42"#,
        ] {
            assert!(
                serde_json::from_str::<Matcher>(json).is_err(),
                "{json} should not parse"
            );
        }
    }

    #[test]
    fn matchers_round_trip_through_toml_too() {
        // The loader accepts TOML as well as JSON, and external tagging has
        // to survive both.
        let config = PingclairConfig {
            servers: vec![ServerConfig {
                name: Some("example.com".into()),
                routes: vec![RouteConfig {
                    path: "/*".into(),
                    handler: HandlerConfig::Respond {
                        status: 200,
                        body: None,
                        headers: BTreeMap::new(),
                    },
                    methods: None,
                    matcher: Some(Matcher::Not(Box::new(path("/admin/*")))),
                }],
                ..Default::default()
            }],
            ..Default::default()
        };

        let toml_text = toml::to_string(&config).expect("serialize TOML");
        let parsed: PingclairConfig = toml::from_str(&toml_text).expect("parse TOML");

        assert_eq!(
            parsed.servers[0].routes[0].matcher.as_ref().unwrap(),
            &Matcher::Not(Box::new(path("/admin/*"))),
            "\n{toml_text}"
        );
    }

    // MARK: - Strict schemas on the trust surface

    /// 🚫 A misspelled `mode` inside `client_auth` must fail the whole load.
    ///
    /// This is the shape that made the rule necessary. Serde used to drop the
    /// unrecognised key, `mode` fell back to its default, and the default is
    /// [`ClientAuthMode::Require`] — demand a certificate, then never ask who
    /// signed it. The operator wrote `require_and_verify`, the config loaded
    /// without a complaint, and the site accepted any certificate a client
    /// cared to present. The document below is that config with one letter
    /// added.
    #[test]
    fn a_misspelled_client_auth_mode_fails_the_load() {
        let document = r#"{
            "servers": [{
                "name": "mtls.example.com",
                "tls": {
                    "auto": true,
                    "client_auth": {
                        "modde": "require_and_verify",
                        "trust_pool": {"provider": "file", "pem_files": ["/etc/ca.pem"]}
                    }
                }
            }]
        }"#;

        let error = serde_json::from_str::<PingclairConfig>(document)
            .expect_err("a misspelled client_auth field must not load");
        let message = error.to_string();
        assert!(
            message.contains("unknown field `modde`"),
            "the error must name the field the operator mistyped; got: {message}"
        );

        // 🧭 The same document with the spelling corrected still loads, so the
        // rule refuses typos rather than the feature.
        let corrected = document.replace("modde", "mode");
        let config: PingclairConfig =
            serde_json::from_str(&corrected).expect("the corrected document must load");
        let client_auth = config.servers[0]
            .tls
            .as_ref()
            .and_then(|tls| tls.client_auth.as_ref())
            .expect("client_auth survives the round trip");
        assert_eq!(client_auth.mode, ClientAuthMode::RequireAndVerify);
    }

    /// 🚫 Every type that names key material, names a trust anchor, or decides
    /// how hard an identity is checked refuses a field it does not know.
    ///
    /// Each probe below is a plausible typo — a singular where the field is
    /// plural, a plural where it is singular — chosen so that swallowing it
    /// would leave something weaker in force: an empty trust pool, the system
    /// store instead of a private CA, an admin API with no key.
    #[test]
    fn the_trust_surface_refuses_unknown_fields() {
        fn refuses<T: serde::de::DeserializeOwned>(label: &str, probe: &str, field: &str) {
            let Err(error) = serde_json::from_str::<T>(probe) else {
                panic!("{label} accepted an unknown field: {probe}");
            };
            let message = error.to_string();
            assert!(
                message.contains(&format!("unknown field `{field}`")),
                "{label} must name the unknown field; got: {message}"
            );
        }

        refuses::<TlsConfig>("TlsConfig", r#"{"clientauth": {}}"#, "clientauth");
        refuses::<ClientAuthConfig>(
            "ClientAuthConfig",
            r#"{"modde": "require_and_verify"}"#,
            "modde",
        );
        refuses::<TrustPool>(
            "TrustPool",
            r#"{"provider": "file", "pem_file": ["/etc/ca.pem"]}"#,
            "pem_file",
        );
        refuses::<UpstreamTlsConfig>(
            "UpstreamTlsConfig",
            r#"{"trusted_ca_cert": ["-----BEGIN CERTIFICATE-----"]}"#,
            "trusted_ca_cert",
        );
        refuses::<AdminConfig>(
            "AdminConfig",
            r#"{"listen": "localhost:2019", "api_keys": "s3cret"}"#,
            "api_keys",
        );
        refuses::<PkiAuthority>("PkiAuthority", r#"{"id": "local", "roots": {}}"#, "roots");
        refuses::<PkiKeyPair>(
            "PkiKeyPair",
            r#"{"certificate": "/root.pem"}"#,
            "certificate",
        );
        refuses::<AcmeServerConfig>(
            "AcmeServerConfig",
            r#"{"allowed": {"domains": ["internal.test"]}}"#,
            "allowed",
        );
        refuses::<AcmeServerPolicy>(
            "AcmeServerPolicy",
            r#"{"domain": ["internal.test"]}"#,
            "domain",
        );
        refuses::<DnsProviderConfig>(
            "DnsProviderConfig",
            r#"{"name": "cloudflare", "argument": ["{env.CF_API_TOKEN}"]}"#,
            "argument",
        );
        refuses::<DnsChallengeConfig>(
            "DnsChallengeConfig",
            r#"{"resolver": ["1.1.1.1"]}"#,
            "resolver",
        );
    }

    /// 🔁 The strict types still read back exactly what they write.
    ///
    /// Rejecting unknown fields is only safe if none of our own output counts
    /// as unknown — an admin `GET /config` followed by a `POST /load` of the
    /// same bytes has to survive, and so does an autosaved config on restart.
    #[test]
    fn the_trust_surface_round_trips_through_its_own_output() {
        fn round_trips<T>(label: &str, value: T)
        where
            T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
        {
            let rendered = serde_json::to_string(&value).expect("serialize");
            let parsed: T = serde_json::from_str(&rendered)
                .unwrap_or_else(|error| panic!("{label} cannot read its own output: {error}"));
            assert_eq!(parsed, value, "{label} changed across a round trip");
        }

        round_trips(
            "ClientAuthConfig",
            ClientAuthConfig {
                mode: ClientAuthMode::RequireAndVerify,
                trust_pool: Some(TrustPool::Combined {
                    sources: vec![
                        TrustPool::System,
                        TrustPool::File {
                            pem_files: vec!["/etc/ca.pem".into()],
                        },
                        TrustPool::PkiRoot {
                            authority: "local".into(),
                        },
                    ],
                }),
                trusted_leaf_cert_folders: vec!["/etc/pinned".into()],
                ..Default::default()
            },
        );
        round_trips(
            "UpstreamTlsConfig",
            UpstreamTlsConfig {
                enable: true,
                server_name: Some("origin.internal".into()),
                trusted_ca_certs: vec!["/etc/origin-ca.pem".into()],
                client_cert: Some("/etc/client.pem".into()),
                client_key: Some("/etc/client.key".into()),
                insecure_skip_verify: false,
            },
        );
        round_trips(
            "PkiAuthority",
            PkiAuthority {
                id: "local".into(),
                name: Some("Pingclair Local".into()),
                root_cn: Some("Pingclair Local Root".into()),
                intermediate_cn: Some("Pingclair Local Intermediate".into()),
                root: Some(PkiKeyPair {
                    cert: Some("/root.pem".into()),
                    key: Some("/root.key".into()),
                    format: Some("pem_file".into()),
                }),
                intermediate: None,
            },
        );
        round_trips(
            "AcmeServerConfig",
            AcmeServerConfig {
                ca: Some("local".into()),
                lifetime_secs: Some(86_400),
                sign_with_root: true,
                challenges: Some(vec!["http-01".into()]),
                allow: Some(AcmeServerPolicy {
                    domains: vec!["internal.test".into()],
                    ip_ranges: vec!["10.0.0.0/8".into()],
                }),
                deny: None,
            },
        );
        round_trips(
            "DnsChallengeConfig",
            DnsChallengeConfig {
                provider: Some(DnsProviderConfig {
                    name: "cloudflare".into(),
                    arguments: vec!["{env.CF_API_TOKEN}".into()],
                }),
                resolvers: vec!["1.1.1.1".into()],
                ttl_secs: Some(60),
                propagation_delay_secs: Some(10),
                propagation_timeout_secs: Some(120),
                challenge_override_domain: Some("acme.example.net".into()),
            },
        );
    }
}
