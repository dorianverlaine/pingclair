// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧭 DNS-driven upstream sources (`dynamic a` and `dynamic srv`).
//!
//! Caddy resolves these sources per request and caches the answer. Pingclair
//! keeps the same freshness without ever putting DNS on the request path: a
//! background refresher calls [`DynamicUpstreamSource::resolve_specs`] on the
//! configured interval and republishes the whole peer set at once, exactly
//! like the hostname refresher in `dns.rs`. The request path only ever reads
//! the published pool.
//!
//! 🔁 The resolver owns a current-thread Tokio runtime of its own and blocks
//! on it, so lookups fit the existing `spawn_blocking` refresh loop without
//! dragging async state into `LoadBalancer`. hickory shipped that wrapper
//! itself until 0.25 removed the synchronous resolver; the runtime below is
//! the same arrangement, now written here rather than in the crate. It is
//! never entered from an async context — the refresher is already on a
//! blocking thread — which is the one way `block_on` would panic.

use crate::upstream::UpstreamSpec;
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{
    ConnectionConfig, NameServerConfig, ProtocolConfig, ResolverConfig, ResolverOpts,
};
use pingclair_core::config::{DynamicAddrUpstream, DynamicSrvUpstream, DynamicUpstreamConfig};
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

/// One SRV record: the target hostname and the port the service listens on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrvRecord {
    pub host: String,
    pub port: u16,
}

/// 🧭 Wraps hickory's async resolver behind the two blocking lookups the
/// dynamic sources need, with the configured timeouts and explicit name
/// servers.
pub struct DynamicResolver {
    inner: Arc<TokioResolver>,
    /// ⏱️ The runtime the async lookups are driven on. One current-thread
    /// runtime per resolver, created once at configuration time rather than
    /// per lookup, because building a runtime is a syscall-heavy operation and
    /// the refresher calls this on an interval.
    runtime: Arc<tokio::runtime::Runtime>,
}

/// 🧭 Precompiled address-family filter for dynamic A/AAAA records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpFamily {
    Both,
    V4,
    V6,
}

impl IpFamily {
    /// ⛔ Validates direct JSON with the same closed set as the adapter.
    fn parse(value: Option<&str>) -> io::Result<Self> {
        match value {
            None | Some("ip") => Ok(Self::Both),
            Some("ipv4" | "ip4") => Ok(Self::V4),
            Some("ipv6" | "ip6") => Ok(Self::V6),
            Some(other) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported dynamic address family `{other}`"),
            )),
        }
    }

    /// 📜 Tests whether one resolved address belongs in the published set.
    fn accepts(self, address: IpAddr) -> bool {
        match self {
            Self::Both => true,
            Self::V4 => address.is_ipv4(),
            Self::V6 => address.is_ipv6(),
        }
    }
}

impl DynamicResolver {
    /// 🧭 Builds a resolver from explicit server addresses (or the system
    /// configuration when none were given) and an optional per-lookup timeout.
    pub fn new(resolvers: &[String], timeout: Option<Duration>) -> io::Result<Self> {
        let (config, options) = resolver_settings(resolvers, timeout)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let mut builder = TokioResolver::builder_with_config(config, Default::default());
        *builder.options_mut() = options;
        Ok(Self {
            inner: Arc::new(builder.build().map_err(io::Error::other)?),
            runtime: Arc::new(runtime),
        })
    }

    /// 📜 Resolves every A/AAAA record of `name`, honoring the address-family
    /// filter (`ipv4`/`ipv6`) when one is configured.
    fn lookup_a(&self, name: &str, family: IpFamily) -> io::Result<Vec<IpAddr>> {
        let lookup = self
            .runtime
            .block_on(self.inner.lookup_ip(name.to_string()))
            .map_err(io::Error::other)?;
        Ok(lookup.iter().filter(|ip| family.accepts(*ip)).collect())
    }

    /// 🧾 Resolves every SRV record of `name`; records whose target is `.`
    /// mean "service not available" and are skipped, matching RFC 2782.
    pub fn lookup_srv(&self, name: &str) -> io::Result<Vec<SrvRecord>> {
        let lookup = self
            .runtime
            .block_on(self.inner.srv_lookup(name.to_string()))
            .map_err(io::Error::other)?;
        // 🧾 `Lookup` hands back every answer record rather than only the
        // requested type, so the SRV rows have to be selected explicitly: a
        // CNAME in the answer section would otherwise be read as a peer.
        Ok(lookup
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                hickory_resolver::proto::rr::RData::SRV(srv) => Some(srv),
                _ => None,
            })
            .filter(|srv| !srv.target.is_root())
            .map(|srv| SrvRecord {
                host: srv.target.to_string(),
                port: srv.port,
            })
            .collect())
    }
}

/// 🔌 Describes one plain-UDP name server on an explicit port.
///
/// hickory 0.26 splits what used to be a `SocketAddr` plus a `Protocol` into
/// an address and a list of per-protocol connections, and `ConnectionConfig`
/// defaults its port to the protocol's standard one. The port therefore has to
/// be set afterwards, or an operator pointing the resolver at `127.0.0.1:5353`
/// would silently be asking `127.0.0.1:53`.
///
/// 📌 `trust_negative_responses: true` is not a new opinion — it is what
/// `NameServerConfig::new` set for us on 0.24, where the argument did not
/// exist. Passing `false` here would quietly change what an `NXDOMAIN` means:
/// instead of being believed, it would send the query on to the next
/// configured server. That is a behaviour change, and a dependency bump is not
/// the place to make one.
fn udp_name_server(ip: IpAddr, port: u16) -> NameServerConfig {
    let mut connection = ConnectionConfig::new(ProtocolConfig::Udp);
    connection.port = port;
    NameServerConfig::new(ip, true, vec![connection])
}

/// 🧭 Compiles resolver strings and system defaults before any lookup runs.
fn resolver_settings(
    resolvers: &[String],
    timeout: Option<Duration>,
) -> io::Result<(ResolverConfig, ResolverOpts)> {
    let (config, mut options) = if resolvers.is_empty() {
        hickory_resolver::system_conf::read_system_conf().map_err(io::Error::other)?
    } else {
        let mut config = ResolverConfig::from_parts(None, Vec::new(), Vec::new());
        for address in resolvers {
            let ip: IpAddr = address.parse().map_err(io::Error::other)?;
            config.add_name_server(udp_name_server(ip, 53));
        }
        (config, ResolverOpts::default())
    };
    if let Some(timeout) = timeout {
        options.timeout = timeout;
    }
    Ok((config, options))
}

/// 🧭 One configured dynamic source, resolved to a fresh peer list on demand.
pub trait DynamicUpstreamSource: Send + Sync {
    /// A stable label for logs.
    fn describe(&self) -> String;

    /// Resolves the current peer set as concrete address specs.
    fn resolve_specs(&self) -> io::Result<Vec<UpstreamSpec>>;

    /// ⏱️ Returns this source's configured refresh interval.
    fn refresh_interval(&self) -> Option<Duration>;

    /// 🌤️ Returns how long a failed source may retain its last successful set.
    fn grace_period(&self) -> Option<Duration> {
        None
    }
}

/// 📜 A-record source: every address of one name on one fixed port.
struct ARecordSource {
    resolver: Arc<DynamicResolver>,
    config: DynamicAddrUpstream,
    refresh_interval: Option<Duration>,
    family: IpFamily,
}

impl DynamicUpstreamSource for ARecordSource {
    fn describe(&self) -> String {
        format!("a://{}:{}", self.config.name, self.config.port)
    }

    fn resolve_specs(&self) -> io::Result<Vec<UpstreamSpec>> {
        let addresses = self.resolver.lookup_a(&self.config.name, self.family)?;
        if addresses.is_empty() {
            return Err(io::Error::other("no address records for the dynamic name"));
        }
        Ok(addresses
            .into_iter()
            .filter_map(|ip| UpstreamSpec::parse(&format!("{ip}:{}", self.config.port)))
            .collect())
    }

    fn refresh_interval(&self) -> Option<Duration> {
        self.refresh_interval
    }
}

/// 🧾 SRV source: every target and port of the RFC 2782 records.
struct SrvSource {
    resolver: Arc<DynamicResolver>,
    config: DynamicSrvUpstream,
    refresh_interval: Option<Duration>,
    grace_period: Option<Duration>,
}

impl SrvSource {
    /// Builds the RFC 2782 name from the configured parts.
    fn lookup_name(&self) -> String {
        match (&self.config.service, &self.config.proto) {
            (Some(service), Some(proto)) => {
                format!("_{service}._{proto}.{}", self.config.name)
            }
            _ => self.config.name.clone(),
        }
    }
}

impl DynamicUpstreamSource for SrvSource {
    fn describe(&self) -> String {
        format!("srv://{}", self.lookup_name())
    }

    fn resolve_specs(&self) -> io::Result<Vec<UpstreamSpec>> {
        let records = self.resolver.lookup_srv(&self.lookup_name())?;
        if records.is_empty() {
            return Err(io::Error::other("no SRV records for the dynamic name"));
        }
        Ok(records
            .into_iter()
            .filter_map(|record| UpstreamSpec::parse(&format!("{}:{}", record.host, record.port)))
            .collect())
    }

    fn refresh_interval(&self) -> Option<Duration> {
        self.refresh_interval
    }

    fn grace_period(&self) -> Option<Duration> {
        self.grace_period
    }
}

/// 🏭 Builds the runtime source for one configured dynamic upstream.
pub fn dynamic_source(
    config: &DynamicUpstreamConfig,
) -> io::Result<Box<dyn DynamicUpstreamSource>> {
    match config {
        DynamicUpstreamConfig::A(addr) => {
            validate_refresh_interval(addr.refresh_secs)?;
            reject_fallback_delay(addr.fallback_delay_ms)?;
            let family = IpFamily::parse(addr.versions.as_deref())?;
            Ok(Box::new(ARecordSource {
                resolver: Arc::new(DynamicResolver::new(
                    &addr.resolvers,
                    addr.dial_timeout_ms.map(Duration::from_millis),
                )?),
                config: addr.clone(),
                refresh_interval: addr.refresh_secs.map(Duration::from_secs),
                family,
            }))
        }
        DynamicUpstreamConfig::Srv(srv) => {
            validate_refresh_interval(srv.refresh_secs)?;
            reject_fallback_delay(srv.fallback_delay_ms)?;
            Ok(Box::new(SrvSource {
                resolver: Arc::new(DynamicResolver::new(
                    &srv.resolvers,
                    srv.dial_timeout_ms.map(Duration::from_millis),
                )?),
                config: srv.clone(),
                refresh_interval: srv.refresh_secs.map(Duration::from_secs),
                grace_period: srv.grace_period_ms.map(Duration::from_millis),
            }))
        }
    }
}

/// ⛔ Rejects a zero interval from direct JSON before it can create a busy loop.
fn validate_refresh_interval(refresh_secs: Option<u64>) -> io::Result<()> {
    if refresh_secs == Some(0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "dynamic refresh interval must be at least one second",
        ));
    }
    Ok(())
}

/// 🚫 Refuses a resolver option Hickory cannot implement with exact semantics.
fn reject_fallback_delay(fallback_delay_ms: Option<i64>) -> io::Result<()> {
    if fallback_delay_ms.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "dynamic dial_fallback_delay is unsupported by the Hickory resolver transport",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn srv_lookup_name_follows_rfc2782_parts() {
        let source = SrvSource {
            resolver: Arc::new(DynamicResolver::new(&[], None).unwrap()),
            config: DynamicSrvUpstream {
                name: "example.com".into(),
                service: Some("api".into()),
                proto: Some("tcp".into()),
                refresh_secs: None,
                resolvers: vec![],
                dial_timeout_ms: None,
                fallback_delay_ms: None,
                grace_period_ms: None,
            },
            refresh_interval: None,
            grace_period: None,
        };
        assert_eq!(source.lookup_name(), "_api._tcp.example.com");
        assert_eq!(source.describe(), "srv://_api._tcp.example.com");
    }

    #[test]
    fn a_record_source_describes_its_name_and_port() {
        let source = ARecordSource {
            resolver: Arc::new(DynamicResolver::new(&[], None).unwrap()),
            config: DynamicAddrUpstream {
                name: "example.test".into(),
                port: 9000,
                refresh_secs: None,
                resolvers: vec![],
                dial_timeout_ms: None,
                fallback_delay_ms: None,
                versions: Some("ipv6".into()),
            },
            refresh_interval: None,
            family: IpFamily::V6,
        };
        assert_eq!(source.describe(), "a://example.test:9000");
    }

    #[test]
    fn explicit_resolvers_must_be_ip_literals() {
        assert!(
            DynamicResolver::new(&["not-an-ip".into()], None).is_err(),
            "a hostname is not a resolver address"
        );
    }

    #[test]
    fn empty_resolver_list_preserves_system_dns_configuration() {
        let (expected, expected_options) =
            hickory_resolver::system_conf::read_system_conf().unwrap();
        let timeout = Duration::from_millis(750);
        let (actual, actual_options) = resolver_settings(&[], Some(timeout)).unwrap();

        // 🧭 Compared by name-server address rather than by whole config:
        // `ResolverConfig` dropped `PartialEq` in hickory 0.26, and the
        // addresses are the property this test is actually about. An empty
        // `resolvers` list must mean "whatever the host is configured to use",
        // never the crate's own public-resolver default — the defect this was
        // written for shipped Google's servers to operators who had named none.
        let addresses = |config: &ResolverConfig| -> Vec<IpAddr> {
            config
                .name_servers()
                .iter()
                .map(|server| server.ip)
                .collect()
        };
        assert_eq!(addresses(&actual), addresses(&expected));
        assert!(
            !addresses(&actual).is_empty(),
            "the system configuration named no resolver, so this proves nothing"
        );
        assert_eq!(actual_options.timeout, timeout);
        assert_eq!(actual_options.attempts, expected_options.attempts);
        assert_eq!(actual_options.ndots, expected_options.ndots);
    }

    #[test]
    fn direct_json_cannot_configure_a_zero_refresh_interval() {
        let config = DynamicUpstreamConfig::A(DynamicAddrUpstream {
            name: "example.test".into(),
            port: 80,
            refresh_secs: Some(0),
            resolvers: vec![],
            dial_timeout_ms: None,
            fallback_delay_ms: None,
            versions: None,
        });
        assert!(dynamic_source(&config).is_err());
    }

    #[test]
    fn direct_json_cannot_bypass_address_family_validation() {
        let config = DynamicUpstreamConfig::A(DynamicAddrUpstream {
            name: "example.test".into(),
            port: 80,
            refresh_secs: None,
            resolvers: vec![],
            dial_timeout_ms: None,
            fallback_delay_ms: None,
            versions: Some("tcp".into()),
        });
        assert!(dynamic_source(&config).is_err());
    }

    #[test]
    fn direct_runtime_construction_rejects_fallback_delay_instead_of_ignoring_it() {
        let config = DynamicUpstreamConfig::Srv(DynamicSrvUpstream {
            name: "_api._tcp.example.test".into(),
            service: None,
            proto: None,
            refresh_secs: None,
            resolvers: vec!["127.0.0.1".into()],
            dial_timeout_ms: None,
            fallback_delay_ms: Some(300),
            grace_period_ms: None,
        });
        assert!(dynamic_source(&config).is_err());
    }
}
