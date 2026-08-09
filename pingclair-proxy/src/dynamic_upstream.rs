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
//! The synchronous hickory resolver owns its own current-thread Tokio runtime,
//! so lookups fit the existing `spawn_blocking` refresh loop without dragging
//! async state into `LoadBalancer`.

use crate::upstream::UpstreamSpec;
use hickory_resolver::Resolver;
use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use pingclair_core::config::{DynamicAddrUpstream, DynamicSrvUpstream, DynamicUpstreamConfig};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

/// One SRV record: the target hostname and the port the service listens on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrvRecord {
    pub host: String,
    pub port: u16,
}

/// 🧭 Wraps hickory's synchronous resolver behind the two lookups the dynamic
/// sources need, with the configured timeouts and explicit name servers.
pub struct DynamicResolver {
    inner: Arc<Resolver>,
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
        Ok(Self {
            inner: Arc::new(Resolver::new(config, options)?),
        })
    }

    /// 📜 Resolves every A/AAAA record of `name`, honoring the address-family
    /// filter (`ipv4`/`ipv6`) when one is configured.
    fn lookup_a(&self, name: &str, family: IpFamily) -> io::Result<Vec<IpAddr>> {
        let lookup = self.inner.lookup_ip(name).map_err(io::Error::other)?;
        Ok(lookup.iter().filter(|ip| family.accepts(*ip)).collect())
    }

    /// 🧾 Resolves every SRV record of `name`; records whose target is `.`
    /// mean "service not available" and are skipped, matching RFC 2782.
    pub fn lookup_srv(&self, name: &str) -> io::Result<Vec<SrvRecord>> {
        let lookup = self.inner.srv_lookup(name).map_err(io::Error::other)?;
        Ok(lookup
            .iter()
            .filter(|record| !record.target().is_root())
            .map(|record| SrvRecord {
                host: record.target().to_string(),
                port: record.port(),
            })
            .collect())
    }
}

/// 🧭 Compiles resolver strings and system defaults before any lookup runs.
fn resolver_settings(
    resolvers: &[String],
    timeout: Option<Duration>,
) -> io::Result<(ResolverConfig, ResolverOpts)> {
    let (config, mut options) = if resolvers.is_empty() {
        hickory_resolver::system_conf::read_system_conf().map_err(io::Error::other)?
    } else {
        let mut config = ResolverConfig::new();
        for address in resolvers {
            let ip: IpAddr = address.parse().map_err(io::Error::other)?;
            config.add_name_server(NameServerConfig::new(
                SocketAddr::new(ip, 53),
                Protocol::Udp,
            ));
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

        assert_eq!(actual, expected);
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
