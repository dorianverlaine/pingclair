// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🛡️ Expands wildcard listeners into known local destinations before DNS publication.

use std::io;
use std::net::{IpAddr, SocketAddr};

pub(super) fn known(listeners: &[SocketAddr]) -> io::Result<Vec<SocketAddr>> {
    if !listeners
        .iter()
        .any(|address| address.ip().is_unspecified())
    {
        return Ok(listeners.to_vec());
    }
    Ok(expand(listeners, &local_ips()?))
}

fn expand(listeners: &[SocketAddr], local: &[IpAddr]) -> Vec<SocketAddr> {
    let mut addresses = listeners.to_vec();
    for listener in listeners
        .iter()
        .filter(|address| address.ip().is_unspecified())
    {
        for ip in local.iter().map(|ip| ip.to_canonical()) {
            // 🌐 A wildcard IPv6 socket may accept mapped IPv4 on a dual-stack host.
            if listener.is_ipv6() || ip.is_ipv4() {
                addresses.push(SocketAddr::new(ip, listener.port()));
            }
        }
    }
    addresses.sort_unstable();
    addresses.dedup();
    addresses
}

#[cfg(unix)]
fn local_ips() -> io::Result<Vec<IpAddr>> {
    Ok(nix::ifaddrs::getifaddrs()
        .map_err(io::Error::other)?
        .filter_map(|interface| {
            let address = interface.address?;
            address
                .as_sockaddr_in()
                .map(|address| IpAddr::V4(address.ip()))
                .or_else(|| {
                    address
                        .as_sockaddr_in6()
                        .map(|address| IpAddr::V6(address.ip()))
                })
        })
        .collect())
}

#[cfg(not(unix))]
fn local_ips() -> io::Result<Vec<IpAddr>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "local destination enumeration is unavailable",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_policy_blocks_local_addresses_without_blocking_external_hosts() {
        let listeners = ["0.0.0.0:443", "[::]:8443", "127.0.0.1:2019"].map(|s| s.parse().unwrap());
        let local = ["127.0.0.1", "192.0.2.1", "2001:db8::1"].map(|s| s.parse().unwrap());
        let actual = expand(&listeners, &local);
        let mut expected: Vec<SocketAddr> = [
            "0.0.0.0:443",
            "127.0.0.1:443",
            "192.0.2.1:443",
            "[::]:8443",
            "127.0.0.1:8443",
            "192.0.2.1:8443",
            "[2001:db8::1]:8443",
            "127.0.0.1:2019",
        ]
        .map(|s| s.parse().unwrap())
        .to_vec();
        expected.sort_unstable();
        assert_eq!(actual, expected);
    }
}
