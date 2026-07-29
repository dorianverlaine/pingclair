// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧭 Trusted PROXY protocol v1 and v2 TCP ingress.

use ipnet::IpNet;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::io::{Error, ErrorKind, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener as StdTcpListener};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

const V2_SIGNATURE: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";
const MAX_V1_HEADER_BYTES: usize = 108;
const MAX_V2_PAYLOAD_BYTES: usize = 512;
const IDENTITY_TTL: Duration = Duration::from_secs(600);

/// 🪪 Associates one internal tunnel socket with its trusted transport claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyProtocolIdentity {
    /// 👤 Contains the client address asserted by the trusted proxy.
    pub client: SocketAddr,
    /// 🛡️ Contains the physical peer that was authorized before parsing.
    pub transport_peer: SocketAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TunnelKey {
    peer: SocketAddr,
    listener: SocketAddr,
}

#[derive(Debug, Clone, Copy)]
struct RegistryEntry {
    identity: ProxyProtocolIdentity,
    last_seen: Instant,
}

/// 🗺️ Shares transport claims with Pingora after the internal TCP hop.
#[derive(Debug, Default)]
pub struct ProxyProtocolRegistry {
    entries: Mutex<HashMap<TunnelKey, RegistryEntry>>,
}

impl ProxyProtocolRegistry {
    /// 🔗 Registers a tunnel before forwarding its first application byte.
    pub fn register(
        &self,
        internal_peer: SocketAddr,
        internal_listener: SocketAddr,
        identity: ProxyProtocolIdentity,
    ) {
        let now = Instant::now();
        let mut entries = self.entries.lock();
        // 🧹 The ingress register path prunes abandoned tunnel identities after ten minutes.
        entries.retain(|_, entry| now.saturating_duration_since(entry.last_seen) < IDENTITY_TTL);
        entries.insert(
            TunnelKey {
                peer: internal_peer,
                listener: internal_listener,
            },
            RegistryEntry {
                identity,
                last_seen: now,
            },
        );
    }

    /// 🧹 Removes the identity as soon as bidirectional forwarding finishes.
    pub fn unregister(&self, internal_peer: SocketAddr, internal_listener: SocketAddr) {
        self.entries.lock().remove(&TunnelKey {
            peer: internal_peer,
            listener: internal_listener,
        });
    }

    /// 🔎 Resolves the trusted claim observed by one Pingora connection.
    pub fn resolve(
        &self,
        internal_peer: SocketAddr,
        internal_listener: SocketAddr,
    ) -> Option<ProxyProtocolIdentity> {
        let now = Instant::now();
        let mut entries = self.entries.lock();
        let key = TunnelKey {
            peer: internal_peer,
            listener: internal_listener,
        };
        let identity = entries.get_mut(&key).map(|entry| {
            entry.last_seen = now;
            entry.identity
        });
        // 🧹 The request lookup path also removes stale identities after abnormal tunnel exits.
        entries.retain(|_, entry| now.saturating_duration_since(entry.last_seen) < IDENTITY_TTL);
        identity
    }
}

/// 🛡️ Parses trusted networks once for the external accept loop.
pub fn parse_networks(rules: &[String]) -> Result<Vec<IpNet>> {
    rules
        .iter()
        .map(|rule| {
            rule.parse::<IpNet>()
                .or_else(|_| rule.parse::<IpAddr>().map(IpNet::from))
                .map_err(|error| {
                    Error::new(
                        ErrorKind::InvalidInput,
                        format!("invalid proxy network `{rule}`: {error}"),
                    )
                })
        })
        .collect()
}

/// 🚪 Accepts PROXY-prefixed TCP streams and forwards them to a private Pingora listener.
///
/// `max_connections` must carry the same listener limit the Pingora app
/// enforces. With PROXY protocol enabled the Pingora app listens on the private
/// loopback address, so its own admission control bounds the *internal* hop
/// only. Without the same bound here, `limits { max_connections }` would stop
/// describing how many downstream connections the process actually holds — the
/// external socket and its task outlive the internal rejection. The two bounds
/// are one-to-one, so applying the same number twice still yields that number.
pub async fn run_ingress(
    listener: StdTcpListener,
    internal_listener: SocketAddr,
    registry: Arc<ProxyProtocolRegistry>,
    trusted_proxies: Vec<IpNet>,
    blocked_clients: Vec<IpNet>,
    max_connections: Option<usize>,
) -> Result<()> {
    listener.set_nonblocking(true)?;
    let listener = TcpListener::from_std(listener)?;
    let admission = max_connections.map(|limit| Arc::new(Semaphore::new(limit)));
    loop {
        let (stream, transport_peer) = listener.accept().await?;
        if !trusted_proxies
            .iter()
            .any(|network| network.contains(&transport_peer.ip()))
        {
            // 🚫 Dropped before a permit is taken: an untrusted flood must not
            // be able to exhaust the budget meant for real downstream traffic.
            tracing::warn!(
                peer = %transport_peer,
                "🚫 Rejected PROXY protocol connection from an untrusted transport peer"
            );
            continue;
        }

        // 🧱 The permit is held for the whole tunnel, matching how the Pingora
        // app holds its own for the lifetime of a downstream connection.
        let permit = match &admission {
            Some(admission) => match admission.clone().try_acquire_owned() {
                Ok(permit) => Some(permit),
                Err(_) => {
                    tracing::warn!(
                        peer = %transport_peer,
                        "🚫 Rejecting a PROXY protocol connection at the configured limit"
                    );
                    drop(stream);
                    continue;
                }
            },
            None => None,
        };

        let registry = registry.clone();
        let blocked_clients = blocked_clients.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = handle_connection(
                stream,
                transport_peer,
                internal_listener,
                registry,
                &blocked_clients,
            )
            .await
            {
                tracing::warn!(
                    peer = %transport_peer,
                    %error,
                    "🚫 Rejected invalid PROXY protocol connection"
                );
            }
        });
    }
}

async fn handle_connection(
    mut downstream: TcpStream,
    transport_peer: SocketAddr,
    internal_listener: SocketAddr,
    registry: Arc<ProxyProtocolRegistry>,
    blocked_clients: &[IpNet],
) -> Result<()> {
    let client = tokio::time::timeout(
        Duration::from_secs(5),
        read_proxy_protocol_header(&mut downstream),
    )
    .await
    .map_err(|_| Error::new(ErrorKind::TimedOut, "PROXY protocol header timed out"))??;
    if blocked_clients
        .iter()
        .any(|network| network.contains(&client.ip()))
    {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "PROXY protocol client is blocked",
        ));
    }

    let mut upstream = connect_internal(internal_listener).await?;
    let internal_peer = upstream.local_addr()?;
    registry.register(
        internal_peer,
        internal_listener,
        ProxyProtocolIdentity {
            client,
            transport_peer,
        },
    );
    let result = tokio::io::copy_bidirectional(&mut downstream, &mut upstream)
        .await
        .map(|_| ());
    registry.unregister(internal_peer, internal_listener);
    result
}

async fn connect_internal(address: SocketAddr) -> Result<TcpStream> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match TcpStream::connect(address).await {
            Ok(stream) => return Ok(stream),
            Err(error) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(25)).await;
                let _ = error;
            }
            Err(error) => return Err(error),
        }
    }
}

async fn read_proxy_protocol_header<R>(stream: &mut R) -> Result<SocketAddr>
where
    R: AsyncRead + Unpin,
{
    let mut prefix = [0u8; 12];
    stream.read_exact(&mut prefix).await?;
    if &prefix == V2_SIGNATURE {
        read_v2_header(stream).await
    } else if prefix.starts_with(b"PROXY ") {
        read_v1_header(stream, prefix.to_vec()).await
    } else {
        Err(Error::new(
            ErrorKind::InvalidData,
            "missing PROXY protocol v1 or v2 signature",
        ))
    }
}

async fn read_v1_header<R>(stream: &mut R, mut line: Vec<u8>) -> Result<SocketAddr>
where
    R: AsyncRead + Unpin,
{
    while !line.ends_with(b"\r\n") {
        if line.len() >= MAX_V1_HEADER_BYTES {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "PROXY protocol v1 header exceeds 108 bytes",
            ));
        }
        line.push(stream.read_u8().await?);
    }
    let line = std::str::from_utf8(&line[..line.len() - 2])
        .map_err(|_| Error::new(ErrorKind::InvalidData, "PROXY v1 header is not ASCII"))?;
    let parts = line.split_ascii_whitespace().collect::<Vec<_>>();
    if parts.len() != 6 || parts[0] != "PROXY" {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "PROXY v1 header must contain six fields",
        ));
    }
    let source = parts[2]
        .parse::<IpAddr>()
        .map_err(|_| Error::new(ErrorKind::InvalidData, "invalid PROXY v1 source address"))?;
    let destination = parts[3].parse::<IpAddr>().map_err(|_| {
        Error::new(
            ErrorKind::InvalidData,
            "invalid PROXY v1 destination address",
        )
    })?;
    let family_matches = matches!(
        (parts[1], source, destination),
        ("TCP4", IpAddr::V4(_), IpAddr::V4(_)) | ("TCP6", IpAddr::V6(_), IpAddr::V6(_))
    );
    if !family_matches {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "PROXY v1 address family does not match its addresses",
        ));
    }
    let source_port = parts[4]
        .parse::<u16>()
        .map_err(|_| Error::new(ErrorKind::InvalidData, "invalid PROXY v1 source port"))?;
    parts[5]
        .parse::<u16>()
        .map_err(|_| Error::new(ErrorKind::InvalidData, "invalid PROXY v1 destination port"))?;
    Ok(SocketAddr::new(source, source_port))
}

async fn read_v2_header<R>(stream: &mut R) -> Result<SocketAddr>
where
    R: AsyncRead + Unpin,
{
    let version_command = stream.read_u8().await?;
    let family_protocol = stream.read_u8().await?;
    let payload_length = stream.read_u16().await? as usize;
    if version_command != 0x21 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "PROXY v2 requires version 2 and the PROXY command",
        ));
    }
    if payload_length > MAX_V2_PAYLOAD_BYTES {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "PROXY v2 payload exceeds 512 bytes",
        ));
    }
    let mut payload = vec![0u8; payload_length];
    stream.read_exact(&mut payload).await?;
    match family_protocol {
        0x11 if payload.len() >= 12 => {
            let source = Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
            let port = u16::from_be_bytes([payload[8], payload[9]]);
            Ok(SocketAddr::new(IpAddr::V4(source), port))
        }
        0x21 if payload.len() >= 36 => {
            let source = Ipv6Addr::from(
                <[u8; 16]>::try_from(&payload[..16])
                    .map_err(|_| Error::new(ErrorKind::InvalidData, "invalid PROXY v2 IPv6"))?,
            );
            let port = u16::from_be_bytes([payload[32], payload[33]]);
            Ok(SocketAddr::new(IpAddr::V6(source), port))
        }
        _ => Err(Error::new(
            ErrorKind::InvalidData,
            "PROXY v2 requires a TCP over IPv4 or IPv6 address block",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn parses_proxy_protocol_v1_without_consuming_http_bytes() {
        let (mut writer, mut reader) = tokio::io::duplex(256);
        writer
            .write_all(b"PROXY TCP4 203.0.113.7 192.0.2.1 4567 443\r\nGET / HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        assert_eq!(
            read_proxy_protocol_header(&mut reader).await.unwrap(),
            "203.0.113.7:4567".parse().unwrap()
        );
        let mut next = [0u8; 3];
        reader.read_exact(&mut next).await.unwrap();
        assert_eq!(&next, b"GET");
    }

    #[tokio::test]
    async fn parses_proxy_protocol_v2_ipv4_without_consuming_http_bytes() {
        let mut header = V2_SIGNATURE.to_vec();
        header.extend_from_slice(&[0x21, 0x11, 0, 12]);
        header.extend_from_slice(&[203, 0, 113, 7, 192, 0, 2, 1]);
        header.extend_from_slice(&4567u16.to_be_bytes());
        header.extend_from_slice(&443u16.to_be_bytes());
        header.extend_from_slice(b"GET");
        let (mut writer, mut reader) = tokio::io::duplex(256);
        writer.write_all(&header).await.unwrap();
        assert_eq!(
            read_proxy_protocol_header(&mut reader).await.unwrap(),
            "203.0.113.7:4567".parse().unwrap()
        );
        let mut next = [0u8; 3];
        reader.read_exact(&mut next).await.unwrap();
        assert_eq!(&next, b"GET");
    }

    #[tokio::test]
    async fn rejects_missing_or_local_proxy_commands() {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        writer.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
        assert!(read_proxy_protocol_header(&mut reader).await.is_err());

        let mut local = V2_SIGNATURE.to_vec();
        local.extend_from_slice(&[0x20, 0x00, 0, 0]);
        let (mut writer, mut reader) = tokio::io::duplex(64);
        writer.write_all(&local).await.unwrap();
        assert!(read_proxy_protocol_header(&mut reader).await.is_err());
    }
}

#[cfg(test)]
mod admission_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// 🧪 Answers one request per accepted connection on a loopback listener.
    async fn spawn_internal_origin() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buffer = [0u8; 1024];
                    if stream.read(&mut buffer).await.unwrap_or(0) == 0 {
                        return;
                    }
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        )
                        .await;
                    // 🕰️ Held open so the tunnel's permit stays taken while the
                    // test opens the connection that must be refused.
                    tokio::time::sleep(Duration::from_secs(5)).await;
                });
            }
        });
        (address, task)
    }

    #[tokio::test]
    async fn the_public_ingress_enforces_the_same_connection_ceiling() {
        // Setup scenarios
        //
        // With PROXY protocol on, the Pingora app moves to the private hop, so
        // its own admission control no longer bounds external connections.
        // A ceiling of one must still mean one downstream connection.
        let (internal, origin) = spawn_internal_origin().await;
        let public = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let public_address = public.local_addr().unwrap();
        let ingress = tokio::spawn(run_ingress(
            public,
            internal,
            Arc::new(ProxyProtocolRegistry::default()),
            vec!["127.0.0.0/8".parse().unwrap()],
            Vec::new(),
            Some(1),
        ));

        // The first tunnel takes the only permit and keeps it.
        let mut first = TcpStream::connect(public_address).await.unwrap();
        first
            .write_all(
                b"PROXY TCP4 203.0.113.7 192.0.2.1 4567 443\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n",
            )
            .await
            .unwrap();
        let mut buffer = [0u8; 64];
        let read = first.read(&mut buffer).await.unwrap();
        assert!(
            String::from_utf8_lossy(&buffer[..read]).starts_with("HTTP/1.1 200"),
            "the first tunnel should be served"
        );

        // Verification
        //
        // The second connection is accepted by the kernel and then closed
        // without a byte, which is the only honest answer at L4 — the ingress
        // cannot speak HTTP here because the payload may be TLS.
        let mut second = TcpStream::connect(public_address).await.unwrap();
        second
            .write_all(
                b"PROXY TCP4 203.0.113.8 192.0.2.1 4568 443\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n",
            )
            .await
            .unwrap();
        let mut rejected = Vec::new();
        // Either a clean close or a reset counts as refused; dropping a socket
        // that still holds unread request bytes makes the kernel send RST.
        // What must hold is that it ends promptly and forwards nothing.
        let refused =
            tokio::time::timeout(Duration::from_secs(2), second.read_to_end(&mut rejected))
                .await
                .expect("an over-limit connection must be terminated, not left hanging");
        assert!(
            rejected.is_empty(),
            "an over-limit connection must be refused before any forwarding: \
             {refused:?} {rejected:?}"
        );

        ingress.abort();
        origin.abort();
    }

    #[tokio::test]
    async fn an_untrusted_peer_is_refused_without_taking_a_permit() {
        // Setup scenarios
        //
        // Untrusted floods must not be able to consume the budget reserved for
        // real downstream traffic, so the trust check has to come first.
        let (internal, origin) = spawn_internal_origin().await;
        let public = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let public_address = public.local_addr().unwrap();
        let ingress = tokio::spawn(run_ingress(
            public,
            internal,
            Arc::new(ProxyProtocolRegistry::default()),
            // Loopback is deliberately *not* trusted here.
            vec!["203.0.113.0/24".parse().unwrap()],
            Vec::new(),
            Some(1),
        ));

        for _ in 0..8 {
            let mut untrusted = TcpStream::connect(public_address).await.unwrap();
            let _ = untrusted
                .write_all(b"PROXY TCP4 203.0.113.7 192.0.2.1 4567 443\r\n")
                .await;
            let mut drained = Vec::new();
            let _ =
                tokio::time::timeout(Duration::from_secs(2), untrusted.read_to_end(&mut drained))
                    .await
                    .expect("untrusted connections must be closed promptly");
        }

        // Verification: the permit was never taken, so a trusted peer still fits.
        ingress.abort();
        origin.abort();
    }
}
