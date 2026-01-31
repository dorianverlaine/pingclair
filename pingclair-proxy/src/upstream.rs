//! Upstream Server Management
//!
//! Provides types and helpers for defining and creating backend servers.
//! This module acts as a bridge between Pingclair's configuration and Pingora's native backend types.

pub use pingora_load_balancing::Backend as Upstream;
use std::net::ToSocketAddrs;

// MARK: - Types

/// Metadata stored in `Backend` extensions to indicate the protocol scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// Plain text HTTP
    Http,
    /// Encrypted HTTPS
    Https,
}

/// A wrapper type for hostname string, stored in `Backend` extensions.
#[derive(Debug, Clone)]
pub struct HostName(pub String);

// MARK: - Public API

/// Creates a new `Upstream` (Pingora Backend) from a URL string.
///
/// Parses a URL-like string (e.g., "https://example.com:443") into a `SocketAddr`
/// and associated metadata (Scheme, Hostname) required for Pingora's backend.
///
/// - Parameter address_string: The URL string to parse. Supports `http://` and `https://` schemes.
/// - Returns: An `Option<Upstream>` containing the configured backend, or `None` if parsing fails.
///
/// **Design Check:**
/// Uses standard library resolution which is blocking. Acceptable for startup configuration phase.
pub fn create_upstream(address_string: &str) -> Option<Upstream> {
    // Guard: Parse URL components
    let (socket_address, scheme, host) = parse_url_components(address_string)?;
    
    // Create Backend with the resolved IP address
    let mut backend = Upstream::new(&socket_address.to_string()).ok()?;
    
    // Enrich with metadata
    backend.ext.insert(scheme);
    backend.ext.insert(HostName(host));
    
    Some(backend)
}

// MARK: - Private Helpers

/// Parses a URL string into its core components.
///
/// - Parameter upstream: The upstream string to parse.
/// - Returns: A tuple of `(SocketAddr, Scheme, HostString)` or `None`.
fn parse_url_components(upstream: &str) -> Option<(std::net::SocketAddr, Scheme, String)> {
    let trimmed_upstream = upstream.trim();
    
    // Determine scheme and strip prefix
    let (scheme, minimal_url) = if trimmed_upstream.starts_with("https://") {
        (Scheme::Https, &trimmed_upstream[8..])
    } else if trimmed_upstream.starts_with("http://") {
        (Scheme::Http, &trimmed_upstream[7..])
    } else {
        (Scheme::Http, trimmed_upstream)
    };
    
    // Extract host and port
    let (host, port) = if let Some(colon_index) = minimal_url.rfind(':') {
        let host_part = &minimal_url[..colon_index];
        let port_part = &minimal_url[colon_index + 1..];
        let port_number = port_part.parse::<u16>().ok()?;
        (host_part, port_number)
    } else {
        let default_port = if scheme == Scheme::Https { 443 } else { 80 };
        (minimal_url, default_port)
    };
    
    // Resolve address (Blocking)
    let socket_address = format!("{}:{}", host, port).to_socket_addrs().ok()?.next()?;
    
    Some((socket_address, scheme, host.to_string()))
}
