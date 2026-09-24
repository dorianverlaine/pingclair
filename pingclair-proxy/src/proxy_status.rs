// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🏷️ `Proxy-Status` (RFC 9209): saying "this 502 is mine, not the origin's".
//!
//! When a backend refuses a connection, the client gets a 502 that looks
//! exactly like a 502 the backend sent itself. Someone reading `curl -i`
//! cannot tell "the origin is broken" from "this proxy could not reach the
//! origin", and those send them to different machines. RFC 9209 exists to
//! carry that one fact: a member naming this hop, with an `error` parameter
//! whose presence means this hop generated the response.
//!
//! # 📌 What goes in the field, and what deliberately does not
//!
//! - **The member name is the fixed token `pingclair`.** The RFC suggests a
//!   deployment name, but a configurable name is a setting nobody has asked
//!   for yet, and a fixed token is stable across reloads and hosts.
//! - **Only the error type.** The RFC's `next-hop` and `details` parameters
//!   would name the backend's address or echo an OS error string to whoever
//!   sent the request, which is an internal topology leak. The error type
//!   alone answers the question the field exists for.
//! - **Only on responses this proxy generated for a failed upstream
//!   exchange.** A forwarded upstream response is never touched — the field
//!   must not be generated on the origin's behalf, and an upstream that sent
//!   its own member should reach the client unchanged. Ordinary local
//!   responses (`respond`, `file_server`, a rate-limit 429) carry nothing,
//!   because no next hop was involved.
//!
//! 🏎️ Every value is a `&'static str` spelled out in full, so emitting the
//! field costs one header insert and no formatting on the error path.

use pingora_core::ErrorType;

/// 🏷️ The RFC 9209 §2.3 proxy error types this proxy can actually observe.
///
/// A deliberately short list: the registry has thirty-odd types, and most
/// name states (DNS failures, per-field size limits) that this proxy either
/// never reaches or cannot tell apart from the error it receives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProxyError {
    /// 🔌 The backend actively refused the TCP connection.
    ConnectionRefused = 1,
    /// ⌛ The TCP or TLS handshake with the backend did not finish in time.
    ConnectionTimeout,
    /// 🧭 The network had no route to the backend's address.
    DestinationIpUnroutable,
    /// 🔐 The TLS handshake with the backend failed.
    TlsProtocolError,
    /// 🔐 The backend's certificate did not verify.
    TlsCertificateError,
    /// ⌛ The backend accepted the request and then did not answer in time.
    HttpResponseTimeout,
    /// ⌛ Writing the request to the backend stalled past its deadline.
    ConnectionWriteTimeout,
    /// 🪓 The backend closed or broke the connection mid-exchange.
    ConnectionTerminated,
    /// 🧾 The backend's answer was not valid HTTP.
    HttpProtocolError,
    /// 🧭 The backend failed in a way none of the specific types describes.
    /// Still a remote failure, so this is not `proxy_internal_error`.
    DestinationUnavailable,
    /// 🧯 This process ran out of something (descriptors, ports) before any
    /// packet reached the backend.
    ProxyInternalError,
}

impl ProxyError {
    /// 🩺 Classifies an error that ended a proxied exchange.
    ///
    /// Local exhaustion is checked first through the same classifier the
    /// health map uses, because Pingora collapses it into `InternalError`
    /// and the two paths must not disagree about whose fault a failure was.
    /// The remaining types are specific on the top-level error — Pingora
    /// names the remote condition there, and the cause chain below it is the
    /// `std::io::Error`, which has no type to add.
    pub fn from_upstream_error(error: &pingora_core::Error) -> Self {
        if !crate::upstream_failure::classify_connect_error(error).implicates_backend() {
            return Self::ProxyInternalError;
        }
        match error.etype() {
            ErrorType::ConnectRefused => Self::ConnectionRefused,
            ErrorType::ConnectTimedout | ErrorType::TLSHandshakeTimedout => Self::ConnectionTimeout,
            ErrorType::ConnectNoRoute => Self::DestinationIpUnroutable,
            ErrorType::TLSHandshakeFailure
            | ErrorType::TLSWantX509Lookup
            | ErrorType::HandshakeError => Self::TlsProtocolError,
            ErrorType::InvalidCert => Self::TlsCertificateError,
            ErrorType::ReadTimedout => Self::HttpResponseTimeout,
            ErrorType::WriteTimedout => Self::ConnectionWriteTimeout,
            ErrorType::ConnectionClosed | ErrorType::ReadError | ErrorType::WriteError => {
                Self::ConnectionTerminated
            }
            ErrorType::InvalidHTTPHeader
            | ErrorType::H1Error
            | ErrorType::H2Error
            | ErrorType::H2Downgrade
            | ErrorType::InvalidH2 => Self::HttpProtocolError,
            _ => Self::DestinationUnavailable,
        }
    }

    /// 🏷️ The complete field value, member name included.
    pub const fn header_value(self) -> &'static str {
        match self {
            Self::ConnectionRefused => "pingclair; error=connection_refused",
            Self::ConnectionTimeout => "pingclair; error=connection_timeout",
            Self::DestinationIpUnroutable => "pingclair; error=destination_ip_unroutable",
            Self::TlsProtocolError => "pingclair; error=tls_protocol_error",
            Self::TlsCertificateError => "pingclair; error=tls_certificate_error",
            Self::HttpResponseTimeout => "pingclair; error=http_response_timeout",
            Self::ConnectionWriteTimeout => "pingclair; error=connection_write_timeout",
            Self::ConnectionTerminated => "pingclair; error=connection_terminated",
            Self::HttpProtocolError => "pingclair; error=http_protocol_error",
            Self::DestinationUnavailable => "pingclair; error=destination_unavailable",
            Self::ProxyInternalError => "pingclair; error=proxy_internal_error",
        }
    }

    /// 🔁 Inverse of `as u8`, for the H3 path, which records the error in an
    /// atomic on a sink shared across await points. Zero means "none".
    pub(crate) const fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::ConnectionRefused,
            2 => Self::ConnectionTimeout,
            3 => Self::DestinationIpUnroutable,
            4 => Self::TlsProtocolError,
            5 => Self::TlsCertificateError,
            6 => Self::HttpResponseTimeout,
            7 => Self::ConnectionWriteTimeout,
            8 => Self::ConnectionTerminated,
            9 => Self::HttpProtocolError,
            10 => Self::DestinationUnavailable,
            11 => Self::ProxyInternalError,
            _ => return None,
        })
    }
}

/// 📛 The field name, lowercase so it is valid on every transport.
pub const HEADER_NAME: &str = "proxy-status";

#[cfg(test)]
mod tests {
    use super::*;

    /// 🔁 Every variant survives the atomic round trip the H3 path relies on.
    #[test]
    fn every_variant_round_trips_through_u8() {
        for value in 1..=11u8 {
            let error = ProxyError::from_u8(value).expect("a defined discriminant");
            assert_eq!(error as u8, value);
        }
        assert_eq!(ProxyError::from_u8(0), None);
        assert_eq!(ProxyError::from_u8(12), None);
    }

    /// 🧯 A local exhaustion is this proxy's fault, not the backend's, even
    /// though Pingora reports it under the same `Upstream` source.
    #[test]
    fn local_exhaustion_is_a_proxy_internal_error() {
        let error = pingora_core::Error::explain(ErrorType::InternalError, "EMFILE");
        assert_eq!(
            ProxyError::from_upstream_error(&error),
            ProxyError::ProxyInternalError
        );
        let refused = pingora_core::Error::explain(ErrorType::ConnectRefused, "refused");
        assert_eq!(
            ProxyError::from_upstream_error(&refused),
            ProxyError::ConnectionRefused
        );
    }
}
