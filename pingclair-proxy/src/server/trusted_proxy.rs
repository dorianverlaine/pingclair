// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🛡️ Who the client is, when a proxy in front of this server says so.
//!
//! A request that arrives through a load balancer comes from the load
//! balancer's address; the real client is named in `X-Forwarded-For`,
//! `Forwarded` or another configured header. Those headers are only believed
//! when the immediate peer is a configured trusted proxy, and even then the
//! chain is walked from the nearest hop outward so a client cannot name itself
//! by prepending an address. Everything here is parsing and trust policy; the
//! request lifecycle that consults it stays in `server.rs`.

use ipnet::IpNet;
use std::net::IpAddr;

/// 🧱 Maximum accepted hops in an inbound `X-Forwarded-For` chain.
pub(super) const MAX_FORWARDED_HOPS: usize = 32;

/// 🛡️ Pre-parsed proxy networks allowed to assert downstream client identity.
#[derive(Debug, Clone)]
pub(super) struct TrustedProxyPolicy {
    networks: Vec<IpNet>,
    /// 🛡️ The headers a trusted peer may name the client in; `None` is the
    /// built-in set. Parsed into `HeaderName`s once, at load.
    client_ip_headers: Option<Box<[http::HeaderName]>>,
}

impl TrustedProxyPolicy {
    pub(super) fn from_rules(rules: &[String]) -> Self {
        let networks = rules
            .iter()
            .filter_map(|rule| {
                rule.parse::<IpNet>()
                    .or_else(|_| rule.parse::<IpAddr>().map(IpNet::from))
                    .map_err(|error| {
                        tracing::error!(
                            rule,
                            %error,
                            "❌ Invalid trusted proxy IP/CIDR; the rule is ignored"
                        );
                    })
                    .ok()
            })
            .collect();
        Self {
            networks,
            client_ip_headers: None,
        }
    }

    /// 🛡️ Restricts the client address to the headers `names` lists, in order.
    ///
    /// An empty list keeps the built-in set. Names were validated when the
    /// configuration compiled; one that still fails to parse is logged and
    /// skipped, which narrows the sources rather than widening them.
    pub(super) fn reading_client_ip_from(mut self, names: &[String]) -> Self {
        if names.is_empty() {
            self.client_ip_headers = None;
            return self;
        }
        self.client_ip_headers = Some(
            names
                .iter()
                .filter_map(|name| {
                    http::HeaderName::from_bytes(name.as_bytes())
                        .map_err(|error| {
                            tracing::error!(
                                name,
                                %error,
                                "❌ Invalid client_ip_headers entry; the header is ignored"
                            );
                        })
                        .ok()
                })
                .collect(),
        );
        self
    }

    pub(super) fn contains(&self, address: IpAddr) -> bool {
        self.networks
            .iter()
            .any(|network| network.contains(&address))
    }

    pub(super) fn verified_client_ip(&self, peer: IpAddr, headers: &http::HeaderMap) -> IpAddr {
        self.verified_client_ip_with_fallback(peer, peer, headers)
    }

    pub(super) fn verified_client_ip_with_fallback(
        &self,
        transport_peer: IpAddr,
        fallback: IpAddr,
        headers: &http::HeaderMap,
    ) -> IpAddr {
        if !self.contains(transport_peer) {
            return fallback;
        }

        // 🛡️ Configured headers are the only sources, consulted in order: the
        // first one that names a client decides, and a header that is absent,
        // malformed or stops at a hidden hop passes to the next.
        //
        // ☁️ `CF-Connecting-IP` is believed only from here. It used to win
        // whenever the peer was trusted, but a trusted peer is not necessarily
        // Cloudflare: an ingress or load balancer that forwards client headers
        // untouched let any client name itself with it.
        if let Some(names) = &self.client_ip_headers {
            return names
                .iter()
                .find_map(|name| self.client_from_header(name, headers))
                .unwrap_or(fallback);
        }

        // 🧭 Each header is read on its own first. A header that fails to
        // parse, or whose walk stops at a hop that hid its address, simply
        // contributes nothing; the other header can still name the client.
        // Only two headers that each name a client, and name different ones,
        // are treated as tampering, because that is the one case where
        // believing either would be a guess.
        let xff = parse_forwarded_chain(headers, "x-forwarded-for");
        let forwarded = parse_rfc_forwarded_chain(headers);
        let both_absent = matches!((&xff, &forwarded), (Ok(None), Ok(None)));
        let xff_client = match &xff {
            Ok(Some(chain)) => self.client_from(chain.iter().copied().map(Some)),
            Ok(None) | Err(()) => None,
        };
        let forwarded_client = match &forwarded {
            Ok(Some(chain)) => self.client_from(chain.iter().copied()),
            Ok(None) | Err(()) => None,
        };
        match (xff_client, forwarded_client) {
            (Some(xff_client), Some(forwarded_client)) => {
                if xff_client == forwarded_client {
                    xff_client
                } else {
                    tracing::warn!(
                        xff = %xff_client,
                        forwarded = %forwarded_client,
                        "🚫 Conflicting forwarding identity headers failed closed"
                    );
                    fallback
                }
            }
            (Some(client), None) | (None, Some(client)) => client,
            // 🛡️ `X-Real-IP` is consulted only when no chain was sent at all.
            // A chain that was sent and could not name anyone is an answer
            // ("unknown"), not a gap for a third header to fill.
            (None, None) if both_absent => headers
                .get("x-real-ip")
                .and_then(|value| value.to_str().ok())
                .and_then(parse_forwarded_ip)
                .unwrap_or(fallback),
            (None, None) => fallback,
        }
    }

    /// 🧭 The client one configured header names, if it names one.
    fn client_from_header(
        &self,
        name: &http::HeaderName,
        headers: &http::HeaderMap,
    ) -> Option<IpAddr> {
        if name == http::header::FORWARDED {
            let chain = parse_rfc_forwarded_chain(headers).ok()??;
            return self.client_from(chain.into_iter());
        }
        let chain = parse_forwarded_chain(headers, name).ok()??;
        self.client_from(chain.into_iter().map(Some))
    }

    /// 🧭 Walks a forwarding chain from the nearest hop outward and returns
    /// the first address this server does not trust, which is the client.
    ///
    /// 🛡️ A hop that hid its address (`None`, from `for=unknown` or an
    /// obfuscated `for=_name`) ends the walk with no answer: everything to its
    /// left was reported by a party whose own address is unknown, so none of
    /// it can be verified. When every hop is trusted, the leftmost one is the
    /// client, as before.
    fn client_from<I>(&self, chain: I) -> Option<IpAddr>
    where
        I: DoubleEndedIterator<Item = Option<IpAddr>>,
    {
        let mut leftmost = None;
        for hop in chain.rev() {
            let address = hop?;
            if !self.contains(address) {
                return Some(address);
            }
            leftmost = Some(address);
        }
        leftmost
    }

    pub(super) fn forwarded_for_with_fallback(
        &self,
        transport_peer: IpAddr,
        fallback: IpAddr,
        headers: &http::HeaderMap,
    ) -> String {
        if !self.contains(transport_peer) {
            return fallback.to_string();
        }

        // 🛡️ When `client_ip_headers` leaves `X-Forwarded-For` out, the
        // incoming chain is not a source this server believes, so it is not
        // passed on either: the upstream chain starts from the client the
        // configured headers named. Forwarding it used to hand the origin an
        // address the client chose, while this server itself ignored it.
        let incoming_chain = match &self.client_ip_headers {
            Some(names) if !names.iter().any(|name| name == "x-forwarded-for") => Ok(None),
            _ => parse_forwarded_chain(headers, "x-forwarded-for"),
        };
        let Ok(Some(mut chain)) = incoming_chain else {
            let client = self.verified_client_ip_with_fallback(transport_peer, fallback, headers);
            return if client == transport_peer {
                transport_peer.to_string()
            } else {
                format!("{client}, {transport_peer}")
            };
        };
        if chain.last().copied() != Some(transport_peer) {
            chain.push(transport_peer);
        }
        chain
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// 🔎 Parses every field named `name` — `X-Forwarded-For`, or any header
/// `client_ip_headers` lists — as a comma-separated address list, into one
/// bounded, normalized chain. A single-address header such as
/// `CF-Connecting-IP` is the one-element case.
///
/// 🧹 Empty list elements are skipped, as RFC 9110 §5.6.1.2 requires of a
/// recipient: a sender that merges two lists commonly leaves `a, , b` or a
/// trailing comma behind. [`EmptyElementBudget`] keeps a field made only of
/// commas from being accepted at any length.
fn parse_forwarded_chain<K: http::header::AsHeaderName>(
    headers: &http::HeaderMap,
    name: K,
) -> Result<Option<Vec<IpAddr>>, ()> {
    let values = headers.get_all(name);
    if values.iter().next().is_none() {
        return Ok(None);
    }

    let mut chain = Vec::new();
    let mut empty = EmptyElementBudget::default();
    for value in values.iter() {
        let value = value.to_str().map_err(|_| ())?;
        for item in value.split(',') {
            if empty.skip(item)? {
                continue;
            }
            if chain.len() >= MAX_FORWARDED_HOPS {
                return Err(());
            }
            chain.push(parse_forwarded_ip(item).ok_or(())?);
        }
    }
    if chain.is_empty() {
        Err(())
    } else {
        Ok(Some(chain))
    }
}

/// 🧹 Counts the empty list elements one forwarding header may carry.
///
/// 🛡️ RFC 9110 §5.6.1.2 asks for "a reasonable number" of empty elements and
/// names the unbounded case as a denial-of-service vector. One empty element
/// per permitted hop is far more than any merge mistake produces; past that
/// the header is treated as malformed rather than walked.
#[derive(Default)]
struct EmptyElementBudget {
    seen: usize,
}

impl EmptyElementBudget {
    /// 🧹 Returns `Ok(true)` for an element to skip, and `Err` once the budget
    /// is spent.
    fn skip(&mut self, element: &str) -> Result<bool, ()> {
        if !element.trim().is_empty() {
            return Ok(false);
        }
        self.seen += 1;
        if self.seen > MAX_FORWARDED_HOPS {
            Err(())
        } else {
            Ok(true)
        }
    }
}

/// 🧭 Parses RFC 7239 `Forwarded` elements into one bounded `for` chain.
///
/// 🙈 A hop that did not disclose an address — `for=unknown`, an obfuscated
/// `for=_name` (RFC 7239 §6), or an element with no `for=` at all — is kept
/// as `None` rather than failing the whole header, so the trust walk can stop
/// there. Anything else that is not an address is still malformed.
fn parse_rfc_forwarded_chain(headers: &http::HeaderMap) -> Result<Option<Vec<Option<IpAddr>>>, ()> {
    let values = headers.get_all("forwarded");
    if values.iter().next().is_none() {
        return Ok(None);
    }

    let mut chain = Vec::new();
    let mut total_bytes = 0usize;
    let mut empty = EmptyElementBudget::default();
    for value in values.iter() {
        let value = value.to_str().map_err(|_| ())?;
        total_bytes = total_bytes.checked_add(value.len()).ok_or(())?;
        if total_bytes > 8_192 {
            return Err(());
        }
        for element in QuotedSplit::new(value, b',') {
            let element = element?;
            // 🧹 `forwarded-element = [ forwarded-pair ] *( ";" [ forwarded-pair ] )`
            // makes an element with no pair legal, and such an element names no hop.
            if empty.skip(element)? {
                continue;
            }
            if chain.len() >= MAX_FORWARDED_HOPS {
                return Err(());
            }
            let mut forwarded_for = None;
            for parameter in QuotedSplit::new(element, b';') {
                let parameter = parameter?;
                // 🧹 The pair between two semicolons is optional too. The
                // 8 KiB field cap above already bounds how many there can be.
                if parameter.is_empty() {
                    continue;
                }
                let (name, raw_value) = parameter.split_once('=').ok_or(())?;
                if !name.trim().eq_ignore_ascii_case("for") {
                    continue;
                }
                if forwarded_for.is_some() {
                    return Err(());
                }
                let decoded = decode_forwarded_value(raw_value.trim())?;
                forwarded_for = Some(match parse_forwarded_ip(&decoded) {
                    Some(address) => Some(address),
                    None if is_undisclosed_node(&decoded) => None,
                    None => return Err(()),
                });
            }
            chain.push(forwarded_for.flatten());
        }
    }
    if chain.is_empty() {
        Err(())
    } else {
        Ok(Some(chain))
    }
}

/// 🙈 Recognises an RFC 7239 §6 node that names no address: `unknown` or an
/// obfuscated `_identifier`, each optionally followed by `:port`.
pub(super) fn is_undisclosed_node(node: &str) -> bool {
    let (name, port) = match node.split_once(':') {
        Some((name, port)) => (name, Some(port)),
        None => (node, None),
    };
    let obfuscated = |value: &str| {
        value.len() > 1
            && value.starts_with('_')
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    };
    let name_ok = name.eq_ignore_ascii_case("unknown") || obfuscated(name);
    let port_ok = port.is_none_or(|port| {
        (!port.is_empty() && port.len() <= 5 && port.bytes().all(|byte| byte.is_ascii_digit()))
            || obfuscated(port)
    });
    name_ok && port_ok
}

/// 🧭 Splits a header value on a delimiter that is not inside a quoted-string,
/// yielding trimmed slices of the original value.
///
/// 🏎️ It borrows instead of copying each piece into a `String`, because it runs
/// on every request from a trusted proxy. Scanning bytes is sound here: the
/// delimiter, `"` and `\` are ASCII, and no byte of a multi-byte UTF-8
/// character can equal one of them. An unterminated quote or a dangling escape
/// ends the iteration with `Err`.
struct QuotedSplit<'a> {
    rest: Option<&'a str>,
    delimiter: u8,
}

impl<'a> QuotedSplit<'a> {
    fn new(value: &'a str, delimiter: u8) -> Self {
        Self {
            rest: Some(value),
            delimiter,
        }
    }
}

impl<'a> Iterator for QuotedSplit<'a> {
    type Item = Result<&'a str, ()>;

    fn next(&mut self) -> Option<Self::Item> {
        let rest = self.rest?;
        let mut quoted = false;
        let mut escaped = false;
        for (index, &byte) in rest.as_bytes().iter().enumerate() {
            if escaped {
                escaped = false;
            } else if quoted && byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = !quoted;
            } else if byte == self.delimiter && !quoted {
                self.rest = Some(&rest[index + 1..]);
                return Some(Ok(rest[..index].trim()));
            }
        }
        self.rest = None;
        Some(if quoted || escaped {
            Err(())
        } else {
            Ok(rest.trim())
        })
    }
}

/// 🧭 Decodes one `Forwarded` parameter value, borrowing unless a quoted-pair
/// forces a copy.
fn decode_forwarded_value(value: &str) -> Result<std::borrow::Cow<'_, str>, ()> {
    let Some(inner) = value.strip_prefix('"') else {
        if value.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(());
        }
        return Ok(std::borrow::Cow::Borrowed(value));
    };
    let inner = inner.strip_suffix('"').ok_or(())?;
    if inner.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(());
    }
    // 🏎️ An address never needs a quoted-pair, so the common case borrows.
    if !inner.contains('\\') {
        return Ok(std::borrow::Cow::Borrowed(inner));
    }
    let mut decoded = String::with_capacity(inner.len());
    let mut escaped = false;
    for character in inner.chars() {
        if escaped {
            decoded.push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else {
            decoded.push(character);
        }
    }
    if escaped {
        Err(())
    } else {
        Ok(std::borrow::Cow::Owned(decoded))
    }
}

/// 🌐 Parses a forwarded IP with optional quotes, brackets, or a port.
fn parse_forwarded_ip(value: &str) -> Option<IpAddr> {
    let value = value.trim();
    let value = value
        .strip_prefix('"')
        .and_then(|unquoted| unquoted.strip_suffix('"'))
        .unwrap_or(value);
    value
        .parse::<IpAddr>()
        .ok()
        .or_else(|| {
            value
                .parse::<std::net::SocketAddr>()
                .ok()
                .map(|addr| addr.ip())
        })
        .or_else(|| {
            value
                .strip_prefix('[')
                .and_then(|bracketed| bracketed.strip_suffix(']'))
                .and_then(|ip| ip.parse::<IpAddr>().ok())
        })
}
