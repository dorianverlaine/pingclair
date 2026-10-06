// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🎧 The per-site `listen` directive, read the way nginx reads it.
//!
//! `listen` is this project's own directive (Caddy has none), so nginx is the
//! reference: `listen 127.0.0.1:8080` binds that address, `listen :8080` or
//! `listen 8080` binds every interface, `listen [::1]:8080` is IPv6 in
//! brackets, and an address with no port takes the default one. Optional
//! `http://` or `https://` in front picks the transport, and
//! `proxy_protocol` after it requires the PROXY header (nginx's spelling).
//!
//! 🤡 Until 2026-10-06 the host was thrown away: every `listen` became
//! `[::]:<port>`, so `listen 127.0.0.1:8080` exposed the site on every
//! interface while reading as loopback-only.
//!
//! 🚫 Refused, because each would otherwise bind something the operator did
//! not write: a hostname (nginx resolves it at startup; this server binds and
//! never resolves, and picking one of several answers is a listener nobody
//! chose), an IPv6 address without brackets (`::1:8080` is itself a valid
//! IPv6 address, so the port cannot be told apart), a port that is not a
//! number from 0 to 65535, and an address that contradicts the site's `bind`.

use super::AdapterError;
use crate::parser::ast::{GlobalBlock, ListenAddr, Scheme, ServerBlock};
use crate::parser::caddy_ast::Directive;
use std::net::IpAddr;

/// 🌐 How every interface, IPv4 and IPv6, is spelled once it is a socket.
const WILDCARD: &str = "[::]";

/// 🎧 Reads one `listen` directive into the listener it names.
pub(super) fn adapt_listen(
    directive: &Directive,
    global: &GlobalBlock,
) -> Result<ListenAddr, AdapterError> {
    let refuse = |reason: String| AdapterError::InvalidArgument("listen".into(), reason);
    let Some(raw) = directive.args.first() else {
        return Err(AdapterError::ArgumentCount("listen".into(), 1, 0));
    };
    // 🚩 Trailing flags are refused rather than dropped: reading `args[0]`
    // alone once made `listen :443 proxy_protocol` a listener that quietly did
    // not require the header it named.
    let mut proxy_protocol = false;
    for flag in &directive.args[1..] {
        match flag.as_str() {
            "proxy_protocol" => proxy_protocol = true,
            other => return Err(refuse(format!("unknown listener flag `{other}`"))),
        }
    }

    let (scheme, force_plaintext, rest) = if let Some(rest) = raw.strip_prefix("https://") {
        (Scheme::Https, false, rest)
    } else if let Some(rest) = raw.strip_prefix("http://") {
        (Scheme::Http, true, rest)
    } else {
        (Scheme::Http, false, raw.as_str())
    };
    let default_port = match scheme {
        Scheme::Https => global.https_port.unwrap_or(443),
        Scheme::Http => global.http_port.unwrap_or(80),
    };

    let (host, port) =
        split_host_and_port(rest).map_err(|reason| refuse(format!("`{raw}`: {reason}")))?;
    let port = match port {
        None => default_port,
        Some(port) => port.parse::<u16>().map_err(|_| {
            refuse(format!(
                "`{raw}`: the port `{port}` is not a number from 0 to 65535"
            ))
        })?,
    };
    let host = if host.is_empty() || host == "*" {
        WILDCARD.to_string()
    } else {
        socket_host(host).ok_or_else(|| {
            refuse(format!(
                "`{raw}`: `{host}` is not an IP address; `listen` binds an interface and \
                 never resolves a name. Use the site address for the name and an IP (or \
                 `:port`) here"
            ))
        })?
    };
    // 📌 `[::]` is every interface, which `bind` may narrow. `0.0.0.0` is not
    // the same thing: it is every IPv4 interface and no IPv6 one, a choice.
    let explicit_interface = host != WILDCARD;

    Ok(ListenAddr {
        scheme,
        host,
        port: Some(port),
        force_plaintext,
        proxy_protocol,
        explicit_interface,
    })
}

/// ✂️ Splits `127.0.0.1:8080`, `[::1]:8080`, `:8080`, `8080`, `127.0.0.1`
/// and `[::1]` into a host and an optional port, without judging either.
fn split_host_and_port(rest: &str) -> Result<(&str, Option<&str>), String> {
    if let Some(bracketed) = rest.strip_prefix('[') {
        let (inside, after) = bracketed
            .split_once(']')
            .ok_or_else(|| "an IPv6 address opened with `[` is never closed".to_string())?;
        let host = &rest[..inside.len() + 2];
        return match after {
            "" => Ok((host, None)),
            _ => match after.strip_prefix(':') {
                Some(port) => Ok((host, Some(port))),
                None => Err(format!("unexpected `{after}` after the IPv6 address")),
            },
        };
    }
    if !rest.is_empty() && rest.bytes().all(|byte| byte.is_ascii_digit()) {
        return Ok(("", Some(rest)));
    }
    match rest.matches(':').count() {
        0 => Ok((rest, None)),
        1 => {
            let (host, port) = rest.split_once(':').expect("one colon");
            Ok((host, Some(port)))
        }
        _ => Err("an IPv6 address needs brackets, as in `[::1]:8080`".to_string()),
    }
}

/// 🌐 The socket spelling of an IP literal: IPv4 as written, IPv6 bracketed.
/// `None` for anything that is not an IP address.
fn socket_host(host: &str) -> Option<String> {
    let bare = host
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(host);
    let bracketed = bare != host;
    match bare.parse::<IpAddr>().ok()? {
        IpAddr::V4(ipv4) if !bracketed => Some(ipv4.to_string()),
        IpAddr::V6(ipv6) if bracketed => Some(format!("[{ipv6}]")),
        // 🚫 `[1.2.3.4]` and an unbracketed IPv6 are not socket spellings.
        IpAddr::V4(_) | IpAddr::V6(_) => None,
    }
}

/// 🚫 Refuses a `listen` address whose interface contradicts the site's
/// `bind`.
///
/// `bind` puts every listener of the site on its host, so
/// `bind 127.0.0.1` with `listen 10.0.0.1:8080` would silently move the
/// listener the operator spelled out. Either one alone is clear; both, when
/// they disagree, have no answer that honours what was written.
pub(super) fn reject_listen_contradicting_bind(server: &ServerBlock) -> Result<(), AdapterError> {
    let Some(bind) = server.bind.as_deref() else {
        return Ok(());
    };
    // 🌐 `bind` takes an IPv6 address with or without brackets.
    let bound = socket_host(bind)
        .or_else(|| socket_host(&format!("[{bind}]")))
        .unwrap_or_else(|| bind.to_string());
    match server
        .listens
        .iter()
        .find(|listen| listen.explicit_interface && listen.host != bound)
    {
        Some(listen) => Err(AdapterError::InvalidArgument(
            "listen".into(),
            format!(
                "`listen {}:{}` names a different interface than `bind {bind}`; `bind` \
                 applies to every listener of the site, so write the address once",
                listen.host,
                listen.port.unwrap_or_default(),
            ),
        )),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use crate::compile;

    fn listens(site_body: &str) -> Vec<String> {
        let config =
            compile(&format!("x.test {{\n{site_body}\n    respond \"x\"\n}}")).expect("compiles");
        config.servers[0].listen.clone()
    }

    fn refusal(site_body: &str) -> String {
        compile(&format!("x.test {{\n{site_body}\n    respond \"x\"\n}}"))
            .expect_err("refused")
            .to_string()
    }

    /// 🎧 Each nginx spelling binds the address it names.
    #[test]
    fn listen_keeps_the_interface_it_names() {
        let cases = [
            ("listen 127.0.0.1:8080", "127.0.0.1:8080"),
            ("listen [::1]:8080", "[::1]:8080"),
            ("listen [0:0::1]:8080", "[::1]:8080"),
            ("listen :8080", "[::]:8080"),
            ("listen 8080", "[::]:8080"),
            ("listen *:8080", "[::]:8080"),
            ("listen 0.0.0.0:8080", "0.0.0.0:8080"),
            ("listen 127.0.0.1", "127.0.0.1:80"),
            ("listen http://127.0.0.1:8080", "127.0.0.1:8080"),
            ("listen https://[::1]", "[::1]:443"),
        ];
        let seen: Vec<(&str, Vec<String>)> = cases
            .iter()
            .map(|(directive, _)| (*directive, listens(directive)))
            .collect();
        let expected: Vec<(&str, Vec<String>)> = cases
            .iter()
            .map(|(directive, address)| (*directive, vec![(*address).to_string()]))
            .collect();
        assert_eq!(seen, expected);
    }

    /// 🚫 Hostnames, unbracketed IPv6, bad ports and contradictions fail.
    #[test]
    fn listen_refuses_what_it_cannot_bind_as_written() {
        for (body, needle) in [
            ("listen example.com:8080", "not an IP address"),
            ("listen ::1:8080", "brackets"),
            ("listen [::1:8080", "never closed"),
            ("listen 127.0.0.1:http", "not a number"),
            ("listen :70000", "not a number"),
            ("listen [1.2.3.4]:80", "not an IP address"),
            (
                "bind 127.0.0.1\n    listen 10.0.0.1:8080",
                "different interface",
            ),
        ] {
            let error = refusal(body);
            assert!(error.contains(needle), "{body}: {error}");
        }
    }

    /// 🎧 A site whose `listen` named its interface keeps it under
    /// `default_bind`, which only fills in for sites that said nothing.
    #[test]
    fn listen_with_an_interface_is_not_moved_by_default_bind() {
        let config = compile(
            "{\n    default_bind 10.0.0.1\n}\n\
             x.test {\n    listen 127.0.0.1:8080\n    respond \"x\"\n}\n\
             y.test {\n    listen :9090\n    respond \"y\"\n}\n",
        )
        .expect("compiles");
        let listens: Vec<Vec<String>> = config
            .servers
            .iter()
            .map(|server| server.listen.clone())
            .collect();
        assert_eq!(
            listens,
            vec![
                vec!["127.0.0.1:8080".to_string()],
                vec!["10.0.0.1:9090".to_string()]
            ]
        );
    }

    /// 📍 `bind` agreeing with `listen`, in either order, is no contradiction.
    #[test]
    fn listen_matching_bind_is_accepted() {
        assert_eq!(
            listens("listen [::1]:8080\n    bind ::1"),
            vec!["[::1]:8080".to_string()]
        );
    }
}
