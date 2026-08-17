// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔁 Bounded inline HTTP subrequests shared by every downstream transport.

use pingclair_core::config::{ForwardAuthConfig, ReverseProxyConfig};
use pingora_core::connectors::http::Connector;
use pingora_core::protocols::http::client::HttpSession;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_http::RequestHeader;

use crate::http_policy::RequestVars;
use crate::load_balancer::{LoadBalancer, Strategy, UpstreamEntry};
use crate::server::{PingclairProxy, peer_requires_h2_alpn, resolve_caddy_placeholders};
use crate::upstream::UpstreamSpec;

/// 🔁 A configuration-time parse of one inline proxy dial target.
pub(crate) struct PreparedSubrequest {
    source: String,
    spec: UpstreamSpec,
    pool: std::sync::Arc<LoadBalancer>,
    config: ReverseProxyConfig,
    /// 🔐 The compiled `upstream_tls` block, resolved at load exactly as a main
    /// reverse-proxy route's is.
    ///
    /// It has to be compiled and stored, not read from `config` per request:
    /// compiling means reading CA bundles and key pairs off disk, and doing that
    /// inside a request would put file I/O on the dial path and would report a
    /// missing certificate to a client rather than to the operator at load.
    /// Sharing [`RouteUpstreamTls`] with the main path is the point — an inline
    /// subrequest that carried its own idea of upstream TLS is how this came to
    /// accept the configuration and then ignore it.
    tls: crate::server::RouteUpstreamTls,
}

impl PreparedSubrequest {
    /// 🧭 Parses the dial policy before a request can reach the route.
    pub(crate) fn new(config: ReverseProxyConfig) -> Option<Self> {
        let source = config.upstreams.first()?.clone();
        let spec = UpstreamSpec::parse(&source)?;
        let pool = std::sync::Arc::new(LoadBalancer::from_entries(
            vec![UpstreamEntry {
                spec: spec.clone(),
                weight: 1,
            }],
            Vec::new(),
            Strategy::RoundRobin,
        ));
        crate::dns::register(&pool);
        // 🔐 The label reaches the operator's log, so it names the thing they
        // wrote rather than a route index they would have to count to.
        let tls = crate::server::compile_route_upstream_tls(
            &format!("subrequest -> {source}"),
            &config.upstream_tls,
        );
        Some(Self {
            spec,
            pool,
            source,
            config,
            tls,
        })
    }

    /// 🔐 The upstream TLS policy this exchange must dial under.
    ///
    /// `Err(())` means the configured material could not be loaded. There is
    /// deliberately no fallback: a subrequest told to pin a private CA or to
    /// present a client certificate, whose material is missing, must not quietly
    /// dial with system trust and no identity — that is exactly the connection
    /// the block was written to forbid. For a `forward_auth` exchange it is also
    /// the connection whose answer decides whether the request is allowed.
    fn tls_policy(&self) -> Result<Option<&std::sync::Arc<crate::upstream_tls::UpstreamTls>>, ()> {
        match &self.tls {
            crate::server::RouteUpstreamTls::Default => Ok(None),
            crate::server::RouteUpstreamTls::Compiled(policy) => Ok(Some(policy)),
            crate::server::RouteUpstreamTls::Broken => Err(()),
        }
    }

    /// 🎯 Reports whether this plan belongs to the normalized runtime handler.
    ///
    /// 🔐 `upstream_tls` is part of the comparison because it is part of what
    /// makes two exchanges different. Two inline subrequests on one route that
    /// differ only in their trust material would otherwise both match the first
    /// prepared plan, and the second would dial under the first one's policy.
    pub(crate) fn matches_reverse_proxy(&self, config: &ReverseProxyConfig) -> bool {
        self.config.upstreams == config.upstreams
            && self.config.rewrite_method == config.rewrite_method
            && self.config.rewrite_uri == config.rewrite_uri
            && self.config.headers_up == config.headers_up
            && self.config.subrequest == config.subrequest
            && self.config.upstream_tls == config.upstream_tls
    }

    /// 🔐 Matches legacy JSON without allocating its normalized replacement per request.
    pub(crate) fn matches_forward_auth(&self, config: &ForwardAuthConfig) -> bool {
        self.source == config.upstream
            && self.config.rewrite_method.as_deref() == Some("GET")
            && self.config.rewrite_uri.as_deref() == Some(config.uri.as_str())
            && self.config.subrequest.as_ref().is_some_and(|policy| {
                policy.continue_status_classes == [2] && policy.copy_headers == config.copy_headers
            })
    }
}

/// 🌊 A rejected subrequest whose response remains attached to its streaming session.
pub(crate) struct SubrequestResponse {
    pub(crate) session: HttpSession,
    pub(crate) peer: HttpPeer,
}

/// 🔀 The only two outcomes an inline subrequest exposes to a handler pipeline.
pub(crate) enum SubrequestOutcome {
    /// ▶️ The configured response class authorized the next handler.
    Continue,
    /// 🚫 The upstream response owns the downstream answer.
    Respond(Box<SubrequestResponse>),
}

/// 🔁 Executes one bodyless proxy exchange without buffering its response.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn execute(
    connector: &Connector,
    prepared: &PreparedSubrequest,
    request: &mut RequestHeader,
    verified_client_ip: Option<&str>,
    scheme: &'static str,
    request_vars: &RequestVars,
) -> Result<SubrequestOutcome, (u16, &'static str)> {
    let config = &prepared.config;
    let policy = config
        .subrequest
        .as_ref()
        .ok_or((500, "Missing Subrequest Policy"))?;
    let upstream = prepared
        .pool
        .select(None)
        .ok_or((502, "Subrequest Upstream Did Not Resolve"))?;
    // 🔐 Refused, not downgraded. The alternative to dialling under the
    // configured policy is not "dial without it" — it is "do not dial".
    let tls_policy = prepared.tls_policy().map_err(|()| {
        tracing::error!(
            upstream = %prepared.source,
            "🚫 Refusing an inline subrequest whose upstream TLS material failed to load"
        );
        (500, "Subrequest Upstream TLS Material Failed To Load")
    })?;
    let peer = PingclairProxy::build_http_peer(&upstream, Some(config), None, None, tls_policy)
        .map_err(|_| (500, "Subrequest Peer Configuration Error"))?;
    let (mut session, _reused) = connector.get_http_session(&peer).await.map_err(|error| {
        tracing::warn!(%error, "🔌 Subrequest upstream connection failed");
        (502, "Subrequest Upstream Connection Failed")
    })?;
    if peer_requires_h2_alpn(&peer) && !matches!(&session, HttpSession::H2(_)) {
        tracing::error!("🔒 Subrequest rejected a TLS upstream without h2 ALPN");
        session.shutdown().await;
        return Err((502, "Subrequest TLS H2 Negotiation Failed"));
    }

    let method = config
        .rewrite_method
        .as_deref()
        .unwrap_or(request.method.as_str());
    let uri_template = config
        .rewrite_uri
        .as_deref()
        .unwrap_or_else(|| request.uri.path());
    let uri = resolve_caddy_placeholders(
        uri_template,
        request,
        verified_client_ip,
        scheme,
        request_vars,
    );
    let mut outbound = RequestHeader::build(method, uri.as_bytes(), None)
        .map_err(|_| (400, "Invalid Subrequest Target"))?;
    outbound
        .insert_header("Host", prepared.spec.authority())
        .map_err(|_| (500, "Invalid Subrequest Host"))?;
    copy_end_to_end_headers(request, &mut outbound)?;
    for (name, template) in &config.headers_up {
        let resolved =
            resolve_caddy_placeholders(template, request, verified_client_ip, scheme, request_vars);
        outbound
            .insert_header(name.clone(), resolved.as_ref())
            .map_err(|_| (500, "Invalid Subrequest Request Header"))?;
    }

    session
        .write_request_header(Box::new(outbound))
        .await
        .map_err(|_| (502, "Subrequest Write Failed"))?;
    session
        .finish_request_body()
        .await
        .map_err(|_| (502, "Subrequest Write Failed"))?;
    session
        .read_response_header()
        .await
        .map_err(|_| (502, "Subrequest Read Failed"))?;
    let status = session
        .response_header()
        .map(|response| response.status.as_u16())
        .unwrap_or(502);
    let continues = policy.continue_status_classes.contains(&(status / 100));
    if !continues {
        return Ok(SubrequestOutcome::Respond(Box::new(SubrequestResponse {
            session,
            peer,
        })));
    }

    // 🔐 Delete every configured destination before considering the auth
    // response value, including renamed and missing fields.
    for mapping in &policy.copy_headers {
        let value = session
            .response_header()
            .and_then(|response| response.headers.get(&mapping.from))
            .filter(|value| !value.is_empty())
            .cloned();
        let destination = mapping.to.as_deref().unwrap_or(&mapping.from);
        request.remove_header(destination);
        if let Some(value) = value {
            request
                .insert_header(destination.to_string(), value)
                .map_err(|_| (500, "Invalid Subrequest Response Header"))?;
        }
    }

    // ♻️ A successful authorization response is hidden from the client, so
    // consume it before returning the connection to the shared pool.
    let mut clean = true;
    loop {
        match session.read_response_body().await {
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(error) => {
                tracing::debug!(%error, "🔌 Subrequest response drain failed");
                clean = false;
                break;
            }
        }
    }
    if clean && let HttpSession::H2(h2) = &mut session {
        clean = h2.read_trailers().await.is_ok();
    }
    if clean {
        connector.release_http_session(session, &peer, None).await;
    } else {
        session.shutdown().await;
    }
    Ok(SubrequestOutcome::Continue)
}

/// 🧹 Copies only end-to-end request fields into a bodyless subrequest.
///
/// 🛡️ The authorization service is a sink like any origin, and arguably a more
/// sensitive one: it exists to make a yes/no decision about this request, so a
/// field the client forged is a field the client got to vote with. The filter is
/// therefore the shared one — this function used to keep its own list, which
/// omitted the proxy credentials and the client's `Forwarded`.
fn copy_end_to_end_headers(
    source: &RequestHeader,
    destination: &mut RequestHeader,
) -> Result<(), (u16, &'static str)> {
    let filter = crate::http_policy::OutboundRequestFilter::for_client(&source.headers);
    for (name, value) in &source.headers {
        // 🧾 Framing fields, plus underscore-bearing names: a subrequest carries
        // no body, and an underscore alias can collide with a CGI variable at
        // whatever the auth service is built on.
        if name.as_str().contains('_')
            || matches!(
                name.as_str(),
                "host" | "transfer-encoding" | "trailer" | "content-length"
            )
        {
            continue;
        }
        if filter.blocks(name.as_str()) {
            continue;
        }
        destination
            .append_header(name.clone(), value.clone())
            .map_err(|_| (500, "Invalid Subrequest Request Header"))?;
    }
    Ok(())
}

/// 🧪 Keeps prepared-plan matching deterministic without opening a socket.
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn prepared_subrequest_distinguishes_policies_for_one_upstream() {
        let first = pingclair_core::config::ForwardAuthConfig {
            upstream: "http://127.0.0.1:9000".to_string(),
            uri: "/auth/first".to_string(),
            copy_headers: Vec::new(),
        };
        let second = pingclair_core::config::ForwardAuthConfig {
            uri: "/auth/second".to_string(),
            ..first.clone()
        };
        let normalized = first.as_reverse_proxy_subrequest();
        let plan = PreparedSubrequest::new(normalized.clone()).unwrap();

        assert!(plan.matches_reverse_proxy(&normalized));
        assert!(plan.matches_forward_auth(&first));
        assert!(!plan.matches_forward_auth(&second));
        assert!(!plan.matches_reverse_proxy(&second.as_reverse_proxy_subrequest()));
    }

    #[test]
    fn header_copy_strips_connection_named_and_underscore_fields() {
        let mut source = RequestHeader::build("POST", b"/private", None).unwrap();
        source.insert_header("Connection", "X-Hop").unwrap();
        source.insert_header("X-Hop", "secret").unwrap();
        source.insert_header("X_Gateway", "alias").unwrap();
        source.append_header("X-End", "one").unwrap();
        source.append_header("X-End", "two").unwrap();
        let mut destination = RequestHeader::build("GET", b"/auth", None).unwrap();

        copy_end_to_end_headers(&source, &mut destination).unwrap();

        assert!(!destination.headers.contains_key("x-hop"));
        assert!(!destination.headers.contains_key("x_gateway"));
        assert_eq!(destination.headers.get_all("x-end").iter().count(), 2);
    }

    /// 🔐 Two subrequests that differ only in their TLS policy are two plans.
    ///
    /// The prepared plan for a request is found by comparing it against the
    /// handler, and `upstream_tls` had been left out of that comparison. On a
    /// route with two inline subrequests to the same upstream — one pinning a
    /// private CA, one not — both would have matched the first plan, and the
    /// second would have dialled under a policy it was never given. Nothing else
    /// in the codebase notices, because the wrong plan still works.
    #[test]
    fn a_plan_is_not_reused_for_a_different_tls_policy() {
        use pingclair_core::config::{ReverseProxySubrequestConfig, UpstreamTlsConfig};

        let base = ReverseProxyConfig {
            upstreams: vec!["https://127.0.0.1:9443".to_string()],
            rewrite_method: Some("GET".to_string()),
            rewrite_uri: Some("/auth".to_string()),
            subrequest: Some(Box::new(ReverseProxySubrequestConfig {
                continue_status_classes: vec![2],
                ..Default::default()
            })),
            ..Default::default()
        };
        let pinned = ReverseProxyConfig {
            upstream_tls: Box::new(UpstreamTlsConfig {
                trusted_ca_certs: vec!["/etc/private-ca.pem".to_string()],
                ..Default::default()
            }),
            ..base.clone()
        };

        let plain_plan = PreparedSubrequest::new(base.clone()).expect("the plain plan prepares");
        assert!(plain_plan.matches_reverse_proxy(&base));
        assert!(
            !plain_plan.matches_reverse_proxy(&pinned),
            "a plan with no trust material answered for one that pins a CA"
        );

        // 🚫 The pinned plan's material does not exist, so it prepares but
        // refuses — the same fail-closed answer a main route gives.
        let pinned_plan = PreparedSubrequest::new(pinned.clone()).expect("the plan still prepares");
        assert!(pinned_plan.matches_reverse_proxy(&pinned));
        assert!(
            pinned_plan.tls_policy().is_err(),
            "missing trust material must refuse rather than fall back to system trust"
        );

        // 🧭 And a policy that loads cleanly resolves to an applied one, so the
        // assertion above is about the missing file and not about every policy
        // being rejected.
        let insecure = ReverseProxyConfig {
            upstream_tls: Box::new(UpstreamTlsConfig {
                server_name: Some("auth.internal".to_string()),
                ..Default::default()
            }),
            ..base.clone()
        };
        let insecure_plan = PreparedSubrequest::new(insecure).expect("plan");
        assert!(
            insecure_plan
                .tls_policy()
                .expect("a loadable policy resolves")
                .is_some(),
            "an SNI override must reach the dial as a compiled policy"
        );
    }

    /// 🛡️ The authorization service sees the same sanitized matrix every other
    /// sink sees.
    ///
    /// It is the sink where a forged field costs the most: the service exists to
    /// answer yes or no about this request, so anything the client can plant is
    /// something the client gets to vote with. This used to copy proxy
    /// credentials and the client's own `Forwarded` straight through.
    #[test]
    fn the_shared_matrix_reaches_the_authorization_service_sanitized() {
        let mut source = RequestHeader::build("POST", b"/private", None).unwrap();
        for (name, value, _) in crate::http_policy::SANITIZER_MATRIX {
            source.append_header(*name, *value).unwrap();
        }
        let mut destination = RequestHeader::build("GET", b"/auth", None).unwrap();

        copy_end_to_end_headers(&source, &mut destination).unwrap();

        for (name, _value, expect_blocked) in crate::http_policy::SANITIZER_MATRIX {
            assert_eq!(
                !destination.headers.contains_key(*name),
                *expect_blocked,
                "`{name}` reached the authorization service the wrong way"
            );
        }
    }

    #[tokio::test]
    async fn dropping_a_rejected_exchange_tears_down_the_upstream() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let upstream = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut chunk).await.unwrap();
                assert!(read > 0);
                request.extend_from_slice(&chunk[..read]);
            }
            stream
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 20971520\r\n\r\n")
                .await
                .unwrap();
            let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut chunk))
                .await
                .expect("dropping the exchange must close the upstream promptly");
            assert!(
                matches!(read, Ok(0))
                    || read
                        .as_ref()
                        .is_err_and(|error| error.kind() == std::io::ErrorKind::ConnectionReset)
            );
        });

        let legacy = pingclair_core::config::ForwardAuthConfig {
            upstream: format!("http://{address}"),
            uri: "/auth".to_string(),
            copy_headers: Vec::new(),
        };
        let config = legacy.as_reverse_proxy_subrequest();
        let prepared = PreparedSubrequest::new(config).unwrap();
        let connector = Connector::new(Some(pingora_core::connectors::ConnectorOptions::new(8)));
        let mut request = RequestHeader::build("GET", b"/private", None).unwrap();
        let outcome = execute(
            &connector,
            &prepared,
            &mut request,
            Some("127.0.0.1"),
            "http",
            &RequestVars::default(),
        )
        .await
        .unwrap();
        assert!(matches!(outcome, SubrequestOutcome::Respond(_)));
        drop(outcome);

        upstream.await.unwrap();
    }
}
