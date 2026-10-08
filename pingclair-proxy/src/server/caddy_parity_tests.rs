// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧭 Access control, upstream selection, transports and handler composition
//! compile to the behaviour each directive promises.

use super::*;
use crate::upstream::create_upstream;

#[test]
fn access_control_enforces_cidr_referer_and_user_agent_rules() {
    let policy = RouteAccessControl::from_config(&AccessControlConfig {
        allowed_ips: vec!["10.0.0.0/8".into()],
        denied_ips: vec!["10.1.2.3".into()],
        allowed_referers: vec!["*.trusted.example".into()],
        denied_referers: vec!["evil.trusted.example".into()],
        allowed_user_agents: vec!["^PingclairClient/".into()],
        denied_user_agents: vec!["(?i)bot".into()],
    });
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::REFERER,
        "https://app.trusted.example/page".parse().unwrap(),
    );
    headers.insert(
        http::header::USER_AGENT,
        "PingclairClient/1.0".parse().unwrap(),
    );
    assert!(policy.allowed_ips[0].contains(&"10.2.3.4".parse::<IpAddr>().unwrap()));
    assert_eq!(
        referer_host("https://app.trusted.example/page"),
        Some("app.trusted.example")
    );
    assert!(host_matches_rule(
        "app.trusted.example",
        "*.trusted.example"
    ));
    assert!(policy.allowed_user_agents[0].is_match("PingclairClient/1.0"));
    let ip: IpAddr = "10.2.3.4".parse().unwrap();
    assert!(
        !policy
            .denied_ips
            .iter()
            .any(|network| network.contains(&ip))
    );
    assert!(
        policy
            .allowed_ips
            .iter()
            .any(|network| network.contains(&ip))
    );
    assert!(
        !policy
            .denied_referers
            .iter()
            .any(|rule| host_matches_rule("app.trusted.example", rule))
    );
    assert!(
        policy
            .allowed_referers
            .iter()
            .any(|rule| host_matches_rule("app.trusted.example", rule))
    );
    assert!(
        !policy
            .denied_user_agents
            .iter()
            .any(|regex| regex.is_match("PingclairClient/1.0"))
    );
    assert!(policy.allows("10.2.3.4", &headers));

    assert!(!policy.allows("192.168.1.1", &headers));
    assert!(!policy.allows("10.1.2.3", &headers));
    headers.insert(
        http::header::REFERER,
        "https://evil.trusted.example/".parse().unwrap(),
    );
    assert!(!policy.allows("10.2.3.4", &headers));
    headers.insert(
        http::header::REFERER,
        "https://app.trusted.example/".parse().unwrap(),
    );
    headers.insert(
        http::header::USER_AGENT,
        "PingclairBot/1.0".parse().unwrap(),
    );
    assert!(!policy.allows("10.2.3.4", &headers));
}

#[test]
fn proxy_state_exposes_the_same_compiled_access_gate_to_every_protocol() {
    let access = AccessControlConfig {
        allowed_ips: vec!["10.0.0.0/8".into()],
        denied_ips: Vec::new(),
        allowed_referers: Vec::new(),
        denied_referers: Vec::new(),
        allowed_user_agents: Vec::new(),
        denied_user_agents: vec!["(?i)blockedbot".into()],
    };
    let state = ProxyState::new(ServerConfig {
        routes: vec![pingclair_core::config::RouteConfig {
            path: "/*".into(),
            handler: HandlerConfig::Pipeline {
                handlers: vec![
                    pingclair_core::config::HandlerElement::plain(HandlerConfig::AccessControl(
                        access,
                    )),
                    pingclair_core::config::HandlerElement::plain(HandlerConfig::Respond {
                        status: 200,
                        body: Some("ok".into()),
                        headers: BTreeMap::new(),
                    }),
                ],
            },
            methods: None,
            matcher: None,
        }],
        ..Default::default()
    });
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::USER_AGENT, "Browser/1.0".parse().unwrap());

    let verdict = |route: usize, ip: &str, headers: &http::HeaderMap| {
        let mut vars = BTreeMap::new();
        let mut request = MatcherRequest {
            path: "/",
            method: "GET",
            headers,
            host: "example.test",
            addresses: RequestAddresses {
                client_ip: None,
                remote_ip: None,
            },
            protocol: "http",
            vars: Some(&mut vars),
        };
        state.allows_access(route, ip, &mut request)
    };

    assert_eq!(verdict(0, "10.2.3.4", &headers), Ok(true));
    assert_eq!(verdict(0, "192.0.2.1", &headers), Ok(false));
    headers.insert(http::header::USER_AGENT, "BlockedBot/1.0".parse().unwrap());
    assert_eq!(verdict(0, "10.2.3.4", &headers), Ok(false));
    assert_eq!(verdict(99, "192.0.2.1", &headers), Ok(true));
}

#[test]
fn weighted_upstreams_set_native_weights_and_isolate_backups() {
    let config = ReverseProxyConfig {
        upstream_options: vec![
            pingclair_core::config::ProxyUpstream {
                address: "127.0.0.1:8301".into(),
                weight: 3,
                backup: false,
            },
            pingclair_core::config::ProxyUpstream {
                address: "127.0.0.1:8302".into(),
                weight: 2,
                backup: true,
            },
        ],
        ..Default::default()
    };
    let (primary, backup, templates) = build_weighted_upstreams(&config);
    assert!(templates.is_empty());
    assert_eq!(primary.len(), 1);
    assert_eq!(primary[0].spec.authority(), "127.0.0.1:8301");
    assert_eq!(primary[0].weight, 3);
    assert_eq!(backup.len(), 1);
    assert_eq!(backup[0].spec.authority(), "127.0.0.1:8302");
    assert_eq!(backup[0].weight, 2);

    // The weights must survive all the way into the built pool.
    let load_balancer = LoadBalancer::from_entries(primary, backup, Strategy::RoundRobin);
    let selected = load_balancer.select(None).unwrap();
    assert_eq!(selected.addr.to_string(), "127.0.0.1:8301");
    assert_eq!(selected.weight, 3);
}

/// ⚖️ FastCGI routes retain every upstream in the runtime selector.
#[test]
fn fastcgi_routes_select_all_configured_upstreams() {
    let state = ProxyState::new(ServerConfig {
        routes: vec![pingclair_core::config::RouteConfig {
            path: "/*".into(),
            handler: HandlerConfig::ReverseProxy(Box::new(ReverseProxyConfig {
                upstreams: vec!["127.0.0.1:8301".into(), "127.0.0.1:8302".into()],
                fastcgi: Some(Box::default()),
                ..Default::default()
            })),
            methods: None,
            matcher: None,
        }],
        ..Default::default()
    });
    let balancer = state.load_balancers[0]
        .as_ref()
        .expect("FastCGI route has a selector");

    let selected: Vec<String> = (0..4)
        .map(|_| balancer.select(None).unwrap().addr.to_string())
        .collect();
    assert_eq!(
        selected,
        [
            "127.0.0.1:8301",
            "127.0.0.1:8302",
            "127.0.0.1:8301",
            "127.0.0.1:8302",
        ]
    );
}

/// 🔢 `transport http { versions … }` reaches the peer, and changes the
/// pool group with it.
///
/// 🤡 This knob used to be parsed into an untyped map, kept in the compiled
/// configuration, warned about once at startup, and read by nothing. Typing
/// it would have been half a fix: the point is that the peer speaks what was
/// asked for.
///
/// The group key matters as much as the version. Two upstreams that differ
/// only in the versions they may speak must not share a pooled connection —
/// otherwise a route that asked for HTTP/1.1 is handed an HTTP/2 connection
/// somebody else opened.
#[test]
fn transport_versions_reach_the_peer_and_its_pool_group() {
    use pingclair_core::config::UpstreamHttpVersions as V;

    let proxy_with = |versions: Option<V>| pingclair_core::config::ReverseProxyConfig {
        upstreams: vec!["http://127.0.0.1:9000".to_string()],
        upstream_versions: versions,
        ..Default::default()
    };

    // 🧭 The scheme still decides when the transport says nothing.
    let upstream = create_upstream("http://127.0.0.1:9000").unwrap();
    let default = PingclairProxy::build_http_peer(&upstream, None, None, None, None).unwrap();
    assert_eq!(default.options.alpn.get_max_http_version(), 1);

    for (versions, min, max) in [(V::Http11, 1, 1), (V::H2, 2, 2), (V::H2AndHttp11, 1, 2)] {
        let config = proxy_with(Some(versions));
        let peer = PingclairProxy::build_http_peer(&upstream, Some(&config), None, None, None)
            .expect("peer builds");
        assert_eq!(
            peer.options.alpn.get_min_http_version(),
            min,
            "{versions:?} min"
        );
        assert_eq!(
            peer.options.alpn.get_max_http_version(),
            max,
            "{versions:?} max"
        );
    }

    // 🔁 Cleartext HTTP/2 is its own reuse group, not the HTTP/1.1 one.
    let h2 = PingclairProxy::build_http_peer(
        &upstream,
        Some(&proxy_with(Some(V::H2))),
        None,
        None,
        None,
    )
    .unwrap();
    let plain = PingclairProxy::build_http_peer(
        &upstream,
        Some(&proxy_with(Some(V::Http11))),
        None,
        None,
        None,
    )
    .unwrap();
    assert_ne!(
        h2.group_key, plain.group_key,
        "an HTTP/2 peer must not share a pool with an HTTP/1.1 one"
    );
}

#[test]
fn upstream_schemes_select_tls_and_http_versions() {
    for (address, tls, min_version, max_version, group_key) in [
        ("http://127.0.0.1:8301", false, 1, 1, 1),
        ("https://127.0.0.1:8302", true, 1, 2, 2),
        ("h2c://127.0.0.1:8303", false, 2, 2, 3),
        ("h2://127.0.0.1:8304", true, 2, 2, 4),
        ("unix//run/app.sock", false, 1, 1, 1),
        ("unix+h2c//run/grpc.sock", false, 2, 2, 3),
    ] {
        let upstream = create_upstream(address).unwrap();
        let peer = PingclairProxy::build_http_peer(&upstream, None, None, None, None)
            .expect("peer builds");

        assert_eq!(peer.is_tls(), tls);
        assert_eq!(
            peer.options.alpn.get_min_http_version(),
            min_version,
            "{address}"
        );
        assert_eq!(
            peer.options.alpn.get_max_http_version(),
            max_version,
            "{address}"
        );
        assert_eq!(peer.group_key, group_key);
        assert_eq!(
            peer_protocol_group(&peer),
            group_key,
            "a peer without a TLS policy must leave the group key unpacked: {address}"
        );
        assert_eq!(
            peer.options.upstream_tls_handshake_complete_hook.is_some(),
            group_key == 4,
            "{address}"
        );
    }
}

/// 🧪 Compiles a TLS policy from an in-memory configuration.
fn compile_tls(
    config: pingclair_core::config::UpstreamTlsConfig,
) -> Arc<crate::upstream_tls::UpstreamTls> {
    crate::upstream_tls::UpstreamTls::compile(&config)
        .expect("policy compiles")
        .expect("policy is a customisation")
}

#[test]
fn a_tls_policy_reaches_the_peer_without_disturbing_the_protocol_group() {
    // Setup scenarios
    let policy = compile_tls(pingclair_core::config::UpstreamTlsConfig {
        server_name: Some("internal.example".into()),
        ..Default::default()
    });
    let upstream = create_upstream("https://10.0.0.7:8443").unwrap();

    // Verification
    let peer = PingclairProxy::build_http_peer(&upstream, None, None, None, Some(&policy))
        .expect("peer builds");
    assert_eq!(peer.sni, "internal.example");
    assert_eq!(
        peer_protocol_group(&peer),
        PROTOCOL_GROUP_HTTPS,
        "packing the TLS identity must not change which protocol the peer speaks"
    );
    assert_ne!(
        peer.group_key, PROTOCOL_GROUP_HTTPS,
        "the TLS identity must actually be present in the group key"
    );
}

#[test]
fn different_trust_domains_do_not_share_a_connection_pool() {
    // Setup scenarios
    // Two routes reaching the same address with the same SNI, differing
    // only in the name they will accept. Pingora's own peer hash ignores
    // the CA bundle, so without the packed group key these would reuse
    // each other's connections.
    let upstream = create_upstream("https://10.0.0.7:8443").unwrap();
    let strict = compile_tls(pingclair_core::config::UpstreamTlsConfig {
        server_name: Some("strict.internal".into()),
        ..Default::default()
    });
    let other = compile_tls(pingclair_core::config::UpstreamTlsConfig {
        server_name: Some("other.internal".into()),
        ..Default::default()
    });

    // Verification
    let left = PingclairProxy::build_http_peer(&upstream, None, None, None, Some(&strict))
        .expect("peer builds");
    let right = PingclairProxy::build_http_peer(&upstream, None, None, None, Some(&other))
        .expect("peer builds");
    assert_ne!(left.group_key, right.group_key);
    assert_eq!(peer_protocol_group(&left), peer_protocol_group(&right));
}

#[test]
fn skipping_verification_reaches_both_peer_flags() {
    // Setup scenarios
    let policy = compile_tls(pingclair_core::config::UpstreamTlsConfig {
        insecure_skip_verify: true,
        ..Default::default()
    });
    let upstream = create_upstream("https://127.0.0.1:8443").unwrap();

    // Verification
    let peer = PingclairProxy::build_http_peer(&upstream, None, None, None, Some(&policy))
        .expect("peer builds");
    assert!(!peer.options.verify_cert);
    assert!(!peer.options.verify_hostname);
}

#[test]
fn a_bare_tls_directive_adds_encryption_without_widening_alpn() {
    // Setup scenarios
    let policy = compile_tls(pingclair_core::config::UpstreamTlsConfig {
        enable: true,
        ..Default::default()
    });
    let plain = create_upstream("127.0.0.1:8443").unwrap();
    let prior_knowledge_h2 = create_upstream("h2c://127.0.0.1:8443").unwrap();

    // Verification
    let upgraded = PingclairProxy::build_http_peer(&plain, None, None, None, Some(&policy))
        .expect("peer builds");
    assert!(
        upgraded.is_tls(),
        "`tls` must upgrade a scheme-less upstream"
    );
    assert_eq!(
        upgraded.options.alpn.get_max_http_version(),
        1,
        "`tls` must not silently start offering h2 to an HTTP/1.1 upstream"
    );
    assert_eq!(peer_protocol_group(&upgraded), PROTOCOL_GROUP_HTTPS);

    let untouched =
        PingclairProxy::build_http_peer(&prior_knowledge_h2, None, None, None, Some(&policy))
            .expect("peer builds");
    assert!(
        !untouched.is_tls(),
        "prior-knowledge h2c has no TLS form to be upgraded into"
    );
}

/// 🧪 Builds a one-route reverse-proxy server around a TLS block.
fn state_with_upstream_tls(tls: pingclair_core::config::UpstreamTlsConfig) -> ProxyState {
    ProxyState::new(ServerConfig {
        routes: vec![pingclair_core::config::RouteConfig {
            path: "/*".into(),
            handler: HandlerConfig::ReverseProxy(Box::new(ReverseProxyConfig {
                upstreams: vec!["https://127.0.0.1:8443".into()],
                upstream_tls: Box::new(tls),
                ..Default::default()
            })),
            methods: None,
            matcher: None,
        }],
        ..Default::default()
    })
}

#[test]
fn a_route_whose_trust_material_is_missing_refuses_instead_of_downgrading() {
    // Setup scenarios
    let state = state_with_upstream_tls(pingclair_core::config::UpstreamTlsConfig {
        trusted_ca_certs: vec!["/nonexistent/pingclair-day11-ca.pem".into()],
        ..Default::default()
    });

    // Verification
    assert!(
        state.upstream_tls_for(0).is_err(),
        "a route that could not load its trust roots must not fall back to system trust"
    );
}

#[test]
fn a_route_with_no_tls_block_keeps_the_shared_default() {
    // Setup scenarios
    let state = state_with_upstream_tls(pingclair_core::config::UpstreamTlsConfig::default());

    // Verification
    assert!(
        matches!(state.upstream_tls_for(0), Ok(None)),
        "an untouched route must not allocate per-route TLS state"
    );
}

#[test]
fn a_route_that_asked_for_an_sni_override_compiles_it() {
    // Setup scenarios
    let state = state_with_upstream_tls(pingclair_core::config::UpstreamTlsConfig {
        server_name: Some("origin.internal".into()),
        ..Default::default()
    });

    // Verification
    let policy = state
        .upstream_tls_for(0)
        .expect("policy loads")
        .expect("policy is a customisation");
    assert_eq!(policy.server_name(), Some("origin.internal"));
    assert!(policy.verifies());
}

#[test]
fn regex_rewrite_preserves_the_query_and_expands_captures() {
    let regex = Regex::new(r"^/api/(.*)$").unwrap();
    assert_eq!(
        rewrite_uri(
            "/api/users/42?verbose=1",
            None,
            None,
            None,
            Some(&regex),
            Some("/v1/$1"),
        ),
        "/v1/users/42?verbose=1",
    );
}

#[test]
fn upstream_timeout_policy_preserves_streaming_read_phases() {
    let spec = UpstreamSpec::parse("127.0.0.1:9000").unwrap();
    let upstream = spec.backend("127.0.0.1:9000".parse().unwrap(), 1).unwrap();
    let config = ReverseProxyConfig {
        connect_timeout: Some(100),
        first_byte_timeout: Some(200),
        between_reads_timeout: Some(300),
        write_timeout: Some(400),
        ..Default::default()
    };
    let peer = PingclairProxy::build_http_peer(
        &upstream,
        Some(&config),
        Some(Duration::from_millis(50)),
        Some(Duration::from_millis(60)),
        None,
    )
    .expect("peer builds");
    assert_eq!(
        peer.options.connection_timeout,
        Some(Duration::from_millis(50))
    );
    assert_eq!(
        peer.options.total_connection_timeout,
        Some(Duration::from_millis(50))
    );
    assert_eq!(peer.options.read_timeout, Some(Duration::from_millis(200)));
    assert_eq!(peer.options.write_timeout, Some(Duration::from_millis(50)));
}

#[test]
fn bandwidth_pacer_retains_only_counters() {
    let mut pacer = BandwidthPacer::new(1_000);
    let first = pacer.delay_for(500).expect("first chunk should be paced");
    assert!(first <= Duration::from_millis(500));
    pacer.started -= Duration::from_secs(2);
    assert_eq!(pacer.delay_for(500), None);
    assert_eq!(pacer.bytes, 1_000);
}
