// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧪 Regressions in configuration precomputation, reload state, route
//! protection and request rewriting, each pinned at the unit level.

use super::*;
use crate::http_policy::authority_host;
use std::collections::BTreeMap;
use std::sync::Barrier;
use std::sync::atomic::{AtomicUsize, Ordering};

fn protected_server(max_in_flight: usize) -> ServerConfig {
    let proxy = ReverseProxyConfig {
        upstreams: vec!["127.0.0.1:9000".to_string()],
        overload: Box::new(pingclair_core::config::OverloadConfig {
            max_in_flight: Some(max_in_flight),
            ..Default::default()
        }),
        circuit_breaker: Box::new(pingclair_core::config::CircuitBreakerConfig {
            consecutive_failures: Some(2),
            ..Default::default()
        }),
        ..Default::default()
    };
    ServerConfig {
        name: Some("reload.example".to_string()),
        routes: vec![pingclair_core::config::RouteConfig {
            path: "/api/*".to_string(),
            handler: HandlerConfig::ReverseProxy(Box::new(proxy)),
            methods: None,
            matcher: None,
        }],
        ..ServerConfig::default()
    }
}

/// 🧭 Original-URI variables cost owned map entries only for a site that
/// can observe them. Missing a real reference would change a rewrite or
/// response; treating ordinary text as a reference only gives up the fast
/// path, which is the deliberately conservative failure mode.
#[test]
fn original_uri_variables_are_precomputed_from_configuration() {
    let mut config = ServerConfig {
        routes: vec![pingclair_core::config::RouteConfig {
            path: "/*".to_string(),
            handler: HandlerConfig::Respond {
                status: 200,
                body: Some("ordinary response".to_string()),
                headers: BTreeMap::new(),
            },
            methods: None,
            matcher: None,
        }],
        ..ServerConfig::default()
    };

    assert!(
        !ProxyState::new(config.clone()).needs_original_uri_vars,
        "a site without original-URI placeholders keeps the allocation-free path"
    );

    let HandlerConfig::Respond { body, .. } = &mut config.routes[0].handler else {
        unreachable!("the fixture is a respond handler")
    };
    *body = Some("arrived as {http.request.orig_uri.path}".to_string());
    assert!(
        ProxyState::new(config).needs_original_uri_vars,
        "a reachable placeholder must retain the original-URI map entries"
    );
}

#[test]
fn hot_reload_retains_only_compatible_route_protection_state() {
    let proxy = PingclairProxy::new();
    proxy.add_server(protected_server(2));
    let before = proxy.get_state("reload.example").unwrap().route_protections[0]
        .as_ref()
        .unwrap()
        .clone();

    proxy.update_config(vec![protected_server(2)]);
    let retained = proxy.get_state("reload.example").unwrap().route_protections[0]
        .as_ref()
        .unwrap()
        .clone();
    assert!(Arc::ptr_eq(&before, &retained));

    proxy.update_config(vec![protected_server(3)]);
    let replaced = proxy.get_state("reload.example").unwrap().route_protections[0]
        .as_ref()
        .unwrap()
        .clone();
    assert!(!Arc::ptr_eq(&retained, &replaced));
}

/// 🍪 A cookie split across field lines is rejoined before it leaves for an
/// HTTP/1 upstream.
///
/// 🤡 This was fixed on HTTP/3 first and only there, which is exactly the
/// shape this repository keeps finding: RFC 9113 §8.2.3 says the same thing
/// about HTTP/2 that RFC 9114 §4.2.1 says about HTTP/3, word for word — the
/// pieces MUST be joined with `"; "` before the request reaches a context
/// that is neither. Measured on a public host after the HTTP/3 fix shipped:
/// the origin still received three separate `Cookie` lines from an HTTP/2
/// client.
#[test]
fn a_split_cookie_is_rejoined_on_http2() {
    let mut h2 = RequestHeader::build_no_case("GET", b"/", None).unwrap();
    h2.set_version(http::Version::HTTP_2);
    h2.set_uri("https://shop.example/".parse().unwrap());
    for piece in ["a=1", "b=2", "c=3"] {
        h2.append_header(http::header::COOKIE, piece).unwrap();
    }

    PingclairProxy::join_split_cookies(&mut h2);

    assert_eq!(h2.headers.get_all(http::header::COOKIE).iter().count(), 1);
    assert_eq!(
        h2.headers.get(http::header::COOKIE).map(|v| v.as_bytes()),
        Some(b"a=1; b=2; c=3".as_slice())
    );
}

/// 📌 HTTP/1.1 is left alone. A client that sent three lines over HTTP/1.1
/// really did send three, and forwarding them unchanged is faithful; the
/// rule that requires joining is about what HTTP/2 and HTTP/3 do to a
/// header, not about what an origin may receive.
#[test]
fn an_http1_request_keeps_the_lines_it_sent() {
    let mut h1 = RequestHeader::build("GET", b"/", None).unwrap();
    for piece in ["a=1", "b=2"] {
        h1.append_header(http::header::COOKIE, piece).unwrap();
    }

    PingclairProxy::join_split_cookies(&mut h1);

    assert_eq!(h1.headers.get_all(http::header::COOKIE).iter().count(), 2);
}

/// 🌐 Rewriting the path must not lose the site the request is for.
///
/// 🤡 It did, on HTTP/2 only. `set_raw_path` replaces the whole URI with a
/// path-only one, and HTTP/2 keeps the site name *in* the URI — so a route
/// with `uri strip_prefix` threw it away, and because HTTP/2 sends no
/// `Host` header there was nothing to fall back to. Measured on a public
/// host: the origin received a literal `Host:` with no value, while the
/// identical request over HTTP/1.1 and HTTP/3 carried the right name.
///
/// 📌 The fix is the one HTTP/3 already had: write the name into a header
/// before anything reshapes the URI, so the two places it can live cannot
/// disagree and a URI rewrite cannot erase it.
#[test]
fn a_uri_rewrite_keeps_the_site_the_request_named() {
    // 🌐 An HTTP/2 request as Pingora builds it: authority in the URI, no
    // `Host` header at all.
    let mut h2 = RequestHeader::build_no_case("GET", b"/strip/thing", None).unwrap();
    h2.set_uri("https://shop.example.test/strip/thing".parse().unwrap());

    PingclairProxy::pin_request_authority(&mut h2);
    h2.set_raw_path(b"/thing").unwrap();

    assert_eq!(
        crate::http_policy::request_authority(&h2),
        "shop.example.test",
        "the site name must survive a path rewrite"
    );
}

/// 🌐 The placeholders that name the site must give the same answer on
/// HTTP/2 as on HTTP/1.1.
///
/// 🤡 They did not. HTTP/2 carries the site name in `:authority`, which
/// Pingora keeps in the URI and does *not* copy into a `Host` header, and
/// every one of these read that header directly — so `{host}` resolved to
/// the empty string for the transport browsers actually use by default.
/// Measured on a public host: `redir https://{host}/landing` answered
/// `Location: https:///landing`, which no browser follows.
///
/// `{uri}` was the same mistake from the other side: rendering the whole
/// URI gives back the scheme and authority that HTTP/2 put there, where
/// HTTP/1.1 has only the path.
#[test]
fn site_placeholders_agree_across_http1_and_http2() {
    let vars = crate::http_policy::RequestVars::default();

    let mut h1 = RequestHeader::build("GET", b"/landing?a=1", None).unwrap();
    h1.insert_header(http::header::HOST, "api.example.com:8443")
        .unwrap();

    // 🌐 What an HTTP/2 request actually looks like once Pingora has built
    // it: authority in the URI, no `Host` header at all.
    let mut h2 = RequestHeader::build_no_case("GET", b"/landing?a=1", None).unwrap();
    h2.set_uri("https://api.example.com:8443/landing?a=1".parse().unwrap());

    for placeholder in [
        "{host}",
        "{http.request.host}",
        "{hostport}",
        "{port}",
        "{labels.0}",
        "{uri}",
        "{path}",
        "{query}",
    ] {
        let over_h1 = resolve_caddy_placeholders(placeholder, &h1, None, "https", &vars);
        let over_h2 = resolve_caddy_placeholders(placeholder, &h2, None, "https", &vars);
        assert_eq!(
            over_h1, over_h2,
            "{placeholder} differs between HTTP/1.1 and HTTP/2"
        );
        assert!(
            !over_h1.is_empty(),
            "{placeholder} resolved to nothing on both transports, so the \
                 comparison above proves nothing"
        );
    }

    // 📌 The concrete failure that started this, pinned by value rather
    // than only by agreement.
    assert_eq!(
        resolve_caddy_placeholders("https://{host}/landing", &h2, None, "https", &vars),
        "https://api.example.com/landing"
    );
    assert_eq!(
        resolve_caddy_placeholders("{uri}", &h2, None, "https", &vars),
        "/landing?a=1"
    );
}

/// 📂 Two responses asking for the same file server get the same one.
///
/// 🤡 They used to get one each, built and thrown away per response. The
/// construction is cheap; the caches it carries are the point, and starting
/// them empty every time meant a custom error page recomputed its content
/// type, `ETag` and `Last-Modified` for every response — and, with
/// `compress` on, deflated the same file again each time.
#[test]
fn a_response_file_server_is_built_once_per_configuration() {
    let state = ProxyState::new(ServerConfig::default());
    let wanted = crate::http_policy::ResponseFileServer {
        root: "/srv/errors".to_string(),
        index: vec!["index.html".to_string()],
        browse: false,
        browse_limit: None,
        compress: true,
    };

    let first = state.response_file_server(&wanted, "/srv/errors");
    let second = state.response_file_server(&wanted, "/srv/errors");
    assert!(
        Arc::ptr_eq(&first, &second),
        "the same configuration must yield the same file server, caches and all"
    );

    // 🔀 A different configuration is a different server, or one of them
    // would be serving from the wrong root.
    let elsewhere = crate::http_policy::ResponseFileServer {
        root: "/srv/other".to_string(),
        ..wanted.clone()
    };
    assert!(!Arc::ptr_eq(
        &first,
        &state.response_file_server(&elsewhere, "/srv/other")
    ));
}

/// 🚫 A root that came from `{http.vars.root}` is never remembered.
///
/// That value can be assembled from the request, so keying a map on it is
/// how a cache becomes a way to grow this process without bound — the same
/// shape as the metrics label this repository already had to cap.
#[test]
fn a_request_derived_root_is_not_cached() {
    let state = ProxyState::new(ServerConfig::default());
    let wanted = crate::http_policy::ResponseFileServer {
        root: ".".to_string(),
        index: vec![],
        browse: false,
        browse_limit: None,
        compress: false,
    };

    let first = state.response_file_server(&wanted, "/srv/from-vars");
    let second = state.response_file_server(&wanted, "/srv/from-vars");
    assert!(
        !Arc::ptr_eq(&first, &second),
        "a `.` root resolves per request and must not be keyed on"
    );
    assert!(
        state
            .response_file_servers
            .lock()
            .expect("uncontended")
            .is_empty(),
        "nothing derived from the request may enter the map"
    );
}

#[test]
fn authority_host_supports_bracketed_ipv6() {
    assert_eq!(authority_host("[2001:db8::1]:443"), "2001:db8::1");
}

// ---- Fix 1: streaming compression stays bounded regardless of body size
//
// The regression tests for this moved to `crate::encoding` when the
// encoder became multi-coding; they now assert the same bound for gzip
// *and* zstd. See `encoding::tests::memory_stays_bounded_by_chunk_size_
// not_body_size`.

// ---- Fix 2: request ID generation is syscall-free per request ----

#[test]
fn request_ids_are_unique_across_many_sequential_calls() {
    let mut ids = std::collections::HashSet::new();
    for _ in 0..100_000 {
        assert!(
            ids.insert(generate_request_id()),
            "duplicate request ID generated"
        );
    }
}

#[test]
fn request_ids_are_unique_under_concurrent_generation() {
    // The counter is a shared static AtomicU64; this is the test that
    // would catch a race in the fix (e.g. non-atomic increment).
    let thread_count = 16;
    let per_thread = 5_000;
    let barrier = Arc::new(Barrier::new(thread_count));

    let handles: Vec<_> = (0..thread_count)
        .map(|_| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                (0..per_thread)
                    .map(|_| generate_request_id())
                    .collect::<Vec<_>>()
            })
        })
        .collect();

    let mut all_ids = std::collections::HashSet::new();
    for h in handles {
        for id in h.join().unwrap() {
            assert!(all_ids.insert(id), "duplicate request ID across threads");
        }
    }
    assert_eq!(all_ids.len(), thread_count * per_thread);
}

#[test]
fn request_id_format_is_stable_and_sortable_within_epoch() {
    let a = generate_request_id();
    let b = generate_request_id();
    assert!(a.contains('-'), "expected `<epoch>-<seq>` format, got {a}");
    let (epoch_a, seq_a) = a.split_once('-').unwrap();
    let (epoch_b, seq_b) = b.split_once('-').unwrap();
    // Same process epoch for two calls made back-to-back.
    assert_eq!(epoch_a, epoch_b);
    let seq_a = u64::from_str_radix(seq_a, 16).unwrap();
    let seq_b = u64::from_str_radix(seq_b, 16).unwrap();
    assert!(seq_b > seq_a, "sequence should be monotonically increasing");
}

#[test]
fn sanitize_request_id_accepts_typical_values() {
    assert_eq!(
        sanitize_request_id("abc-123_DEF.456"),
        Some("abc-123_DEF.456".to_string())
    );
    assert_eq!(
        sanitize_request_id("  padded  "),
        Some("padded".to_string())
    );
}

#[test]
fn sanitize_request_id_rejects_unsafe_values() {
    // Empty / whitespace-only
    assert_eq!(sanitize_request_id(""), None);
    assert_eq!(sanitize_request_id("   "), None);
    // CR/LF header-smuggling attempts
    assert_eq!(sanitize_request_id("ok\r\nX-Injected: evil"), None);
    assert_eq!(sanitize_request_id("ok\nbad"), None);
    // Non-ASCII
    assert_eq!(sanitize_request_id("要求-123"), None);
    // Overlong
    assert_eq!(sanitize_request_id(&"a".repeat(129)), None);
    assert!(sanitize_request_id(&"a".repeat(128)).is_some());
}

// ---- Fix 3: hosts/default reads never contend with reloads ----

fn minimal_server_config(name: &str) -> ServerConfig {
    ServerConfig {
        name: Some(name.to_string()),
        ..Default::default()
    }
}

#[test]
fn get_state_resolves_exact_host_after_add_server() {
    let proxy = PingclairProxy::new();
    assert!(proxy.get_state("api.example.com").is_none());

    proxy.add_server(minimal_server_config("api.example.com"));
    assert!(proxy.get_state("api.example.com").is_some());
    assert!(proxy.get_state("other.example.com").is_none());
}

// MARK: - Virtual-host name canonicalization

/// 🏠 A site answers to its own name however the client spells it.
///
/// The consequence of getting this wrong is not "no match" — it is
/// **the wrong match**. A miss falls through to the catch-all, so a request
/// for a protected site with one capital letter in the `Host` header used to
/// be served by whatever the permissive default site allows.
///
/// Both directions are asserted: the configured name is spelled unusually in
/// one case and the request is in the other, because canonicalizing only one
/// side looks correct from whichever end somebody happened to test.
#[test]
fn a_site_answers_to_its_name_however_it_is_spelled() {
    let proxy = PingclairProxy::new();
    proxy.add_server(minimal_server_config("api.example.com"));

    for spelling in [
        "api.example.com",
        "API.EXAMPLE.COM",
        "Api.Example.Com",
        "api.example.com.",
        "API.Example.com.",
    ] {
        assert!(
            proxy.get_state(spelling).is_some(),
            "`{spelling}` did not reach its own site"
        );
    }

    // 🔤 And with the *configuration* spelled unusually instead.
    let shouty = PingclairProxy::new();
    shouty.add_server(minimal_server_config("API.Example.COM."));
    assert!(shouty.get_state("api.example.com").is_some());
    assert!(shouty.get_state("API.EXAMPLE.COM").is_some());

    // 🧭 Still no accidental matches.
    assert!(proxy.get_state("other.example.com").is_none());
    assert!(proxy.get_state("api.example.com.evil.test").is_none());
}

/// 🕳️ A miss lands on the catch-all, which is exactly why a miss must be a
/// real miss.
///
/// The test that makes the bug visible rather than merely absent: with a
/// catch-all registered, a case-sensitive lookup does not fail loudly, it
/// silently serves the wrong site's configuration.
#[test]
fn a_differently_spelled_host_does_not_fall_through_to_the_catch_all() {
    let proxy = PingclairProxy::new();
    proxy.add_server(minimal_server_config("secure.example.com"));
    proxy.add_server(minimal_server_config("_"));

    let secure = proxy.get_state("secure.example.com").expect("named site");
    let shouted = proxy.get_state("SECURE.EXAMPLE.COM").expect("catch-all");
    assert!(
        Arc::ptr_eq(&secure, &shouted),
        "a capital letter in Host moved the request to a different site"
    );

    let dotted = proxy.get_state("secure.example.com.").expect("catch-all");
    assert!(
        Arc::ptr_eq(&secure, &dotted),
        "a fully qualified Host moved the request to a different site"
    );

    // 🧭 A genuinely different name still reaches the catch-all, so the
    // assertions above are about spelling and not about the catch-all being
    // unreachable.
    let stranger = proxy.get_state("stranger.test").expect("catch-all");
    assert!(!Arc::ptr_eq(&secure, &stranger));
}

/// 🃏 A wildcard site covers one label, whatever the case.
#[test]
fn wildcard_sites_cover_one_label_in_any_case() {
    let proxy = PingclairProxy::new();
    proxy.add_server(minimal_server_config("*.example.com"));

    assert!(proxy.get_state("a.example.com").is_some());
    assert!(proxy.get_state("A.EXAMPLE.COM").is_some());
    assert!(proxy.get_state("a.example.com.").is_some());
    // 🧭 Two labels deep is not covered by a wildcard certificate, so it is
    // not covered here either — and with no catch-all registered that is
    // visible as a miss.
    assert!(proxy.get_state("a.b.example.com").is_none());
    assert!(proxy.get_state("example.com").is_none());
}

/// 🔢 Address literals are hosts too, and they must keep working.
///
/// A request to a bare IP has an authority with no name to fold, and an IPv6
/// literal arrives bracketed with hex that may be upper or lower case.
#[test]
fn address_literal_hosts_still_resolve() {
    let proxy = PingclairProxy::new();
    proxy.add_server(minimal_server_config("192.0.2.7"));
    proxy.add_server(minimal_server_config("2001:db8::1"));

    assert!(proxy.get_state("192.0.2.7").is_some());
    assert!(proxy.get_state("2001:db8::1").is_some());
    assert!(
        proxy.get_state("2001:DB8::1").is_some(),
        "an IPv6 literal's hex digits are case-insensitive too"
    );
}

#[test]
fn get_state_reuses_the_published_snapshot() {
    let proxy = PingclairProxy::new();
    proxy.add_server(minimal_server_config("api.example.com"));

    let first = proxy.get_state("api.example.com").unwrap();
    let second = proxy.get_state("api.example.com").unwrap();

    assert!(Arc::ptr_eq(&first, &second));
}

#[test]
fn get_state_falls_back_to_wildcard_then_default() {
    let proxy = PingclairProxy::new();
    proxy.add_server(minimal_server_config("*.example.com"));
    assert!(proxy.get_state("foo.example.com").is_some());
    assert!(proxy.get_state("example.com").is_none()); // wildcard doesn't match bare domain

    proxy.add_server(minimal_server_config("_")); // catch-all
    assert!(proxy.get_state("totally-unrelated.test").is_some());
}

#[test]
fn update_config_atomically_replaces_the_whole_host_map() {
    let proxy = PingclairProxy::new();
    proxy.add_server(minimal_server_config("a.example.com"));
    proxy.add_server(minimal_server_config("b.example.com"));
    assert!(proxy.get_state("a.example.com").is_some());
    assert!(proxy.get_state("b.example.com").is_some());

    // Replace entirely with just one host — "a" should disappear.
    proxy.update_config(vec![minimal_server_config("b.example.com")]);
    assert!(proxy.get_state("a.example.com").is_none());
    assert!(proxy.get_state("b.example.com").is_some());
}

#[test]
fn listener_limits_include_the_default_virtual_host() {
    let proxy = PingclairProxy::new();
    let mut config = minimal_server_config("_");
    config.limits.header_timeout_ms = Some(200);
    config.limits.max_connections = Some(1);
    proxy.add_server(config);
    let limits = proxy.listener_limits();
    assert_eq!(limits.header_timeout_ms, Some(200));
    assert_eq!(limits.max_connections, Some(1));
}

#[test]
fn concurrent_add_server_calls_never_lose_entries() {
    // This is the test a naive `hosts.write(); *hosts = ...` swap (or a
    // non-retrying read-modify-write) would fail: under contention,
    // ArcSwap::rcu must retry rather than silently drop a racing
    // writer's insert.
    let proxy = Arc::new(PingclairProxy::new());
    let thread_count = 32;
    let barrier = Arc::new(Barrier::new(thread_count));

    let handles: Vec<_> = (0..thread_count)
        .map(|i| {
            let proxy = proxy.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                proxy.add_server(minimal_server_config(&format!("host-{i}.example.com")));
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }

    for i in 0..thread_count {
        assert!(
            proxy.get_state(&format!("host-{i}.example.com")).is_some(),
            "host-{i}.example.com was lost under concurrent add_server calls"
        );
    }
}

#[test]
fn concurrent_reads_never_observe_a_torn_or_panicking_state_during_reload() {
    // Readers must never block on, or be corrupted by, a concurrent
    // hot-reload. Hammer get_state from many threads while another
    // thread repeatedly calls update_config, and assert nothing panics
    // and every read is a fully-formed ProxyState or None.
    let proxy = Arc::new(PingclairProxy::new());
    proxy.add_server(minimal_server_config("stable.example.com"));

    let stop = Arc::new(AtomicUsize::new(0));
    let reload_count = 200;

    let writer = {
        let proxy = proxy.clone();
        let stop = stop.clone();
        std::thread::spawn(move || {
            for i in 0..reload_count {
                proxy.update_config(vec![
                    minimal_server_config("stable.example.com"),
                    minimal_server_config(&format!("churn-{i}.example.com")),
                ]);
            }
            stop.store(1, Ordering::Relaxed);
        })
    };

    let readers: Vec<_> = (0..8)
        .map(|_| {
            let proxy = proxy.clone();
            let stop = stop.clone();
            std::thread::spawn(move || {
                let mut observed_none_for_stable = false;
                while stop.load(Ordering::Relaxed) == 0 {
                    match proxy.get_state("stable.example.com") {
                        Some(state) => {
                            // A fully-formed ProxyState must have a
                            // router; this is what would look "torn"
                            // if we ever read across two different
                            // in-progress writes.
                            let _ = &state.router;
                        }
                        None => observed_none_for_stable = true,
                    }
                }
                observed_none_for_stable
            })
        })
        .collect();

    writer.join().unwrap();
    for r in readers {
        let saw_none = r.join().unwrap();
        // "stable.example.com" is present in every single update_config
        // call, so a correct implementation must never report it
        // missing to a reader.
        assert!(
            !saw_none,
            "reader observed stable host missing during reload — reload is not atomic per-map"
        );
    }

    assert!(proxy.get_state("stable.example.com").is_some());
}

// ---- Fix 4: upstream connection pool size is explicit, not implicit ----

#[test]
fn global_config_pool_size_defaults_to_none_and_round_trips() {
    use pingclair_core::config::GlobalConfig;

    let default_cfg = GlobalConfig::default();
    assert_eq!(
        default_cfg.upstream_keepalive_pool_size, None,
        "default must be None so main.rs falls back to Pingora's own default explicitly, \
             rather than us silently guessing a number"
    );

    let json =
        r#"{"email":null,"auto_https":"on","blocked_ips":[],"upstream_keepalive_pool_size":256}"#;
    let parsed: GlobalConfig = serde_json::from_str(json).unwrap();
    assert_eq!(parsed.upstream_keepalive_pool_size, Some(256));

    // Old configs saved before this field existed must still parse.
    let legacy_json = r#"{"email":null,"auto_https":"on","blocked_ips":[]}"#;
    let parsed_legacy: GlobalConfig = serde_json::from_str(legacy_json).unwrap();
    assert_eq!(parsed_legacy.upstream_keepalive_pool_size, None);
}
