// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔀 One route, one reverse proxy.
//!
//! The plain idea: the runtime keeps one upstream pool and one proxy policy per
//! route, found by walking the route's handler tree to its first
//! `reverse_proxy`. A route that holds two proxies therefore sends every
//! request it proxies to the first one.
//!
//! 🤡 That is exactly what a Pingclairfile like this did:
//!
//! ```text
//! route {
//!     handle /mcp     { reverse_proxy worker:443 }
//!     handle /install { reverse_proxy releases:443 }
//! }
//! ```
//!
//! `/install` reached `worker`, with `worker`'s headers and TLS name. Top-level
//! `handle` blocks were never affected, because each one already compiles to a
//! route of its own. pingclair.com's own configuration hit this on 2026-10-12.
//!
//! The fix keeps the runtime's model and makes the configuration fit it: a
//! route whose handler is a group of mutually exclusive branches — `route` or
//! `handle` around `handle` blocks — is split into one route per branch, in
//! the same order, each matching `route condition AND branch condition`. The
//! first branch that matches still answers. When no branch matches, the
//! request carries on to the routes after them, which is how upstream treats a
//! `route` block too.
//!
//! 🛡️ A route that still holds more than one proxy after that — a shape this
//! cannot split without changing what runs first — is refused by
//! [`refuse_shared_proxy_routes`], on every configuration path, rather than
//! loaded and misrouted.
//!
//! 📌 Load path only. Nothing here runs per request.

use crate::compiler::{CompileError, CompileResult};
use pingclair_core::config::{
    HandlerConfig, HandlerElement, Matcher, PingclairConfig, RouteConfig,
};

/// 🔢 How many proxies a handler tree holds, counted the way the runtime
/// finds them: through pipelines, first-match groups and `handle_path`.
/// Subrequest proxies (`forward_auth`) are part of another handler and do not
/// own the route's pool.
fn proxies(handler: &HandlerConfig) -> usize {
    match handler {
        HandlerConfig::ReverseProxy(config) if config.subrequest.is_none() => 1,
        HandlerConfig::Pipeline { handlers }
        | HandlerConfig::FirstMatch { handlers }
        | HandlerConfig::HandlePath { handlers, .. } => handlers
            .iter()
            .map(|element| proxies(&element.handler))
            .sum(),
        _ => 0,
    }
}

/// 🧩 The branches of a route that is nothing but one group of mutually
/// exclusive blocks: a first-match group, alone or as a pipeline's only,
/// unconditional element.
fn exclusive_branches(handler: &HandlerConfig) -> Option<&[HandlerElement]> {
    match handler {
        HandlerConfig::FirstMatch { handlers } => Some(handlers),
        HandlerConfig::Pipeline { handlers } => match handlers.as_slice() {
            [only] if only.matcher.is_none() => exclusive_branches(&only.handler),
            _ => None,
        },
        _ => None,
    }
}

/// 🔀 Splits every route that holds several proxies in exclusive branches
/// into one route per branch, keeping their order.
pub(crate) fn split_proxy_routes(routes: Vec<RouteConfig>) -> Vec<RouteConfig> {
    let mut split = Vec::with_capacity(routes.len());
    for route in routes {
        push_split(route, &mut split);
    }
    split
}

fn push_split(route: RouteConfig, into: &mut Vec<RouteConfig>) {
    let Some(branches) = exclusive_branches(&route.handler).filter(|_| proxies(&route.handler) > 1)
    else {
        into.push(route);
        return;
    };
    for branch in branches.iter().cloned() {
        // 🔁 A branch can hold a group of its own (`handle` inside `handle`).
        push_split(
            RouteConfig {
                path: route.path.clone(),
                handler: branch.handler,
                methods: route.methods.clone(),
                matcher: both(route.matcher.clone(), branch.matcher),
            },
            into,
        );
    }
}

/// 🤝 The condition of a branch inside a route: the route's and its own.
fn both(route: Option<Matcher>, branch: Option<Matcher>) -> Option<Matcher> {
    match (route, branch) {
        (Some(route), Some(branch)) => Some(Matcher::And(Box::new(route), Box::new(branch))),
        (route, branch) => route.or(branch),
    }
}

/// 🛡️ Refuses a route that would send every proxied request to its first
/// proxy. Runs in `validate_config`, so JSON and the Admin API meet it too.
pub(crate) fn refuse_shared_proxy_routes(config: &PingclairConfig) -> CompileResult<()> {
    for server in &config.servers {
        for route in &server.routes {
            let count = proxies(&route.handler);
            if count > 1 {
                let site = server.name.as_deref().unwrap_or("a site");
                return Err(CompileError::InvalidServer {
                    message: format!(
                        "{site}: the route for `{}` holds {count} reverse proxies, and one route \
                         sends every proxied request to its first proxy. Give each \
                         `reverse_proxy` its own `handle` block",
                        route.path
                    ),
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use pingclair_core::config::{HandlerConfig, Matcher};

    /// 🧪 The first proxy's first upstream.
    fn first_upstream(handler: &HandlerConfig) -> Option<String> {
        match handler {
            HandlerConfig::ReverseProxy(config) => config.upstreams.first().cloned(),
            HandlerConfig::Pipeline { handlers }
            | HandlerConfig::FirstMatch { handlers }
            | HandlerConfig::HandlePath { handlers, .. } => handlers
                .iter()
                .find_map(|element| first_upstream(&element.handler)),
            _ => None,
        }
    }

    fn upstreams(source: &str) -> Vec<(Option<Matcher>, String)> {
        crate::compile(source).expect("compiles").servers[0]
            .routes
            .iter()
            .map(|route| {
                let upstream = first_upstream(&route.handler).unwrap_or_default();
                (route.matcher.clone(), upstream)
            })
            .collect()
    }

    fn path(pattern: &str) -> Matcher {
        Matcher::Path {
            patterns: vec![pattern.to_string()],
        }
    }

    /// 🔀 Each `handle` in a `route` gets a route, and so its own proxy.
    #[test]
    fn handles_inside_a_route_block_become_one_route_each() {
        let routes = upstreams(
            ":8080 {\n\troute {\n\t\thandle /a {\n\t\t\treverse_proxy 127.0.0.1:9001\n\t\t}\n\
             \t\thandle /b {\n\t\t\treverse_proxy 127.0.0.1:9002\n\t\t}\n\t}\n}\n",
        );
        assert_eq!(
            routes,
            [
                (Some(path("/a")), "127.0.0.1:9001".to_string()),
                (Some(path("/b")), "127.0.0.1:9002".to_string()),
            ]
        );
    }

    /// 🔁 A `handle` nested in a `handle` keeps both conditions.
    #[test]
    fn nested_handles_keep_the_outer_condition() {
        let routes = upstreams(
            ":8080 {\n\thandle /api/* {\n\t\thandle /api/a {\n\t\t\treverse_proxy 127.0.0.1:9001\n\t\t}\n\
             \t\thandle {\n\t\t\treverse_proxy 127.0.0.1:9002\n\t\t}\n\t}\n}\n",
        );
        assert_eq!(routes.len(), 2, "{routes:?}");
        assert_eq!(routes[0].1, "127.0.0.1:9001");
        assert!(matches!(&routes[0].0, Some(Matcher::And(..))), "{routes:?}");
        assert_eq!(routes[1].1, "127.0.0.1:9002");
    }

    /// 👍 A route with one proxy is left exactly as it was.
    #[test]
    fn a_single_proxy_route_is_untouched() {
        let routes = upstreams(
            ":8080 {\n\troute {\n\t\theader X-A 1\n\t\treverse_proxy 127.0.0.1:9001\n\t}\n}\n",
        );
        assert_eq!(routes.len(), 1);
        assert!(matches!(
            crate::compile(
                ":8080 {\n\troute {\n\t\theader X-A 1\n\t\treverse_proxy 127.0.0.1:9001\n\t}\n}\n"
            )
            .unwrap()
            .servers[0]
                .routes[0]
                .handler,
            HandlerConfig::Pipeline { .. }
        ));
    }

    /// 🛡️ A shape that cannot be split is refused instead of misrouted.
    #[test]
    fn an_unsplittable_shared_route_is_refused() {
        let error = crate::compile(
            ":8080 {\n\troute {\n\t\theader X-A 1\n\t\thandle /a {\n\t\t\treverse_proxy 127.0.0.1:9001\n\t\t}\n\
             \t\thandle /b {\n\t\t\treverse_proxy 127.0.0.1:9002\n\t\t}\n\t}\n}\n",
        )
        .expect_err("two proxies behind a shared middleware cannot be split")
        .to_string();
        assert!(error.contains("holds 2 reverse proxies"), "{error}");
    }
}
