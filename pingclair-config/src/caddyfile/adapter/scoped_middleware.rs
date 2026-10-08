// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🛡️ Middleware written with a matcher, composed into every route that can
//! answer a request it matches.
//!
//! The reference format runs a site as one chain: each directive in
//! directive order looks at the request, and the ones whose matcher matches
//! run. `basic_auth /secret` sorts ahead of `respond /secret`, so it asks for
//! credentials before the body is ever written.
//!
//! Our router does not run a chain. It picks the **first route that matches**
//! (issue #18) and runs only that route's handler. A guard like
//! `basic_auth /secret` does not answer by itself, so it is not a route that
//! can be picked on its own merit; if `respond /secret` is picked instead, the
//! guard never sees the request and an unauthenticated client reads the
//! protected body. That is the defect this module exists to close.
//!
//! 📌 So every middleware line is copied, at load, into each answering route
//! it should run ahead of, keeping its matcher as a step guard. Which routes
//! it reaches is decided here, once:
//!
//! - **Unmatched site middleware** (`header X-Site on`) goes ahead of an
//!   answering route when the directive order puts it first, exactly like a
//!   matched line. `redir`, which the order puts ahead of `basic_auth`,
//!   answers without asking for credentials whether or not either line
//!   carries a matcher — the site-wide guard used to be copied ahead of
//!   every route unconditionally, so the same URL was a 308 with no
//!   `basic_auth` and a 401 with one (#310).
//! - **Matched middleware** (`basic_auth /secret { … }`) goes ahead of an
//!   answering route when the directive order puts it first — a lower rank
//!   than the directive that answers. `redir`, which the order puts ahead of
//!   `basic_auth`, still redirects without asking for credentials, exactly as
//!   the reference does.
//! - **A matched middleware line's own route** — the route that catches the
//!   requests it matches and answers them through the site's fallback
//!   pipeline — runs every matched line, not only its own. Only one route
//!   answers a request, so when two lines match the same request, the route
//!   of the one sorted first used to be the only one that ran: a longer
//!   `header /admin/public …` sorted ahead of `basic_auth /admin/*` and
//!   answered without the guard.
//!
//! The matcher on each copied step is checked per request against a matcher
//! compiled at load, the same check a `handle` block already makes for its
//! own directives. A route's own line is copied without its matcher, since
//! the route only answers requests that already matched it.

use super::order::DirectiveOrder;
use super::route_order::{RouteOrderKey, Twins, sort_path};
use super::sites::handler_has_terminal;
use crate::caddyfile::parser::ast::{Handler, HandlerElement, Matcher, RouteArm};
use std::collections::HashMap;

/// 🧩 One middleware line, ready to be placed in front of a route, with the
/// key that orders it among the others: directive rank, then the path
/// tie-break, with unmatched lines after matched ones of the same rank.
struct Step {
    key: RouteOrderKey,
    element: HandlerElement,
}

/// 🛡️ Turns a site's keyed routes and its default pipeline into the final
/// route list, with middleware composed into the routes that answer.
///
/// `keyed` holds the site's matched routes in file order, each keyed by
/// [`RouteOrderKey::for_arm`]; `defaults` is the matcher-less pipeline,
/// already sorted by directive rank. The result is unsorted.
pub(super) fn compose_site_routes(
    order: &DirectiveOrder,
    matchers: &HashMap<String, Matcher>,
    keyed: Vec<(RouteArm, RouteOrderKey)>,
    defaults: &[Handler],
    pipeline_rank: usize,
) -> Vec<(RouteArm, RouteOrderKey)> {
    let mut routes = Vec::with_capacity(keyed.len() + 1);
    // 🧭 Each scoped line keeps its route key too, because it stays a route
    // of its own as well as a step in front of others (see below).
    let mut scoped: Vec<(RouteOrderKey, Step)> = Vec::new();
    // 👯 Step keys rank by the middleware's own directive, so their twins
    // are tracked apart from the route keys the caller built.
    let mut twins = Twins::default();
    for (file_index, (arm, route_key)) in keyed.into_iter().enumerate() {
        if handler_has_terminal(&arm.handler) {
            routes.push((arm, route_key));
            continue;
        }
        let element = HandlerElement {
            matcher: arm.matcher,
            handler: arm.handler,
        };
        let key = RouteOrderKey::for_element(order, matchers, &mut twins, &element, file_index);
        scoped.push((route_key, Step { key, element }));
    }

    let site: Vec<Step> = defaults
        .iter()
        .enumerate()
        .filter(|(_, handler)| is_site_middleware(handler))
        .map(|(index, handler)| unmatched_step(order, matchers, handler, index))
        .collect();

    // 🏎️ Whether any step could change the path before a later step's
    // matcher reads it. Only when none can is a disjoint step left out.
    let may_rewrite = site
        .iter()
        .chain(scoped.iter().map(|(_, step)| step))
        .any(|step| may_change_path(&step.element.handler));
    for (arm, key) in &mut routes {
        let answering = key.rank();
        let route_path = arm
            .matcher
            .as_ref()
            .and_then(|matcher| sort_path(matcher, matchers));
        let steps = sorted(
            site.iter()
                .filter(|step| step.key.rank() < answering)
                .chain(
                    scoped
                        .iter()
                        .map(|(_, step)| step)
                        .filter(|step| step.key.rank() < answering)
                        .filter(|step| {
                            may_rewrite || !never_both(route_path, &step.element, matchers)
                        }),
                ),
        );
        if steps.is_empty() {
            continue;
        }
        let own = std::mem::replace(&mut arm.handler, Handler::Pipeline(Vec::new()));
        arm.handler = Handler::Pipeline(
            steps
                .into_iter()
                .chain(std::iter::once(HandlerElement {
                    matcher: None,
                    handler: own,
                }))
                .collect(),
        );
    }

    // 🧺 Each matched line stays a route of its own, answering through the
    // fallback pipeline, so a request it matches still reaches the guards
    // when no answering route above claims it.
    for (index, (route_key, step)) in scoped.iter().enumerate() {
        routes.push((
            RouteArm {
                matcher: step.element.matcher.clone(),
                handler: through_fallback(order, matchers, defaults, &scoped, index, may_rewrite),
            },
            *route_key,
        ));
    }
    if !defaults.is_empty() {
        let handler = if defaults.len() == 1 {
            defaults[0].clone()
        } else {
            Handler::Pipeline(defaults.iter().cloned().map(plain).collect())
        };
        routes.push((
            RouteArm {
                matcher: None,
                handler,
            },
            RouteOrderKey::for_catch_all(pipeline_rank),
        ));
    }
    routes
}

/// 🧺 The handler for the route of scoped line `own`: the fallback pipeline's
/// non-answering directives and every scoped line in directive order, then
/// the handlers that answer.
///
/// 📌 Scoped lines go ahead of the first answering handler whatever their
/// rank, as the one line of such a route always did.
fn through_fallback(
    order: &DirectiveOrder,
    matchers: &HashMap<String, Matcher>,
    defaults: &[Handler],
    scoped: &[(RouteOrderKey, Step)],
    own: usize,
    may_rewrite: bool,
) -> Handler {
    let route_path = scoped[own]
        .1
        .element
        .matcher
        .as_ref()
        .and_then(|matcher| sort_path(matcher, matchers));
    let answering = defaults
        .iter()
        .position(handler_has_terminal)
        .unwrap_or(defaults.len());
    let (lead, rest) = defaults.split_at(answering);
    let lead_steps: Vec<Step> = lead
        .iter()
        .enumerate()
        .map(|(index, handler)| unmatched_step(order, matchers, handler, index))
        .collect();
    let own_step = Step {
        key: scoped[own].1.key,
        element: plain(scoped[own].1.element.handler.clone()),
    };
    let mut elements = sorted(
        lead_steps.iter().chain(
            scoped
                .iter()
                .enumerate()
                .filter(|(index, (_, step))| {
                    *index == own || may_rewrite || !never_both(route_path, &step.element, matchers)
                })
                .map(|(index, (_, step))| if index == own { &own_step } else { step }),
        ),
    );
    elements.extend(rest.iter().cloned().map(plain));
    Handler::Pipeline(elements)
}

/// 🧩 An element that runs for every request that reaches it.
fn plain(handler: Handler) -> HandlerElement {
    HandlerElement {
        matcher: None,
        handler,
    }
}

/// 🧩 A step for a directive written without a matcher. Its index only keeps
/// unmatched lines of one rank in their existing order.
fn unmatched_step(
    order: &DirectiveOrder,
    matchers: &HashMap<String, Matcher>,
    handler: &Handler,
    index: usize,
) -> Step {
    let element = HandlerElement {
        matcher: None,
        handler: handler.clone(),
    };
    // 👯 A step without a matcher has no pattern and so no twins; an empty
    // map does not allocate.
    let key = RouteOrderKey::for_element(order, matchers, &mut Twins::default(), &element, index);
    Step { key, element }
}

/// 🔃 The steps' elements in key order. The sort is stable, so equal keys
/// keep the order they were given in.
fn sorted<'a>(steps: impl Iterator<Item = &'a Step>) -> Vec<HandlerElement> {
    let mut steps: Vec<&Step> = steps.collect();
    steps.sort_by_key(|step| step.key);
    steps.into_iter().map(|step| step.element.clone()).collect()
}

/// 🏎️ Whether no request can reach a route on `route_path` and also match
/// `step`'s matcher, judged from the two path patterns alone.
///
/// A step that can never apply would still cost a matcher check on every
/// request to the route, so it is left out. The answer must be certain: a
/// wrong "never" drops a guard. So it says "never" only when both sides
/// require one path pattern each and their literal text — everything before
/// the first `*`, compared without regard to ASCII case as the router does —
/// cannot agree: two different exact paths, an exact path outside a prefix,
/// or two prefixes neither of which extends the other. The caller only asks
/// when no step can change the path first.
fn never_both(
    route_path: Option<&str>,
    step: &HandlerElement,
    matchers: &HashMap<String, Matcher>,
) -> bool {
    let (Some(route), Some(step)) = (
        route_path,
        step.matcher
            .as_ref()
            .and_then(|matcher| sort_path(matcher, matchers)),
    ) else {
        return false;
    };
    let literal = |pattern: &str| -> (bool, String) {
        let exact = !pattern.contains('*');
        let text = pattern.split('*').next().unwrap_or_default();
        (exact, text.to_ascii_lowercase())
    };
    let ((route_exact, route), (step_exact, step)) = (literal(route), literal(step));
    match (route_exact, step_exact) {
        (true, true) => route != step,
        (true, false) => !route.starts_with(&step),
        (false, true) => !step.starts_with(&route),
        (false, false) => !route.starts_with(&step) && !step.starts_with(&route),
    }
}

/// 🔀 Whether a step might change the request path before the steps after
/// it are matched. Anything not known to leave the path alone counts.
fn may_change_path(handler: &Handler) -> bool {
    match handler {
        Handler::Headers(_)
        | Handler::RequestHeaders(_)
        | Handler::RequestBody(_)
        | Handler::BasicAuth(_)
        | Handler::RateLimit(_)
        | Handler::Cors(_)
        | Handler::AccessControl(_)
        | Handler::LogSkip
        | Handler::Vars(_)
        | Handler::Intercept(_)
        | Handler::ForwardAuth(_) => false,
        Handler::Rewrite(_)
        | Handler::TryFiles(_)
        | Handler::Pipeline(_)
        | Handler::Handle(_)
        | Handler::HandleGroup(_)
        | Handler::HandlePath { .. }
        | Handler::Plugin { .. }
        | Handler::Proxy(_)
        | Handler::Respond(_)
        | Handler::Error(_)
        | Handler::Redirect(_)
        | Handler::FileServer(_)
        | Handler::AcmeServer(_)
        | Handler::Templates
        | Handler::Abort
        | Handler::Metrics { .. } => true,
    }
}

/// 🧩 Site directives that transform or guard a request or response before a
/// route answers. Response-producing handlers stay in the fallback pipeline.
fn is_site_middleware(handler: &Handler) -> bool {
    match handler {
        Handler::Headers(_)
        | Handler::RequestHeaders(_)
        | Handler::RequestBody(_)
        | Handler::BasicAuth(_)
        | Handler::RateLimit(_)
        | Handler::Rewrite(_)
        | Handler::TryFiles(_)
        | Handler::Cors(_)
        | Handler::AccessControl(_)
        | Handler::LogSkip
        | Handler::Vars(_)
        | Handler::Intercept(_)
        | Handler::ForwardAuth(_) => true,
        Handler::Proxy(_)
        | Handler::Respond(_)
        | Handler::Error(_)
        | Handler::Redirect(_)
        | Handler::FileServer(_)
        | Handler::AcmeServer(_)
        | Handler::Templates
        | Handler::Abort
        | Handler::Metrics { .. }
        | Handler::Pipeline(_)
        | Handler::Handle(_)
        | Handler::HandleGroup(_)
        | Handler::HandlePath { .. }
        | Handler::Plugin { .. } => false,
    }
}

// MARK: - Tests

/// 🧪 Which steps each compiled route carries.
#[cfg(test)]
mod tests {
    use pingclair_core::config::{HandlerConfig, RouteConfig};

    /// 🔑 `alice` / `secret1`, at the cheapest bcrypt cost.
    const ALICE: &str = "alice $2y$04$EBGg0.PJo2Qi2WYiMUqXsuB9orpRrMXiABirLM33AHHNb5GzEcipS";

    fn routes(source: &str) -> Vec<RouteConfig> {
        crate::compile(source).expect("compile").servers[0]
            .routes
            .clone()
    }

    /// 🏷️ The handler types of a route's top-level steps, each marked with
    /// whether it carries a matcher of its own.
    fn steps(routes: &[RouteConfig], path: &str) -> Vec<(String, bool)> {
        let route = routes
            .iter()
            .find(|route| route.path == path)
            .unwrap_or_else(|| panic!("no route for {path}"));
        let name = |handler: &HandlerConfig| {
            serde_json::to_value(handler).unwrap()["type"]
                .as_str()
                .unwrap()
                .to_string()
        };
        match &route.handler {
            HandlerConfig::Pipeline { handlers } => handlers
                .iter()
                .map(|element| (name(&element.handler), element.matcher.is_some()))
                .collect(),
            other => vec![(name(other), false)],
        }
    }

    fn step(name: &str, guarded: bool) -> (String, bool) {
        (name.to_string(), guarded)
    }

    #[test]
    fn a_guard_goes_ahead_of_a_later_ranked_route_but_not_redir() {
        // 🛡️ `respond` ranks after `basic_auth`, so the guard runs first;
        // `redir` ranks ahead of it and redirects unguarded, as in the
        // reference. The guard's own route runs it without a matcher.
        let routes = routes(&format!(
            "example.com {{\n    basic_auth /s* {{\n        {ALICE}\n    }}\n    respond /secret \"x\"\n    redir /sold /new\n}}"
        ));
        assert_eq!(
            steps(&routes, "/secret"),
            [step("basic_auth", true), step("respond", false)]
        );
        assert_eq!(steps(&routes, "/sold"), [step("redirect", false)]);
        assert_eq!(steps(&routes, "/s*"), [step("basic_auth", false)]);
    }

    #[test]
    fn a_step_whose_path_cannot_match_the_route_is_left_out() {
        // 🏎️ `/assets/*` can never match a request for `/health`, so the
        // health route does not pay a matcher check for it. `/a*` against
        // `/A/b` differs only in case, which the router ignores, so it stays.
        let routes = routes(concat!(
            "example.com {\n",
            "    header /assets/* X-A 1\n",
            "    header /a* X-B 1\n",
            "    respond /health \"up\"\n",
            "    respond /A/b \"b\"\n",
            "}",
        ));
        assert_eq!(steps(&routes, "/health"), [step("respond", false)]);
        assert_eq!(
            steps(&routes, "/A/b"),
            [step("headers", true), step("respond", false)]
        );
    }

    #[test]
    fn a_rewrite_keeps_every_step() {
        // 🔀 A rewrite runs first and can move the request onto a path a
        // later guard names, so no step is judged out of reach by path.
        let routes = routes(&format!(
            "example.com {{\n    rewrite /health /admin/x\n    basic_auth /admin/* {{\n        {ALICE}\n    }}\n    respond /health \"up\"\n}}"
        ));
        assert_eq!(
            steps(&routes, "/health"),
            [
                step("rewrite", true),
                step("basic_auth", true),
                step("respond", false)
            ]
        );
    }
}
