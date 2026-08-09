// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 📇 The names this adapter knows, in one table.
//!
//! Before this module the same knowledge lived in three places that had no way
//! to stay in agreement: a list used to tell a directive from a site address, a
//! second list used to tell an unimplemented directive from a typo, and the
//! `match` arms that actually do the work. Nothing connected them, so adding a
//! directive meant remembering all three, and forgetting one was silent in a
//! different way each time:
//!
//! - missing from the first list, a directive at the start of a file became a
//!   *site named after it*, serving nothing;
//! - missing from the second, a directive the format defines was reported as a
//!   typo, sending the operator hunting for a misspelling in a word they had
//!   spelled correctly;
//! - present in a list but missing from the `match`, nothing happened at all.
//!
//! One table cannot disagree with itself. What it cannot do on its own is prove
//! that every name in it is actually wired up — a table is a promise, not an
//! implementation — so [`tests`] compiles a minimal configuration for every
//! implemented entry and fails if the promise is empty.
//!
//! # 🧭 Why a table and not registration
//!
//! The format's own implementation has each directive register itself as its
//! package loads, which is idiomatic there and would be a poor fit here: it
//! needs mutable global state, an initialisation order, and a lock on a path
//! that is otherwise free of both. A static table gives the same property that
//! made registration worth copying — **one place to add a directive** — while
//! staying something the compiler checks.

/// Whether this crate does anything with a directive, or merely recognises it.
///
/// 📌 `Implemented` means "somewhere": `root` is a site-level directive here but
/// not a handler, so it is implemented and still refused inside a `route` block.
/// The distinction that matters to an operator is *recognised versus typo*, and
/// that is membership in the table rather than this flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Support {
    /// Adapted into configuration.
    Implemented,
    /// Part of the format, and refused with a message that says so.
    Recognised,
}

/// One name and what we do with it.
#[derive(Debug, Clone, Copy)]
pub(super) struct Spec {
    pub(super) name: &'static str,
    pub(super) support: Support,
}

const fn implemented(name: &'static str) -> Spec {
    Spec {
        name,
        support: Support::Implemented,
    }
}

const fn recognised(name: &'static str) -> Spec {
    Spec {
        name,
        support: Support::Recognised,
    }
}

/// 🧾 Every directive name, whether or not it is implemented.
///
/// Adding a directive is one entry here plus one parsing function. That is the
/// whole payoff: the cost of keeping up with the format becomes proportional to
/// what the format added, not to how many places in this crate happen to know
/// about names.
pub(super) static DIRECTIVES: &[Spec] = &[
    // MARK: - Implemented
    implemented("access_control"),
    implemented("basic_auth"),
    implemented("basicauth"),
    implemented("bind"),
    implemented("compress"),
    implemented("cors"),
    implemented("encode"),
    implemented("error"),
    implemented("error_page"),
    implemented("file_server"),
    implemented("forward_auth"),
    implemented("gzip_types"),
    implemented("handle"),
    implemented("handle_errors"),
    implemented("handle_path"),
    implemented("header"),
    implemented("import"),
    implemented("intercept"),
    implemented("limits"),
    implemented("listen"),
    implemented("log"),
    implemented("log_skip"),
    implemented("php_fastcgi"),
    implemented("rate_limit"),
    implemented("redir"),
    implemented("redirect"),
    implemented("respond"),
    implemented("reverse_proxy"),
    implemented("rewrite"),
    implemented("root"),
    implemented("route"),
    implemented("templates"),
    implemented("tls"),
    implemented("try_files"),
    implemented("uri"),
    implemented("vars"),
    // MARK: - Recognised, not implemented
    recognised("abort"),
    recognised("acme_server"),
    recognised("copy_response"),
    recognised("copy_response_headers"),
    recognised("fs"),
    recognised("invoke"),
    recognised("log_append"),
    recognised("log_name"),
    recognised("map"),
    recognised("method"),
    recognised("metrics"),
    recognised("push"),
    recognised("request_body"),
    recognised("request_header"),
    recognised("skip_log"),
    recognised("tracing"),
];

/// 🌐 Every global-block option name.
pub(super) static GLOBAL_OPTIONS: &[Spec] = &[
    // MARK: - Implemented
    implemented("admin"),
    implemented("auto_https"),
    implemented("debug"),
    implemented("dns_refresh"),
    implemented("email"),
    implemented("grace_period"),
    implemented("http_port"),
    implemented("https_port"),
    implemented("local_certs"),
    implemented("log"),
    implemented("metrics"),
    implemented("order"),
    implemented("persist_config"),
    implemented("protocols"),
    implemented("trusted_proxies"),
    // MARK: - Recognised, not implemented
    recognised("acme_ca"),
    recognised("acme_ca_root"),
    recognised("acme_dns"),
    recognised("acme_eab"),
    recognised("cert_issuer"),
    recognised("cert_lifetime"),
    recognised("default_bind"),
    recognised("default_sni"),
    recognised("dns"),
    recognised("ech"),
    recognised("events"),
    recognised("fallback_sni"),
    recognised("filesystem"),
    recognised("frankenphp"),
    recognised("key_type"),
    recognised("ocsp_interval"),
    recognised("ocsp_stapling"),
    recognised("on_demand_tls"),
    recognised("pki"),
    recognised("preferred_chains"),
    recognised("renew_interval"),
    recognised("renewal_window_ratio"),
    recognised("shutdown_delay"),
    recognised("skip_install_trust"),
    recognised("storage"),
    recognised("storage_clean_interval"),
];

/// Looks a directive up by name.
pub(super) fn directive(name: &str) -> Option<&'static Spec> {
    DIRECTIVES.iter().find(|spec| spec.name == name)
}

/// 🧾 Whether this adapter turns `name` into configuration, for callers
/// outside the crate.
///
/// 📌 This exists so that anything advertising a directive to a user can be
/// checked against the one table that decides. `pingclair list-modules` used
/// to carry its own hand-written copy of the answer, and on 2026-08-07 that
/// copy still listed `try_files` — which the adapter refused. A name a tool
/// prints and a name the parser accepts have to come from the same place, or
/// the tool becomes a way to learn something untrue about the binary you are
/// holding.
pub fn is_implemented_directive(name: &str) -> bool {
    directive(name).is_some_and(|spec| spec.support == Support::Implemented)
}

/// 🚩 Every directive and global option the format defines and this crate
/// refuses, in table order.
///
/// 📌 Exposed so the READMEs' "not supported" list can be checked against the
/// table rather than maintained by hand. A promise of compatibility is only
/// worth what its stated limits are worth, and a limits list nobody verifies
/// goes stale in the direction that flatters us — it keeps naming things we
/// have since implemented and stops naming things we never did.
pub fn recognised_but_unimplemented() -> impl Iterator<Item = &'static str> {
    DIRECTIVES
        .iter()
        .chain(GLOBAL_OPTIONS.iter())
        .filter(|spec| spec.support == Support::Recognised)
        .map(|spec| spec.name)
}

/// Looks a global-block option up by name.
pub(super) fn global_option(name: &str) -> Option<&'static Spec> {
    GLOBAL_OPTIONS.iter().find(|spec| spec.name == name)
}

/// 🎯 Whether a word is a directive rather than a site address.
///
/// Nothing about the text tells them apart — `localhost` is a fine site address
/// and `handle` is a fine word — so the answer is membership in the table, and
/// this is the only layer that has it. Getting it wrong is silent in both
/// directions: a directive read as a site serves nothing, and a site read as a
/// directive is refused for a reason that mentions neither.
pub(super) fn is_directive_name(name: &str) -> bool {
    directive(name).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 🧭 A table with the same name twice would make lookups depend on order.
    #[test]
    fn no_name_is_registered_twice() {
        for table in [DIRECTIVES, GLOBAL_OPTIONS] {
            let mut names: Vec<&str> = table.iter().map(|spec| spec.name).collect();
            names.sort_unstable();
            let mut unique = names.clone();
            unique.dedup();
            assert_eq!(names, unique, "a name is registered twice");
        }
    }

    /// 📌 Entries are kept sorted within their group so a new one has an
    /// obvious home and two people adding directives do not collide.
    #[test]
    fn each_group_is_sorted() {
        for table in [DIRECTIVES, GLOBAL_OPTIONS] {
            for support in [Support::Implemented, Support::Recognised] {
                let group: Vec<&str> = table
                    .iter()
                    .filter(|spec| spec.support == support)
                    .map(|spec| spec.name)
                    .collect();
                let mut sorted = group.clone();
                sorted.sort_unstable();
                assert_eq!(group, sorted, "{support:?} entries are out of order");
            }
        }
    }

    /// 🎯 The check a table cannot do for itself: every directive claiming to
    /// be implemented must actually be wired into the adapter.
    ///
    /// Without this, `Implemented` is a comment. A name in the table but
    /// missing from the dispatch produces nothing at all — the failure mode
    /// that used to be possible in three different ways at once.
    #[test]
    fn every_implemented_directive_is_actually_wired_up() {
        // 🧾 A minimal, valid use of each directive. Writing them out is the
        // point: it is also the shortest possible documentation of what each
        // one needs, checked on every commit.
        let minimal = [
            (
                "access_control",
                "access_control {\n allow_ip 10.0.0.0/8\n }",
            ),
            (
                "basic_auth",
                "basic_auth {\n u $2a$14$Zkx19XLiW6VYouLHR5NmfOFU0z2GTNmpkT/5qqR7hx4IjWJPDhjvG\n }",
            ),
            (
                "basicauth",
                "basicauth {\n u $2a$14$Zkx19XLiW6VYouLHR5NmfOFU0z2GTNmpkT/5qqR7hx4IjWJPDhjvG\n }",
            ),
            ("bind", "bind 127.0.0.1"),
            ("compress", "compress gzip"),
            ("cors", "cors *"),
            ("encode", "encode gzip"),
            ("error_page", "error_page 404 /404.html"),
            ("file_server", "file_server"),
            ("gzip_types", "gzip_types text/*"),
            ("handle", "handle {\n respond \"x\"\n }"),
            ("handle_path", "handle_path /api/* {\n respond \"x\"\n }"),
            ("header", "header X-A b"),
            ("import", "import missing_is_a_different_error"),
            (
                "intercept",
                "intercept {\n @500 status 500\n handle_response @500 {\n respond \"x\"\n }\n }",
            ),
            (
                "forward_auth",
                "forward_auth 127.0.0.1:9000 {\n uri /auth\n copy_headers X-User-Id\n }",
            ),
            ("limits", "limits {\n max_connections 10\n }"),
            ("listen", "listen :8080"),
            ("log", "log {\n output stdout\n }"),
            ("log_skip", "log_skip"),
            ("php_fastcgi", "php_fastcgi 127.0.0.1:9000"),
            ("rate_limit", "rate_limit 10 1s"),
            ("error", "error 404"),
            ("redir", "redir /a /b"),
            ("redirect", "redirect /a /b"),
            ("handle_errors", "handle_errors {\n respond \"x\"\n }"),
            ("respond", "respond \"x\""),
            ("reverse_proxy", "reverse_proxy 127.0.0.1:9000"),
            ("rewrite", "rewrite /a /b"),
            ("root", "root /srv"),
            ("route", "route {\n respond \"x\"\n }"),
            ("templates", "templates"),
            ("tls", "tls internal"),
            ("try_files", "try_files {path} /index.html"),
            ("uri", "uri strip_prefix /api"),
            ("vars", "vars foo bar"),
        ];

        for spec in DIRECTIVES
            .iter()
            .filter(|spec| spec.support == Support::Implemented)
        {
            let body = minimal
                .iter()
                .find(|(name, _)| *name == spec.name)
                .unwrap_or_else(|| {
                    panic!(
                        "`{}` is registered as implemented but this test has no minimal \
                         use for it — add one rather than removing the entry",
                        spec.name
                    )
                })
                .1;

            let source = format!("example.com {{\n {body}\n}}");
            match crate::compile(&source) {
                Ok(_) => {}
                Err(error) => {
                    let message = error.to_string();
                    // 🧭 `import` of a name that does not exist fails for its
                    // own reason, which still proves the directive is wired.
                    let wired = !message.contains("Unknown directive")
                        && !message.contains("not supported by Pingclair");
                    assert!(
                        wired,
                        "`{}` is registered as implemented but the adapter does not \
                         handle it: {message}",
                        spec.name
                    );
                }
            }
        }
    }

    /// 🚫 And the other direction: a name the table calls recognised must be
    /// refused with a message that says so, never as an unknown word.
    #[test]
    fn every_recognised_directive_is_refused_by_name() {
        for spec in DIRECTIVES
            .iter()
            .filter(|spec| spec.support == Support::Recognised)
        {
            let source = format!("example.com {{\n {} \n}}", spec.name);
            let message = crate::compile(&source)
                .err()
                .map(|error| error.to_string())
                .unwrap_or_else(|| {
                    panic!("`{}` is not implemented, so it must be refused", spec.name)
                });
            assert!(
                !message.contains("Unknown directive"),
                "`{}` is part of the format, so it must not read as a typo: {message}",
                spec.name
            );
        }
    }
}
