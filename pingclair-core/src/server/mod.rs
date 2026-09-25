// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! HTTP Server implementation

mod file_glob;
mod handlers;
mod matcher_tree;
mod path_pattern;
mod redirect;
mod route_candidates;
mod router;

pub use self::handlers::{
    HandlerError, HandlerResponse, MAX_BCRYPT_COST, argon2id_hash_valid, basic_auth_challenge,
    bcrypt_hash_cost, execute_handler, verify_basic_auth, verify_basic_auth_async,
};
pub use self::redirect::{HttpRedirectServer, RedirectConfig};
pub use self::router::{
    CompiledMatcher, CompiledRoute, MATCHER_PLACEHOLDER_PREFIXES, MATCHER_PLACEHOLDERS,
    MatcherPrecompile, MatcherRequest, MatcherVerdict, RequestAddresses, Router, evaluate,
    evaluate_file_matcher, evaluate_verdict, precompile_handler_list,
};
