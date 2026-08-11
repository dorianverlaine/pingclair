// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! HTTP Server implementation

mod handlers;
mod redirect;
mod router;

pub use self::handlers::{
    HandlerError, HandlerResponse, MAX_BCRYPT_COST, argon2id_hash_valid, basic_auth_challenge,
    bcrypt_hash_cost, execute_handler, verify_basic_auth, verify_basic_auth_async,
};
pub use self::redirect::{HttpRedirectServer, RedirectConfig};
pub use self::router::{
    CompiledMatcher, CompiledRoute, FILE_MATCHER_PLACEHOLDER_PREFIXES, FILE_MATCHER_PLACEHOLDERS,
    MatcherPrecompile, MatcherRequest, MatcherVerdict, Router, evaluate, evaluate_file_matcher,
    evaluate_verdict, precompile_handler_list,
};
