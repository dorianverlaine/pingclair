// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! ⚖️ Validation of the weights a `reverse_proxy` gives its upstreams.
//!
//! A weight of zero means "send this upstream nothing", the spelling an
//! operator uses to drain a backend before taking it away. Caddy honours it in
//! `weighted_round_robin` by skipping that upstream (from memory, Caddy 2.10,
//! caddyserver/caddy#6681), and the runtime here does the same for every
//! policy. What a zero cannot mean is "send everything nowhere": a pool whose
//! every primary upstream is drained would answer every request with an error,
//! so that is refused here, where `pingclair validate`, the Admin API and a
//! reload all see it.
//!
//! 📌 The ceiling exists because the runtime's weighted selector expands each
//! weight into that many table slots. It used to be applied silently, turning
//! a typo such as `weight 1000` into 100; it is refused instead, so the
//! operator learns the bound rather than getting a ratio they did not write.

use crate::compiler::{CompileError, CompileResult};
use pingclair_core::config::ReverseProxyConfig;

/// 📏 The largest weight one upstream may carry. The runtime mirrors this
/// bound in `build_weighted_upstreams`; both must move together.
const MAX_UPSTREAM_WEIGHT: u32 = 100;

/// ⚖️ Refuses an out-of-range weight, and a pool whose primary upstreams are
/// all drained.
pub(crate) fn validate_upstream_weights(proxy: &ReverseProxyConfig) -> CompileResult<()> {
    if let Some(upstream) = proxy
        .upstream_options
        .iter()
        .find(|upstream| upstream.weight > MAX_UPSTREAM_WEIGHT)
    {
        return Err(CompileError::InvalidRoute {
            message: format!(
                "upstream `{}` has weight {}; weights range from 0 to {MAX_UPSTREAM_WEIGHT}",
                upstream.address, upstream.weight
            ),
        });
    }
    let mut primaries = proxy
        .upstream_options
        .iter()
        .filter(|upstream| !upstream.backup)
        .peekable();
    if primaries.peek().is_some() && primaries.all(|upstream| upstream.weight == 0) {
        return Err(CompileError::InvalidRoute {
            message: "every primary upstream has weight 0, so no request could be sent \
                      anywhere; give at least one a non-zero weight"
                .to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingclair_core::config::ProxyUpstream;

    fn proxy(weights: &[(u32, bool)]) -> ReverseProxyConfig {
        ReverseProxyConfig {
            upstream_options: weights
                .iter()
                .enumerate()
                .map(|(index, &(weight, backup))| ProxyUpstream {
                    address: format!("127.0.0.1:{}", 9000 + index),
                    weight,
                    backup,
                })
                .collect(),
            ..Default::default()
        }
    }

    /// 🎯 A drained upstream beside a live one is a valid pool, and so is the
    /// ceiling itself; a drained pool and a weight past the ceiling are not.
    #[test]
    fn weights_are_checked_against_the_drain_and_ceiling_rules() {
        let verdicts = [
            &[(0, false), (1, false)][..],
            &[(100, false)],
            &[(0, false), (0, false)],
            &[(0, false), (5, true)],
            &[(101, false), (1, false)],
        ]
        .map(|weights| validate_upstream_weights(&proxy(weights)).is_ok());
        assert_eq!(verdicts, [true, true, false, false, false]);
    }

    /// 🎯 Both spellings of a weight reach the same rule. Before the fix
    /// `weighted_round_robin 0 1` and `weight 1000` loaded (and were clamped at
    /// runtime) while `to … { weight 0 }` was refused.
    #[test]
    fn both_weight_spellings_agree() {
        let compiles = [
            "lb_policy weighted_round_robin 0 1",
            "lb_policy weighted_round_robin 0 0",
            "lb_policy weighted_round_robin 1000 1",
        ]
        .map(|policy| {
            crate::compile(&format!(
                "http://example.com {{\n    reverse_proxy 127.0.0.1:9000 127.0.0.1:9001 {{\n        \
                 {policy}\n    }}\n}}"
            ))
            .is_ok()
        });
        assert_eq!(compiles, [true, false, false]);
        crate::compile(
            "http://example.com {\n    reverse_proxy {\n        to 127.0.0.1:9000 {\n            \
             weight 0\n        }\n        to 127.0.0.1:9001\n    }\n}",
        )
        .expect("`to … { weight 0 }` drains that upstream, like the policy spelling");
    }
}
