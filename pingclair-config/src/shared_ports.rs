// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔌 Validation of ports shared by a wildcard and a specific address.
//!
//! The runtime serves `127.0.0.1:8080` through `[::]:8080` when both appear
//! in one configuration (see `pingclair_core::config::SharedPortFold`). That
//! fold can surface a disagreement the separate addresses hid: one site wants
//! the port in plaintext and another wants TLS, or only one of them expects a
//! PROXY protocol header. A socket has one answer to each, so the folded
//! configuration is checked by the same rules as any shared listener, here,
//! where `pingclair validate`, the Admin API and a reload all see the refusal.
//!
//! 📌 This checks the configuration as written. The runtime plans the fold
//! again with the automatic HTTPS companion included, because only the
//! running process knows whether it could take the HTTP port.

use crate::compiler::{
    CompileError, CompileResult, validate_plaintext_listeners, validate_proxy_protocol_listeners,
};
use pingclair_core::config::{PingclairConfig, SharedPortFold};

/// 🔌 Refuses a configuration whose shared ports cannot be one socket each.
pub(crate) fn validate_shared_ports(config: &PingclairConfig) -> CompileResult<()> {
    let fold =
        SharedPortFold::plan(config, &[]).map_err(|conflict| CompileError::InvalidServer {
            message: conflict.to_string(),
        })?;
    if fold.folded().is_empty() {
        return Ok(());
    }
    // 📌 A clone, on the load path only, and only when something folds.
    let mut folded = config.clone();
    fold.apply(&mut folded);
    validate_proxy_protocol_listeners(&folded)?;
    validate_plaintext_listeners(&folded)
}

#[cfg(test)]
mod tests {
    /// 🚫 A plaintext literal and a TLS wildcard cannot share one socket.
    #[test]
    fn folding_refuses_a_plaintext_and_tls_disagreement() {
        let source = "http://127.0.0.1:8443 {\n    respond \"plain\"\n}\n\
                      https://example.test:8443 {\n    tls internal\n    respond \"secure\"\n}\n";
        let error = crate::compile(source).expect_err("one socket cannot be both");
        assert!(error.to_string().contains("[::]:8443"), "{error}");
    }

    /// 🔌 #246: the hostname and literal sites validate together.
    #[test]
    fn a_literal_and_a_hostname_on_one_port_validate() {
        let source = "http://127.0.0.1:8080 {\n    respond \"loopback\"\n}\n\
                      http://example.test:8080 {\n    respond \"named\"\n}\n";
        crate::compile(source).expect("one plaintext socket carries both");
    }
}
