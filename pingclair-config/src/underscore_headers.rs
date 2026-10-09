// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🛡️ Validate the allowlist on every configuration path, including Admin JSON.

use crate::compiler::{CompileError, CompileResult};
use pingclair_core::config::PingclairConfig;

pub(crate) fn validate(config: &PingclairConfig) -> CompileResult<()> {
    let lists = std::iter::once(&config.global.expected_underscore_headers).chain(
        config
            .global
            .listener_options
            .values()
            .filter_map(|options| options.expected_underscore_headers.as_ref()),
    );
    for entries in lists {
        for entry in entries {
            let name = entry.strip_suffix('*').unwrap_or(entry);
            if !name.contains('_')
                || name.contains('*')
                || http::HeaderName::from_bytes(name.as_bytes()).is_err()
            {
                return Err(CompileError::InvalidServer {
                    message: format!(
                        "expected_underscore_headers entry `{entry}` must be an ASCII header name containing `_`, with at most one trailing `*`"
                    ),
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expected_underscore_headers_round_trip_with_listener_override() {
        let config = crate::compile(
            r#"
        {
            servers {
 expected_underscore_headers X_Probe Webhook_*
 }
            servers :8081 {
 expected_underscore_headers Other_Field
 }
        }
        http://:8080, http://:8081 {
 respond ok
 }
        "#,
        )
        .unwrap();
        assert_eq!(
            config.global.expected_underscore_headers,
            ["X_Probe", "Webhook_*"]
        );
        assert_eq!(
            config.global.listener_options[":8081"].expected_underscore_headers,
            Some(vec!["Other_Field".to_owned()])
        );
        let decoded: PingclairConfig =
            serde_json::from_value(serde_json::to_value(&config).unwrap()).unwrap();
        assert_eq!(
            serde_json::to_value(&decoded).unwrap(),
            serde_json::to_value(&config).unwrap()
        );
        crate::compiler::validate_config(&decoded).unwrap();
    }

    #[test]
    fn expected_underscore_headers_reject_invalid_entries_on_all_paths() {
        for entry in ["x-probe", "*", "x_*_bad", "x_é", "x_ bad", "x_:bad"] {
            let mut config = PingclairConfig::default();
            config.global.expected_underscore_headers = vec![entry.to_owned()];
            assert!(validate(&config).is_err(), "global: {entry}");
            config.global.expected_underscore_headers.clear();
            config.global.listener_options.insert(
                ":8080".into(),
                pingclair_core::config::ListenerOptions {
                    expected_underscore_headers: Some(vec![entry.to_owned()]),
                    ..Default::default()
                },
            );
            assert!(
                crate::compiler::validate_config(&config)
                    .unwrap_err()
                    .to_string()
                    .contains("expected_underscore_headers")
            );
        }
        for directive in [
            "expected_underscore_headers",
            "expected_underscore_headers X_Probe { nested }",
            "expected_underscore_headers true",
        ] {
            assert!(
                crate::compile(&format!(
                    "{{\n servers {{\n {directive}\n }}\n}}\nhttp://:8080 {{\n respond ok\n }}"
                ))
                .is_err()
            );
        }
    }
}
