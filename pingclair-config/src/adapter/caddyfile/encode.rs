// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🗜️ Encode block settings must survive adaptation or fail by name.

use super::{AdapterError, reverse_proxy::parse_response_matcher};
use crate::parser::{ast::CompressionAlgo, caddy_ast::Block};
use pingclair_core::encoding::EncodeOptions;

pub(super) fn adapt_block(
    block: &Block,
    algos: &mut Vec<CompressionAlgo>,
    options: &mut EncodeOptions,
) -> Result<(), AdapterError> {
    for sub in &block.directives {
        match sub.name.as_str() {
            "gzip" | "zstd" => {
                if sub.block.is_some() || sub.args.len() > usize::from(sub.name == "gzip") {
                    return Err(AdapterError::InvalidArgument(
                        sub.name.clone(),
                        "unexpected codec arguments or block".into(),
                    ));
                }
                let algo = if sub.name == "gzip" {
                    if let Some(level) = sub.args.first() {
                        let level: u32 = level.parse().map_err(|_| {
                            AdapterError::InvalidArgument("gzip".into(), level.clone())
                        })?;
                        if level > 9 {
                            return Err(AdapterError::InvalidArgument(
                                "gzip".into(),
                                "level must be between 0 and 9".into(),
                            ));
                        }
                        options.gzip_level = if level == 0 { 5 } else { level };
                    }
                    CompressionAlgo::Gzip
                } else {
                    CompressionAlgo::Zstd
                };
                if !algos.contains(&algo) {
                    algos.push(algo);
                }
            }
            "minimum_length" => {
                if sub.args.len() != 1 || sub.block.is_some() {
                    return Err(AdapterError::ArgumentCount(
                        "minimum_length".into(),
                        1,
                        sub.args.len(),
                    ));
                }
                let length = sub.args[0].parse().map_err(|_| {
                    AdapterError::InvalidArgument("minimum_length".into(), sub.args[0].clone())
                })?;
                options.minimum_length = if length == 0 { 512 } else { length };
            }
            "match" => {
                if !sub.args.is_empty() || sub.block.is_none() {
                    return Err(AdapterError::InvalidArgument(
                        "encode match".into(),
                        "expected a response matcher block".into(),
                    ));
                }
                options.matcher = Some(parse_response_matcher(sub)?);
            }
            other => return Err(AdapterError::UnknownDirective(format!("encode: {other}"))),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::compile;

    #[test]
    fn encode_block_compiles_every_setting() {
        let config = compile("http://:8080 {\n encode {\n zstd\n gzip 1\n minimum_length 1024\n match {\n status 2xx\n header Content-Type text/*\n }\n }\n respond ok\n}").unwrap();
        let server = &config.servers[0];
        assert_eq!(
            server.encodings,
            [
                pingclair_core::config::Encoding::Zstd,
                pingclair_core::config::Encoding::Gzip
            ]
        );
        assert_eq!(server.encode.minimum_length, 1024);
        assert_eq!(server.encode.gzip_level, 1);
        assert_eq!(server.encode.matcher.as_ref().unwrap().status_codes, [2]);
        assert_eq!(
            server.encode.matcher.as_ref().unwrap().headers["Content-Type"],
            ["text/*"]
        );
    }

    #[test]
    fn encode_off_refuses_a_block() {
        for disable in ["off", "none"] {
            for settings in ["gzip", "zstd", "minimum_length 1024"] {
                let result = compile(&format!(
                    "http://:8080 {{\n encode {disable} {{\n {settings}\n }}\n respond ok\n}}"
                ));
                assert!(result.is_err(), "{disable}: {settings}");
            }
        }
    }

    #[test]
    fn encode_block_refuses_unknown_settings() {
        for setting in [
            "bogus_subdirective 42",
            "gzip 10",
            "zstd 1",
            "minimum_length nope",
            "match {\n bogus 2xx\n }",
        ] {
            assert!(
                compile(&format!(
                    "http://:8080 {{\n encode {{\n {setting}\n }}\n respond ok\n}} "
                ))
                .is_err(),
                "{setting}"
            );
        }
    }
}
