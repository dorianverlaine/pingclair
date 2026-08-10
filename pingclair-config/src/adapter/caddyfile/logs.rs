// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

use super::AdapterError;
use super::args::{parse_positive_usize, parse_required_duration};
use crate::parser::ast::*;
use crate::parser::caddy_ast::{Block, Directive};

// MARK: - Log Block

pub(super) fn adapt_log_block(block: Block) -> Result<LogBlock, AdapterError> {
    let mut output = LogOutput::Stdout;
    let mut format = LogFormat::default();
    let mut level = None;
    let mut rotation = LogRotationBlock::default();
    let mut request_headers = Vec::new();
    let mut response_headers = Vec::new();
    let mut include_tls = false;
    let mut hostnames = Vec::new();
    let mut include = Vec::new();
    let mut exclude = Vec::new();
    let mut sampling = None;

    for d in block.directives {
        match d.name.as_str() {
            "output" => {
                let kind = d
                    .args
                    .first()
                    .ok_or_else(|| AdapterError::ArgumentCount("log output".into(), 1, 0))?;
                match kind.as_str() {
                    "file" => {
                        let path = d.args.get(1).ok_or_else(|| {
                            AdapterError::ArgumentCount("log output file".into(), 2, 1)
                        })?;
                        output = LogOutput::File(path.clone());
                        // 🔄 Caddy spells the rotation settings as a block on the
                        // destination itself: `output file <path> { roll_size 1mb }`.
                        // This block used to be parsed and then dropped on the
                        // floor, so a pasted Caddy configuration validated green
                        // and then never rotated anything — the log grew until the
                        // device filled, which is the exact failure rotation exists
                        // to prevent. Silence is the worst possible answer here.
                        if let Some(roll) = d.block {
                            parse_caddy_roll_block(roll, &mut rotation)?;
                        }
                    }
                    // 🚫 Only a file has anything to roll. A block on a stream
                    // destination is a misunderstanding worth naming, not
                    // something to accept and ignore.
                    "stdout" | "stderr" if d.block.is_some() => {
                        return Err(AdapterError::InvalidArgument(
                            "log output".into(),
                            format!("`{kind}` takes no block; rotation applies to `output file`"),
                        ));
                    }
                    "stdout" => output = LogOutput::Stdout,
                    "stderr" => output = LogOutput::Stderr,
                    // 🚩 A typo in the log destination used to fall through to
                    // the default sink, so `output stdoutd` wrote to stderr and
                    // nobody could tell why the line went missing.
                    other => {
                        return Err(AdapterError::InvalidArgument(
                            "log output".into(),
                            format!("unknown output `{other}` (expected file, stdout or stderr)"),
                        ));
                    }
                }
            }
            // 🔄 `roll { size 100mb; age 24h; keep 7; compress }` — a log that
            // only grows eventually fills the device, which is exactly the
            // failure the bounded writer exists to survive. Better not to
            // cause it.
            "roll" => {
                let Some(roll) = d.block else {
                    return Err(AdapterError::InvalidArgument(
                        "log roll".into(),
                        "block required, e.g. `roll { size 100mb }`".into(),
                    ));
                };
                for r in roll.directives {
                    match r.name.as_str() {
                        "size" => rotation.max_size_bytes = Some(parse_byte_size(&r)?),
                        "age" => rotation.max_age_secs = Some(parse_required_duration(&r)? / 1000),
                        "keep" => rotation.keep = Some(parse_positive_usize(&r)?),
                        "compress" => rotation.compress = true,
                        other => {
                            return Err(AdapterError::UnknownDirective(format!("roll: {other}")));
                        }
                    }
                }
                if !rotation.compress && rotation.keep.is_some() && !rotation.is_enabled_block() {
                    return Err(AdapterError::InvalidArgument(
                        "log roll".into(),
                        "`keep` needs a rotation trigger — add `size` or `age`, or nothing \
                         will ever be rotated to keep"
                            .into(),
                    ));
                }
            }
            // 🏷️ `headers { request X-Foo; response Y-Bar; tls }`. Sensitive
            // names are still masked at write time, so naming `authorization`
            // here records that it was present without recording the secret.
            "headers" => {
                let Some(hdrs) = d.block else {
                    return Err(AdapterError::InvalidArgument(
                        "log headers".into(),
                        "block required, e.g. `headers { request X-Request-Id }`".into(),
                    ));
                };
                for h in hdrs.directives {
                    match h.name.as_str() {
                        "request" => {
                            request_headers.extend(h.args.iter().map(|a| a.to_ascii_lowercase()))
                        }
                        "response" => {
                            response_headers.extend(h.args.iter().map(|a| a.to_ascii_lowercase()))
                        }
                        "tls" => include_tls = true,
                        other => {
                            return Err(AdapterError::UnknownDirective(format!(
                                "headers: {other}"
                            )));
                        }
                    }
                }
            }
            "format" => {
                let kind = d
                    .args
                    .first()
                    .ok_or_else(|| AdapterError::ArgumentCount("log format".into(), 1, 0))?;
                match kind.as_str() {
                    "json" => format.format_type = LogFormatType::Json,
                    "text" | "console" => format.format_type = LogFormatType::Text,
                    "filter" => {
                        // `format filter { wrap <json|text> ... }`.
                        // JSON is the default here because a filter block
                        // exists to drop fields, which only structured
                        // output makes meaningful — but an explicit
                        // `wrap text` must still win. This previously
                        // pinned Json before reading `wrap` at all, so
                        // `wrap text` was impossible to express.
                        format.format_type = LogFormatType::Json;
                        if let Some(filter_block) = d.block {
                            let mut filter = LogFilter::default();
                            for fb_d in filter_block.directives {
                                if fb_d.name == "wrap" {
                                    match fb_d.args.first().map(|s| s.as_str()) {
                                        Some("json") => format.format_type = LogFormatType::Json,
                                        Some("text") | Some("console") => {
                                            format.format_type = LogFormatType::Text
                                        }
                                        // 🚩 `wrap` with an unknown encoder or
                                        // no encoder is a config error, not a
                                        // reason to silently pick JSON.
                                        _ => {
                                            return Err(AdapterError::InvalidArgument(
                                                "log format filter wrap".into(),
                                                format!(
                                                    "expected json, text or console, got {:?}",
                                                    fb_d.args.first()
                                                ),
                                            ));
                                        }
                                    }
                                } else if fb_d.name == "fields"
                                    && let Some(fields_block) = fb_d.block
                                {
                                    for field_d in fields_block.directives {
                                        // field_name "delete" → exclude field
                                        if field_d.args.first().map(|a| a.as_str())
                                            == Some("delete")
                                        {
                                            filter.exclude.push(field_d.name);
                                        }
                                    }
                                } else {
                                    // 🔎 Flat filter directives name a field
                                    // path and an operation, e.g.
                                    // `request>headers>Authorization delete`.
                                    // `delete` is honoured; the replace/hash/
                                    // mask operations are parsed and ignored
                                    // until the formatter implements them.
                                    if fb_d.args.first().map(|a| a.as_str()) == Some("delete") {
                                        filter.exclude.push(fb_d.name.clone());
                                    }
                                }
                            }
                            format.filter = Some(filter);
                        }
                    }
                    // 🚩 `format jsno` used to fall back to text encoding and
                    // hide the typo behind a working-looking log line.
                    other => {
                        return Err(AdapterError::InvalidArgument(
                            "log format".into(),
                            format!("unknown format `{other}` (expected json, text or filter)"),
                        ));
                    }
                }
            }
            "level" => {
                // 🚦 Accepts Caddy's log levels and maps them onto the
                // process levels; the value flows through to the compiled
                // config for tooling and future filtering.
                let raw = d
                    .args
                    .first()
                    .ok_or_else(|| AdapterError::ArgumentCount("log level".into(), 1, 0))?;
                if d.args.len() != 1 {
                    return Err(AdapterError::ArgumentCount(
                        "log level".into(),
                        1,
                        d.args.len(),
                    ));
                }
                level = Some(match raw.to_ascii_lowercase().as_str() {
                    "trace" => LogLevel::Trace,
                    "debug" => LogLevel::Debug,
                    "info" => LogLevel::Info,
                    "warn" | "warning" => LogLevel::Warn,
                    "error" => LogLevel::Error,
                    other => {
                        return Err(AdapterError::InvalidArgument(
                            "log level".into(),
                            format!("unknown level `{other}`"),
                        ));
                    }
                });
            }
            "hostnames" => {
                if d.args.is_empty() {
                    return Err(AdapterError::ArgumentCount("log hostnames".into(), 1, 0));
                }
                hostnames.extend(d.args.iter().cloned());
            }
            "include" => include.extend(d.args.iter().cloned()),
            "exclude" => exclude.extend(d.args.iter().cloned()),
            "sampling" => {
                let Some(sampling_block) = d.block else {
                    return Err(AdapterError::InvalidArgument(
                        "log sampling".into(),
                        "block required, e.g. `sampling { interval 5m; first 50; thereafter 40 }`"
                            .into(),
                    ));
                };
                let mut parsed = LogSampling {
                    interval_secs: 0,
                    first: 0,
                    thereafter: 0,
                };
                let mut saw = false;
                for sub in sampling_block.directives {
                    saw = true;
                    match sub.name.as_str() {
                        "interval" => {
                            parsed.interval_secs = parse_required_duration(&sub)? / 1000;
                        }
                        "first" => {
                            parsed.first = parse_positive_usize(&sub)?;
                        }
                        "thereafter" => {
                            parsed.thereafter = parse_positive_usize(&sub)?;
                        }
                        other => {
                            return Err(AdapterError::UnknownDirective(format!(
                                "log sampling: {other}"
                            )));
                        }
                    }
                }
                if !saw || parsed.interval_secs == 0 {
                    return Err(AdapterError::InvalidArgument(
                        "log sampling".into(),
                        "`interval` is required and must be non-zero".into(),
                    ));
                }
                sampling = Some(parsed);
            }
            // 🚩 Unknown log subdirectives (e.g. `level debug` today) must not
            // vanish: the operator would believe the setting took effect.
            other => {
                return Err(AdapterError::UnknownDirective(format!("log: {other}")));
            }
        }
    }

    Ok(LogBlock {
        name: None,
        output,
        format,
        level,
        rotation,
        request_headers,
        response_headers,
        include_tls,
        hostnames,
        include,
        exclude,
        sampling,
    })
}

/// 📏 Parses a byte size with an optional unit suffix (`100mb`, `4KiB`, `512`).
///
/// 🔄 Reads Caddy's rotation settings from `output file <path> { … }`.
///
/// Caddy puts these on the destination rather than in a sibling block, and
/// spells them with a `roll_` prefix. Both spellings now reach the same
/// `LogRotation`, so a configuration written either way means the same thing.
///
/// One difference is deliberate and worth knowing: Caddy compresses rotated
/// files unless told not to, so a `roll_` block turns compression **on** and
/// `roll_uncompressed` is what turns it off. Our own `roll { … }` block keeps
/// its opt-in `compress`, because changing that would quietly alter what
/// existing configurations do.
pub(super) fn parse_caddy_roll_block(
    block: Block,
    rotation: &mut LogRotationBlock,
) -> Result<(), AdapterError> {
    let mut uncompressed = false;
    let mut saw_setting = false;

    for r in block.directives {
        saw_setting = true;
        match r.name.as_str() {
            "roll_size" => rotation.max_size_bytes = Some(parse_byte_size(&r)?),
            "roll_keep" => rotation.keep = Some(parse_positive_usize(&r)?),
            "roll_keep_for" => rotation.max_age_secs = Some(parse_required_duration(&r)? / 1000),
            "roll_uncompressed" => uncompressed = true,
            "mode" => rotation.mode = Some(r.args.first().cloned().unwrap_or_default()),
            "dir_mode" => rotation.dir_mode = Some(r.args.first().cloned().unwrap_or_default()),
            "roll_compression" => {
                rotation.roll_compression = r.args.first().cloned();
            }
            "roll_local_time" => rotation.roll_local_time = true,
            "roll_interval" => {
                rotation.roll_interval_secs = Some(parse_required_duration(&r)? / 1000);
            }
            "roll_at" => rotation.roll_at = Some(r.args.join(" ")),
            "roll_minutes" => rotation.roll_minutes = Some(r.args.join(" ")),
            other => {
                return Err(AdapterError::UnknownDirective(format!(
                    "log output file: {other}"
                )));
            }
        }
    }

    if saw_setting {
        rotation.compress = !uncompressed;
    }
    // 📌 `roll_keep` alone would otherwise be silently inert, which is the same
    // class of failure this whole function exists to remove.
    if rotation.keep.is_some() && !rotation.is_enabled_block() {
        return Err(AdapterError::InvalidArgument(
            "log output file".into(),
            "`roll_keep` needs a rotation trigger — add `roll_size` or \
             `roll_keep_for`, or nothing will ever be rotated to keep"
                .into(),
        ));
    }
    Ok(())
}

/// Sizes are the one place where a bare number is genuinely unambiguous —
/// it means bytes — so unlike durations it is accepted. What is *not*
/// accepted is an unrecognised suffix: `100mbb` must fail loudly rather than
/// silently parse as 100.
pub(super) fn parse_byte_size(directive: &Directive) -> Result<u64, AdapterError> {
    let raw = directive.args.first().ok_or_else(|| {
        AdapterError::ArgumentCount(directive.name.clone(), 1, directive.args.len())
    })?;
    if directive.args.len() != 1 {
        return Err(AdapterError::ArgumentCount(
            directive.name.clone(),
            1,
            directive.args.len(),
        ));
    }
    let lower = raw.to_ascii_lowercase();
    let digits = lower.trim_end_matches(|c: char| c.is_ascii_alphabetic());
    let suffix = &lower[digits.len()..];
    let value: u64 = digits.parse().map_err(|_| {
        AdapterError::InvalidArgument(directive.name.clone(), format!("`{raw}` is not a size"))
    })?;
    let multiplier: u64 = match suffix {
        "" | "b" => 1,
        "k" | "kb" | "kib" => 1024,
        "m" | "mb" | "mib" => 1024 * 1024,
        "g" | "gb" | "gib" => 1024 * 1024 * 1024,
        other => {
            return Err(AdapterError::InvalidArgument(
                directive.name.clone(),
                format!("unknown size unit `{other}` (expected b, kb, mb or gb)"),
            ));
        }
    };
    value.checked_mul(multiplier).ok_or_else(|| {
        AdapterError::InvalidArgument(directive.name.clone(), format!("`{raw}` overflows"))
    })
}

#[cfg(test)]
mod log_format_tests {
    use crate::compile;
    use pingclair_core::config::{LogFormat as CoreLogFormat, LogOutput as CoreLogOutput};

    fn log_of(source: &str) -> pingclair_core::config::LogConfig {
        compile(source)
            .unwrap()
            .servers
            .remove(0)
            .log
            .expect("log config")
    }

    #[test]
    fn plain_format_directives_compile() {
        assert!(matches!(
            log_of(":80 {\n log { format json }\n respond \"ok\" 200\n}").format,
            CoreLogFormat::Json
        ));
        assert!(matches!(
            log_of(":80 {\n log { format text }\n respond \"ok\" 200\n}").format,
            CoreLogFormat::Text
        ));
    }

    /// Regression: `format filter { wrap text }` used to be impossible to
    /// express — the adapter pinned Json before it ever read `wrap`, so a
    /// config asking for text silently got JSON.
    #[test]
    fn filter_block_honors_explicit_wrap() {
        let text = log_of(
            ":80 {\n log { format filter { wrap text\n fields { user_agent delete } } }\n respond \"ok\" 200\n}",
        );
        assert!(
            matches!(text.format, CoreLogFormat::Text),
            "wrap text must win over the filter block's JSON default"
        );

        let json = log_of(
            ":80 {\n log { format filter { wrap json\n fields { user_agent delete } } }\n respond \"ok\" 200\n}",
        );
        assert!(matches!(json.format, CoreLogFormat::Json));
    }

    /// A filter block with no explicit `wrap` still defaults to JSON, since
    /// dropping named fields only means something for structured output.
    #[test]
    fn filter_block_without_wrap_defaults_to_json() {
        let cfg = log_of(
            ":80 {\n log { format filter { fields { referer delete } } }\n respond \"ok\" 200\n}",
        );
        assert!(matches!(cfg.format, CoreLogFormat::Json));
    }

    /// Regression: field exclusions were parsed into the AST and then dropped
    /// by the compiler, so `fields { x delete }` was accepted and ignored.
    #[test]
    fn field_exclusions_survive_compilation() {
        let cfg = log_of(
            ":80 {\n log { format filter { wrap json\n fields { user_agent delete\n referer delete } } }\n respond \"ok\" 200\n}",
        );
        assert!(
            cfg.exclude_fields.contains(&"user_agent".to_string()),
            "{:?}",
            cfg.exclude_fields
        );
        assert!(
            cfg.exclude_fields.contains(&"referer".to_string()),
            "{:?}",
            cfg.exclude_fields
        );
    }

    #[test]
    fn output_targets_compile() {
        assert!(matches!(
            log_of(":80 {\n log { output stdout }\n respond \"ok\" 200\n}").output,
            CoreLogOutput::Stdout
        ));
        assert!(matches!(
            log_of(":80 {\n log { output stderr }\n respond \"ok\" 200\n}").output,
            CoreLogOutput::Stderr
        ));
        match log_of(":80 {\n log { output file /var/log/x.log }\n respond \"ok\" 200\n}").output {
            CoreLogOutput::File(p) => assert_eq!(p, "/var/log/x.log"),
            other => panic!("expected file output, got {other:?}"),
        }
    }

    #[test]
    fn hostnames_and_sampling_compile() {
        let cfg = log_of(
            ":80 {\n log {\n hostnames a.example b.example\n sampling {\n interval 5m\n first 50\n thereafter 40\n }\n }\n respond \"ok\" 200\n}",
        );
        assert_eq!(
            cfg.hostnames,
            vec!["a.example".to_string(), "b.example".to_string()]
        );
        let sampling = cfg.sampling.expect("sampling policy");
        assert_eq!(sampling.interval_secs, 300);
        assert_eq!(sampling.first, 50);
        assert_eq!(sampling.thereafter, 40);
    }

    /// 🚫 A global logger has no site block, so `hostnames` can never select
    /// anything and is refused rather than accepted and ignored.
    ///
    /// Confirmed against Caddy v2.11.4, which answers
    /// "hostnames is not allowed in the log global options".
    #[test]
    fn hostnames_in_the_global_log_block_is_refused() {
        let error = crate::compile(
            "{\n\tlog {\n\t\thostnames a.example\n\t\toutput stdout\n\t}\n}\n\n:80 {\n\trespond \"ok\" 200\n}",
        )
        .expect_err("a global logger must not accept hostnames");
        assert!(
            format!("{error}").contains("hostnames is not allowed in the log global options"),
            "the message must name the setting and where it is not allowed: {error}"
        );
    }

    #[test]
    fn output_file_accepts_mode_and_extra_roll_options() {
        let cfg = log_of(
            ":80 {\n log {\n output file /tmp/x.log {\n mode 0644\n dir_mode 0755\n roll_size 1gb\n roll_uncompressed\n roll_compression none\n roll_local_time\n roll_keep 5\n roll_keep_for 90d\n roll_interval 12h\n roll_at 00:00 06:00\n roll_minutes 10 40\n }\n }\n respond \"ok\" 200\n}",
        );
        assert_eq!(cfg.rotation.mode.as_deref(), Some("0644"));
        assert_eq!(cfg.rotation.roll_interval_secs, Some(12 * 3600));
        assert!(cfg.rotation.roll_local_time);
        assert_eq!(cfg.rotation.roll_compression.as_deref(), Some("none"));
    }

    #[test]
    fn flat_filter_delete_fields_compile() {
        let cfg = log_of(
            ":80 {\n log {\n format filter {\n wrap json\n request>headers>Authorization delete\n }\n }\n respond \"ok\" 200\n}",
        );
        assert!(
            cfg.exclude_fields
                .contains(&"request>headers>Authorization".to_string())
        );
    }
}

#[cfg(test)]
mod log_channel_tests {
    use crate::compile;

    /// 🪵 A global channel is declared once and referenced by name.
    #[test]
    fn a_server_can_reference_a_declared_channel() {
        let config = compile(
            "{\n    log errors {\n        output stderr\n        format json\n    }\n}\n\
             http://:8080 {\n    log errors\n    respond \"ok\"\n}\n",
        )
        .expect("a declared channel resolves");
        assert!(config.logging.channels.contains_key("errors"));
        assert_eq!(config.servers[0].log_channels, vec!["errors".to_string()]);
    }

    /// 🚫 A typo must fail closed and say what the real names are.
    ///
    /// The alternative is a site that writes to no channel at all — and the
    /// missing output is exactly what an operator would have used to notice.
    #[test]
    fn referencing_an_undeclared_channel_is_rejected_with_the_known_names() {
        let error = compile(
            "{\n    log errors {\n        output stderr\n    }\n}\n\
             http://:8080 {\n    log erors\n    respond \"ok\"\n}\n",
        )
        .expect_err("a typo must not compile");
        let message = error.to_string();
        assert!(
            message.contains("erors"),
            "name the bad reference: {message}"
        );
        assert!(
            message.contains("errors"),
            "list the declared channels so the typo is obvious: {message}"
        );
    }

    /// 🚫 Declaring one name twice is a mistake, not a merge — the second
    /// block would silently win and the first output would vanish.
    #[test]
    fn a_channel_declared_twice_is_rejected() {
        let error = compile(
            "{\n    log dup {\n        output stderr\n    }\n    log dup {\n        output stdout\n    }\n}\n\
             http://:8080 {\n    respond \"ok\"\n}\n",
        )
        .expect_err("a redeclared channel must not compile");
        assert!(error.to_string().contains("dup"));
    }

    /// 🧾 `log <name> { … }` is upstream's spelling for a *named per-site
    /// logger* — the block configures it. The old refusal treated the name
    /// as a channel reference and rejected the combination.
    #[test]
    fn a_named_site_logger_compiles() {
        let config = compile(
            "http://:8080 {\n    log errors {\n        output stderr\n    }\n    respond \"ok\"\n}\n",
        )
        .expect("a named site logger must compile");
        assert_eq!(config.servers[0].named_logs.len(), 1);
        assert_eq!(config.servers[0].named_logs[0].name, "errors");
        assert!(matches!(
            config.servers[0].named_logs[0].config.output,
            pingclair_core::config::LogOutput::Stderr
        ));
    }

    /// 📝 A bare `log` enables the site's default access sink.
    #[test]
    fn a_bare_log_enables_the_default_sink() {
        let config = compile("http://:8080 {\n    log\n    respond \"ok\"\n}\n")
            .expect("a bare log must compile");
        assert!(config.servers[0].log.is_some());
    }

    /// 🪵 An unnamed global `log { … }` configures the default logger.
    #[test]
    fn an_unnamed_global_log_configures_the_default_logger() {
        let config = compile(
            "{\n    log {\n        output stderr\n        format json\n    }\n}\n\
             http://:8080 {\n    respond \"ok\"\n}\n",
        )
        .expect("an unnamed global log must compile");
        assert!(config.logging.default.is_some());
    }

    /// 🔌 Global `include`/`exclude` reach the compiled default logger.
    ///
    /// The fixture carves one logger out of an included tree, which is the only
    /// shape that means anything when both lists are set. It used to include
    /// `some-source` while excluding `a.api b.api` — a pair upstream refuses,
    /// so the test was green while asserting a configuration Caddy v2.11.4
    /// rejects with "each element must be a superspace or subspace of one in
    /// the other list". Confirmed by running that binary, not by reading.
    #[test]
    fn global_include_and_exclude_compile() {
        let config = compile(
            "{\n    log {\n        output stderr\n        include http.log.access\n        exclude http.log.access.noisy\n    }\n}\n\
             http://:8080 {\n    respond \"ok\"\n}\n",
        )
        .expect("include/exclude must compile");
        let default = config.logging.default.expect("default logger");
        assert_eq!(default.include, vec!["http.log.access".to_string()]);
        assert_eq!(default.exclude, vec!["http.log.access.noisy".to_string()]);
    }

    /// 🚫 Two lists that contradict each other are refused, as upstream does.
    #[test]
    fn global_include_and_exclude_must_be_nested() {
        let error = compile(
            "{\n    log {\n        output stderr\n        include some-source\n        exclude a.api b.api\n    }\n}\n\
             http://:8080 {\n    respond \"ok\"\n}\n",
        )
        .expect_err("an unrelated include/exclude pair cannot be honoured either way");
        assert!(
            format!("{error}").contains("superspace or subspace"),
            "the message must say why the pair is impossible: {error}"
        );
    }

    /// 🚫 `log_skip` compiles as request-scoped middleware.
    #[test]
    fn log_skip_compiles_as_middleware() {
        let config = compile(":80 {\n    log\n    log_skip /hidden*\n    respond \"ok\"\n}\n")
            .expect("log_skip must compile");
        let handler = &config.servers[0].routes[0].handler;
        assert!(
            matches!(
                handler,
                pingclair_core::config::HandlerConfig::Pipeline { handlers }
                    if handlers.iter().any(|element| matches!(
                        &element.handler,
                        pingclair_core::config::HandlerConfig::LogSkip
                    ))
            ),
            "the log_skip route must carry the middleware, got {handler:?}"
        );
    }

    /// 🎯 A site keeps its own inline log while also fanning out to a channel.
    #[test]
    fn an_inline_block_and_a_channel_coexist() {
        let config = compile(
            "{\n    log audit {\n        output stderr\n    }\n}\n\
             http://:8080 {\n    log {\n        output stdout\n    }\n    log audit\n    respond \"ok\"\n}\n",
        )
        .expect("a site may have both");
        assert!(config.servers[0].log.is_some(), "the inline sink survives");
        assert_eq!(config.servers[0].log_channels, vec!["audit".to_string()]);
    }
}
