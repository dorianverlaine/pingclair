// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 📊 Contract tests for `.accessLog`: Caddyfile twins for the shared
//! capabilities and native-only refusals for the shapes that cannot mean
//! anything.

use super::*;

const SITE: &str = "HTTPListener(on: \":8080\") {\n    Site(host: \"*\") { Fallback { Respond(body: \"hi\") } }\n}";

fn native(source: &str) -> PingclairConfig {
    crate::adapt(source).expect("the native source adapts")
}

fn legacy(source: &str) -> PingclairConfig {
    crate::adapt(source).expect("the Caddyfile source adapts")
}

fn log_of(config: &PingclairConfig) -> serde_json::Value {
    serde_json::to_value(&config.servers[0].log).expect("the log serialises")
}

#[test]
fn the_full_access_log_lowers_like_its_caddyfile_twin() {
    let native_source = format!(
        "{SITE}\n\
         .accessLog(\n\
         \x20   output: .file(\"/tmp/access.log\"),\n\
         \x20   format: .json,\n\
         \x20   level: .warn,\n\
         \x20   headers: [.request(\"Authorization\"), .response(\"Content-Type\"), .tls],\n\
         \x20   hostnames: [\"a.example.com\", \"b.example.com\"],\n\
         \x20   include: [\"http.log.access\"],\n\
         \x20   exclude: [\"http.log.error\"],\n\
         \x20   excludeFields: [\"request>headers>Cookie\"],\n\
         \x20   sampling: .window(interval: .minutes(5), first: 100, thereafter: 20),\n\
         \x20   rotation: .roll(\n\
         \x20       size: .mebibytes(100),\n\
         \x20       age: .hours(24),\n\
         \x20       keep: 7,\n\
         \x20       compress: true,\n\
         \x20       mode: \"0644\",\n\
         \x20       dirMode: \"0755\",\n\
         \x20       localTime: true,\n\
         \x20       interval: .hours(12),\n\
         \x20       at: [\"0:00\", \"12:00\"],\n\
         \x20       minutes: [\"0\", \"30\"],\n\
         \x20       compression: .gzip,\n\
         \x20   ),\n\
         )"
    );
    let legacy_source = ":8080 {\n\
         \x20   log {\n\
         \x20       output file /tmp/access.log {\n\
         \x20           mode 0644\n\
         \x20           dir_mode 0755\n\
         \x20           roll_size 100MiB\n\
         \x20           roll_keep 7\n\
         \x20           roll_keep_for 24h\n\
         \x20           roll_interval 12h\n\
         \x20           roll_local_time\n\
         \x20           roll_at 0:00 12:00\n\
         \x20           roll_minutes 0 30\n\
         \x20           roll_compression gzip\n\
         \x20       }\n\
         \x20       level warn\n\
         \x20       format filter {\n\
         \x20           wrap json\n\
         \x20           fields {\n\
         \x20               request>headers>Cookie delete\n\
         \x20           }\n\
         \x20       }\n\
         \x20       headers {\n\
         \x20           request Authorization\n\
         \x20           response Content-Type\n\
         \x20           tls\n\
         \x20       }\n\
         \x20       hostnames a.example.com b.example.com\n\
         \x20       include http.log.access\n\
         \x20       exclude http.log.error\n\
         \x20       sampling {\n\
         \x20           interval 5m\n\
         \x20           first 100\n\
         \x20           thereafter 20\n\
         \x20       }\n\
         \x20   }\n\
         \x20   respond \"hi\"\n\
         }\n";

    assert_eq!(
        log_of(&native(&native_source)),
        log_of(&legacy(legacy_source)),
        "{native_source}"
    );
}

#[test]
fn the_accepted_log_shapes_compile() {
    for modifier in [
        ".accessLog()",
        ".accessLog(output: .stderr, format: .json, level: .info)",
        ".accessLog(headers: [.tls])",
        ".accessLog(hostnames: [\"a.test\"], include: [\"http.log.access\"], exclude: [\"x.y\"])",
        ".accessLog(excludeFields: [\"request>headers>Cookie\"])",
        ".accessLog(sampling: .window(interval: .seconds(5), first: 1, thereafter: 0))",
        ".accessLog(output: .file(\"/tmp/a.log\"), rotation: .roll(size: .mebibytes(1), keep: 2))",
        ".accessLog(output: .file(\"/tmp/a.log\"), rotation: .roll(at: [\"0:00\"], minutes: [\"30\"], dirMode: \"inherit\"))",
    ] {
        let source = format!("{SITE}\n{modifier}");
        assert!(crate::compile(&source).is_ok(), "refused {source:?}");
    }
}

#[test]
fn access_log_mistakes_fail_closed() {
    for modifier in [
        ".accessLog(format: .console)",
        ".accessLog(level: .verbose)",
        ".accessLog(headers: [])",
        ".accessLog(headers: [.request(\"not a header\")])",
        ".accessLog(headers: [.unknown])",
        ".accessLog(hostnames: [])",
        ".accessLog(include: [])",
        ".accessLog(excludeFields: [])",
        ".accessLog(sampling: .window(interval: .minutes(5), first: 100))",
        ".accessLog(sampling: .window(interval: .seconds(0), first: 1, thereafter: 1))",
        ".accessLog(sampling: .window(interval: .seconds(5), first: 0, thereafter: 1))",
        ".accessLog(sampling: .unknown(interval: .seconds(5)))",
        ".accessLog(unknown: 1)",
        ".accessLog(format: .json, format: .text)",
        ".accessLog(rotation: .roll(size: .mebibytes(1)))",
        ".accessLog(output: .file(\"/tmp/a.log\"), rotation: .roll(keep: 7))",
        ".accessLog(output: .file(\"/tmp/a.log\"), rotation: .roll(size: .mebibytes(0)))",
        ".accessLog(output: .file(\"/tmp/a.log\"), rotation: .roll(size: .mebibytes(1), keep: 0))",
        ".accessLog(output: .file(\"/tmp/a.log\"), rotation: .roll(size: .mebibytes(1), mode: \"999\"))",
        ".accessLog(output: .file(\"/tmp/a.log\"), rotation: .roll(size: .mebibytes(1), at: [\"25:00\"]))",
        ".accessLog(output: .file(\"/tmp/a.log\"), rotation: .roll(size: .mebibytes(1), minutes: [\"60\"]))",
        ".accessLog(output: .file(\"/tmp/a.log\"), rotation: .roll(size: .mebibytes(1), compression: .brotli))",
    ] {
        let source = format!("{SITE}\n{modifier}");
        assert!(crate::compile(&source).is_err(), "accepted {source:?}");
    }
}

#[test]
fn the_formatter_round_trips_the_log_shapes() {
    let source = format!(
        "{SITE}\n.accessLog(output: .file(\"/tmp/a.log\"), rotation: .roll(size: .mebibytes(100), keep: 7), sampling: .window(interval: .minutes(5), first: 100, thereafter: 20))\n"
    );
    let formatted = crate::format::format(&source).expect("the source formats");
    assert!(formatted.contains(".mebibytes(100)"), "{formatted}");
    assert_eq!(
        crate::format::format(&formatted).expect("idempotent"),
        formatted
    );
}
