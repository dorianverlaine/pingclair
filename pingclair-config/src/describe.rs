// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 📇 What the language accepts, as data: the source `pingclair describe` prints.
//!
//! Every entry carries a canonical example and a refusal. Tests compile the
//! examples and refuse the refusals, so this table cannot drift from the parser
//! without turning red.

use serde_json::json;

/// What a described name is.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Component,
    Modifier,
    Attribute,
}

impl Kind {
    fn label(self) -> &'static str {
        match self {
            Kind::Component => "component",
            Kind::Modifier => "modifier",
            Kind::Attribute => "attribute",
        }
    }
}

/// One described name.
#[derive(Clone, Copy)]
pub struct Entry {
    pub name: &'static str,
    pub kind: Kind,
    pub summary: &'static str,
    pub example: &'static str,
    pub refusal: &'static str,
}

pub const ENTRIES: &[Entry] = &[
    Entry {
        name: "TCPListener",
        kind: Kind::Component,
        summary: "Raw TCP listener; routes by TLS ClientHello or peer address.",
        example: r#"TCPListener(on: "127.0.0.1:9443") {
    Route(when: .tls(sni: ["example.test"])) { Proxy(to: "127.0.0.1:8443") }
    Fallback { Proxy(to: "127.0.0.1:8080") }
}"#,
        refusal: r#"TCPListener(on: "127.0.0.1:9443") {
    Unknown { Proxy(to: "127.0.0.1:8080") }
}"#,
    },
    Entry {
        name: "Route",
        kind: Kind::Component,
        summary: "A conditional route: `when:`/`from:` plus exactly one `Proxy`.",
        example: r#"TCPListener(on: "127.0.0.1:9443") {
    Route(when: .tls(sni: ["example.test"]), from: ["127.0.0.0/8"]) {
        Proxy(to: "127.0.0.1:8443")
    }
}"#,
        refusal: r#"TCPListener(on: "127.0.0.1:9443") {
    Route(when: .tls(sni: ["example.test"])) { }
}"#,
    },
    Entry {
        name: "Fallback",
        kind: Kind::Component,
        summary: "The unconditional final route of a listener.",
        example: r#"TCPListener(on: "127.0.0.1:9443") {
    Fallback { Proxy(to: "127.0.0.1:8080") }
}"#,
        refusal: r#"TCPListener(on: "127.0.0.1:9443") {
    Fallback(when: .tls()) { Proxy(to: "127.0.0.1:8080") }
}"#,
    },
    Entry {
        name: "Proxy",
        kind: Kind::Component,
        summary: "The upstream connection: `Proxy(to: \"host:port\")`.",
        example: r#"TCPListener(on: "127.0.0.1:9443") {
    Fallback { Proxy(to: "127.0.0.1:8080") }
}"#,
        refusal: r#"TCPListener(on: "127.0.0.1:9443") {
    Fallback { Proxy(to: 8080) }
}"#,
    },
    Entry {
        name: "HTTPListener",
        kind: Kind::Component,
        summary: "A plaintext HTTP listener serving one or more sites.",
        example: r#"HTTPListener(on: ":8080") {
    Site(host: "*") {
        Fallback { Respond(body: "hello", status: 200) }
    }
}"#,
        refusal: r#"HTTPListener(on: ":8080") {}"#,
    },
    Entry {
        name: "Site",
        kind: Kind::Component,
        summary: "One virtual host inside an HTTP listener.",
        example: r#"HTTPListener(on: ":8080") {
    Site(host: "example.test") {
        Fallback { Respond(body: "hello") }
    }
}"#,
        refusal: r#"HTTPListener(on: ":8080") {
    Site(host: "example.test") { }
}"#,
    },
    Entry {
        name: "Respond",
        kind: Kind::Component,
        summary: "A fixed HTTP response: `Respond(body:, status:)`.",
        example: r#"HTTPListener(on: ":8080") {
    Site(host: "*") {
        Fallback { Respond(body: "hello", status: 200) }
    }
}"#,
        refusal: r#"HTTPListener(on: ":8080") {
    Site(host: "*") {
        Fallback { Respond(body: "hello", status: 999999) }
    }
}"#,
    },
    Entry {
        name: "Admin",
        kind: Kind::Component,
        summary: "The admin endpoint; one declaration per file.",
        example: r#"Admin(listen: "127.0.0.1:2019")
TCPListener(on: "127.0.0.1:9443") { Fallback { Proxy(to: "127.0.0.1:8080") } }"#,
        refusal: r#"Admin(listen: "127.0.0.1:2019")
Admin(listen: "127.0.0.1:2020")
TCPListener(on: "127.0.0.1:9443") { Fallback { Proxy(to: "127.0.0.1:8080") } }"#,
    },
    Entry {
        name: "Metrics",
        kind: Kind::Component,
        summary: "The metrics collection switch.",
        example: r#"Metrics(enabled: true)
TCPListener(on: "127.0.0.1:9443") { Fallback { Proxy(to: "127.0.0.1:8080") } }"#,
        refusal: r#"Metrics(enabled: 1)
TCPListener(on: "127.0.0.1:9443") { Fallback { Proxy(to: "127.0.0.1:8080") } }"#,
    },
    Entry {
        name: "Shutdown",
        kind: Kind::Component,
        summary: "The shutdown grace period; whole seconds.",
        example: r#"Shutdown(grace: .seconds(5))
TCPListener(on: "127.0.0.1:9443") { Fallback { Proxy(to: "127.0.0.1:8080") } }"#,
        refusal: r#"Shutdown(grace: 5)
TCPListener(on: "127.0.0.1:9443") { Fallback { Proxy(to: "127.0.0.1:8080") } }"#,
    },
    Entry {
        name: "limits",
        kind: Kind::Modifier,
        summary: "Connection count and buffer bounds for a TCP listener.",
        example: r#"TCPListener(on: "127.0.0.1:9443") {
    Fallback { Proxy(to: "127.0.0.1:8080") }
}
.limits(connections: 1024, preread: .kibibytes(16), relay: .kibibytes(16))"#,
        refusal: r#"TCPListener(on: "127.0.0.1:9443") {
    Fallback { Proxy(to: "127.0.0.1:8080") }
}
.limits(connections: 0)"#,
    },
    Entry {
        name: "timeouts",
        kind: Kind::Modifier,
        summary: "Preread, connect, and idle deadlines for a TCP listener.",
        example: r#"TCPListener(on: "127.0.0.1:9443") {
    Fallback { Proxy(to: "127.0.0.1:8080") }
}
.timeouts(preread: .seconds(30), connect: .seconds(5), idle: .minutes(5))"#,
        refusal: r#"TCPListener(on: "127.0.0.1:9443") {
    Fallback { Proxy(to: "127.0.0.1:8080") }
}
.timeouts(connect: 5)"#,
    },
    Entry {
        name: "halfClose",
        kind: Kind::Modifier,
        summary: "Whether each direction propagates EOF independently.",
        example: r#"TCPListener(on: "127.0.0.1:9443") {
    Fallback { Proxy(to: "127.0.0.1:8080") }
}
.halfClose(enabled: true)"#,
        refusal: r#"TCPListener(on: "127.0.0.1:9443") {
    Fallback { Proxy(to: "127.0.0.1:8080") }
}
.halfClose(enabled: 1)"#,
    },
    Entry {
        name: "Matcher",
        kind: Kind::Attribute,
        summary: "Marks a condition binding so `when:` accepts it.",
        example: r#"@Matcher
let secure = .tls(sni: ["example.test"])
TCPListener(on: "127.0.0.1:9443") {
    Route(when: secure) { Proxy(to: "127.0.0.1:8443") }
}"#,
        refusal: r#"@Matcher
let secure = "text"
TCPListener(on: "127.0.0.1:9443") { Fallback { Proxy(to: "127.0.0.1:8080") } }"#,
    },
    Entry {
        name: "Secret",
        kind: Kind::Attribute,
        summary: "Marks a value binding that never reaches any output.",
        example: r#"@Secret
let token = "placeholder"
TCPListener(on: "127.0.0.1:9443") { Fallback { Proxy(to: "127.0.0.1:8080") } }"#,
        refusal: r#"@Secret
let backend = Proxy(to: "127.0.0.1:8080")
TCPListener(on: "127.0.0.1:9443") { Fallback { Proxy(to: "127.0.0.1:8080") } }"#,
    },
];

/// Finds an entry by name; attributes may be written with or without `@`.
pub fn find(name: &str) -> Option<&'static Entry> {
    ENTRIES.iter().find(|entry| {
        entry.name == name
            || (entry.kind == Kind::Attribute && name.strip_prefix('@') == Some(entry.name))
    })
}

fn select(name: Option<&str>) -> Result<Vec<&'static Entry>, String> {
    match name {
        None => Ok(ENTRIES.iter().collect()),
        Some(name) => match find(name) {
            Some(entry) => Ok(vec![entry]),
            None => Err(format!(
                "unknown component '{name}'; run `pingclair describe` for the full list"
            )),
        },
    }
}

/// Renders the entries for humans.
pub fn render_text(name: Option<&str>) -> Result<String, String> {
    let entries = select(name)?;
    let mut rendered = String::new();
    for (index, entry) in entries.iter().enumerate() {
        if index > 0 {
            rendered.push('\n');
        }
        rendered.push_str(&format!("{} — {}\n", entry.name, entry.kind.label()));
        rendered.push_str(&format!("  {}\n", entry.summary));
        rendered.push_str("  example:\n");
        for line in entry.example.lines() {
            rendered.push_str(&format!("    {line}\n"));
        }
        rendered.push_str("  refused:\n");
        for line in entry.refusal.lines() {
            rendered.push_str(&format!("    {line}\n"));
        }
    }
    Ok(rendered)
}

/// Renders the entries as JSON for tools and agents.
pub fn render_json(name: Option<&str>) -> Result<String, String> {
    let entries = select(name)?;
    let value = json!({
        "entries": entries
            .iter()
            .map(|entry| json!({
                "name": entry.name,
                "kind": entry.kind.label(),
                "summary": entry.summary,
                "example": entry.example,
                "refusal": entry.refusal,
            }))
            .collect::<Vec<_>>(),
    });
    serde_json::to_string_pretty(&value).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_example_compiles_and_every_refusal_is_refused() {
        for entry in ENTRIES {
            crate::compile(entry.example).unwrap_or_else(|error| {
                panic!("{} example failed to compile: {error}", entry.name)
            });
            assert!(
                crate::compile(entry.refusal).is_err(),
                "{} refusal compiled",
                entry.name
            );
        }
    }

    #[test]
    fn every_entry_names_itself_in_its_example() {
        for entry in ENTRIES {
            assert!(
                entry.example.contains(entry.name),
                "{} example does not name the entry",
                entry.name
            );
        }
    }

    #[test]
    fn lookups_accept_attributes_with_at_signs() {
        assert!(find("TCPListener").is_some());
        assert!(find("@Matcher").is_some());
        assert!(find("Matcher").is_some());
        assert!(find("tcpListener").is_none());
    }

    #[test]
    fn unknown_names_are_refused_with_the_list_hint() {
        let error = render_text(Some("Unknown")).unwrap_err();
        assert!(error.contains("unknown component 'Unknown'"), "{error}");
    }

    #[test]
    fn json_lists_every_entry() {
        let rendered = render_json(None).unwrap();
        for entry in ENTRIES {
            assert!(rendered.contains(entry.name), "json missing {}", entry.name);
        }
    }
}
