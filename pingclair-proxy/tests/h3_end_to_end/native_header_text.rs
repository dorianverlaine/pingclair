//! 📝 Native headers preserve literal text over HTTP/3 too.

use super::*;

#[tokio::test]
async fn h3_native_header_literals_reach_both_sides_of_the_exchange() {
    let (origin, mut heads, _) = spawn_scripted_upstream(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    )
    .await;
    let source = format!(
        r#"HTTPListener(on: ":8080") {{
        Site(host: "*") {{ Fallback {{
            RequestHeader(.set("X-Request", "{{host}}"), .append("X-Request", "{{path}}"))
            ResponseHeader(.set("X-Response", "{{host}}"), .append("X-Response", "{{path}}"),
                           .setIfAbsent("X-Default", "{{host}}"))
            Proxy(to: "{origin}", headersUp: [.set("X-Up", "{{host}}"), .append("X-Up", "{{path}}")],
                  headersDown: [.append("X-Down", "{{path}}")])
        }} }}
    }}"#
    );
    let site = pingclair_config::compile(&source)
        .unwrap()
        .servers
        .remove(0);
    let server = spawn_h3_server_with(|address| ServerConfig {
        listen: vec![address.to_string()],
        ..site
    })
    .await;
    let response = h3_get(server, "/literal").await.unwrap();
    assert_eq!(response.status, 200);
    let values: Vec<_> = response
        .headers
        .iter()
        .filter(|(name, _)| name == "x-response")
        .map(|(_, value)| value.as_str())
        .collect();
    assert_eq!(values, ["{host}", "{path}"]);
    for field in [("x-default", "{host}"), ("x-down", "{path}")] {
        assert!(
            response
                .headers
                .iter()
                .any(|(name, value)| (name.as_str(), value.as_str()) == field)
        );
    }
    let head = heads.recv().await.unwrap().to_ascii_lowercase();
    for field in [
        "x-request: {host}",
        "x-request: {path}",
        "x-up: {host}",
        "x-up: {path}",
    ] {
        assert!(head.contains(field), "missing literal {field}: {head}");
    }
}
