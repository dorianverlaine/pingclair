//! 🚨 Native error response status inheritance also applies over HTTP/3.

use super::*;

#[tokio::test]
async fn h3_native_respond_inherits_errors_and_honors_overrides() {
    let source = r#"HTTPListener(on: ":443") {
        Site(host: "*") {
            ErrorRoute(for: [.status(503), .status(504)]) {
                ResponseHeader(.set("X-Error-Route", "inherited"))
                Respond(body: "inherited")
            }
            ErrorRoute(for: [.status(404)]) { Respond(body: "overridden", status: 200) }
            ErrorRoute(for: [.status(502)]) { Respond(body: "created", status: 201) }
            Route(when: .path(exact: "/503")) { Fail(status: 503) }
            Route(when: .path(exact: "/504")) { Fail(status: 504) }
            Route(when: .path(exact: "/404")) { Fail(status: 404) }
            Route(when: .path(exact: "/502")) { Fail(status: 502) }
            Fallback { Respond(body: "ordinary") }
        }
    }"#;
    let site = pingclair_config::compile(source).unwrap().servers.remove(0);
    let server = spawn_h3_server_with(|address| ServerConfig {
        listen: vec![address.to_string()],
        ..site
    })
    .await;
    let mut seen = Vec::new();
    for path in ["/503", "/504", "/404", "/502", "/ordinary"] {
        let response = h3_get(server, path).await.unwrap();
        if matches!(path, "/503" | "/504") {
            assert!(
                response
                    .headers
                    .iter()
                    .any(|(name, value)| { name == "x-error-route" && value == "inherited" })
            );
        }
        seen.push((response.status, String::from_utf8(response.body).unwrap()));
    }
    assert_eq!(
        seen,
        vec![
            (503, "inherited".to_string()),
            (504, "inherited".to_string()),
            (200, "overridden".to_string()),
            (201, "created".to_string()),
            (200, "ordinary".to_string()),
        ]
    );
}
