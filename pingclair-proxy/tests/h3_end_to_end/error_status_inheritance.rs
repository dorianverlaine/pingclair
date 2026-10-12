//! 🚨 `respond` keeps the error status in `handle_errors` over HTTP/3 too.

use super::*;

#[tokio::test]
async fn h3_respond_inherits_errors_and_honors_overrides() {
    let source = r#":8080 {
    handle_errors 503 504 {
        header X-Error-Route inherited
        respond "inherited"
    }
    handle_errors 404 {
        respond "overridden" 200
    }
    handle_errors 502 {
        respond "created" 201
    }
    handle /503 {
        error 503
    }
    handle /504 {
        error 504
    }
    handle /404 {
        error 404
    }
    handle /502 {
        error 502
    }
    handle {
        respond "ordinary"
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
