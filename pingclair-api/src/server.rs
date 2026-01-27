//! Admin API Server

use std::net::SocketAddr;
use std::sync::Arc;
use std::convert::Infallible;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, Method};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use http_body_util::{BodyExt, Full};
use bytes::Bytes;
use parking_lot::RwLock;

use pingclair_core::config::ServerConfig;


/// Run the admin server
pub async fn run_admin_server(
    addr: SocketAddr,
    proxies: Arc<RwLock<std::collections::HashMap<String, pingclair_proxy::server::PingclairProxy>>>,
) -> pingclair_core::Result<()> {
    let listener = TcpListener::bind(addr).await
        .map_err(|e| pingclair_core::Error::Server(format!("Failed to bind admin API: {}", e)))?;
    
    tracing::info!("🔧 Admin API listening on http://{}", addr);
    
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("Admin accept error: {}", e);
                continue;
            }
        };

        let io = TokioIo::new(stream);
        let proxies = proxies.clone();

        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(io, service_fn(move |req| handle_request(req, proxies.clone())))
                .await
            {
                tracing::error!("Error serving connection: {:?}", err);
            }
        });
    }
}

async fn handle_request(
    req: Request<hyper::body::Incoming>,
    proxies: Arc<RwLock<std::collections::HashMap<String, pingclair_proxy::server::PingclairProxy>>>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/health") => {
            Ok(Response::new(Full::new(Bytes::from(r#"{"status":"healthy"}"#))))
        },
        (&Method::GET, "/metrics") => {
            let buffer = pingclair_proxy::metrics::gather();
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "text/plain; version=0.0.4")
                .body(Full::new(Bytes::from(buffer)))
                .unwrap())
        },
        (&Method::GET, "/config") => {
            let mut configs = std::collections::HashMap::new();
            let proxies_guard = proxies.read();
            for (addr, proxy) in proxies_guard.iter() {
                let mut host_configs = Vec::new();
                for host_state in proxy.hosts.read().values() {
                    host_configs.push(host_state.config.as_ref().clone());
                }
                if let Some(def) = proxy.default.read().as_ref() {
                    host_configs.push(def.config.as_ref().clone());
                }
                configs.insert(addr.clone(), host_configs);
            }
            
            let json = serde_json::to_string_pretty(&configs).unwrap_or_default();
            Ok(Response::new(Full::new(Bytes::from(json))))
        },
        (&Method::POST, path) if path.starts_with("/config") => {
            let body_bytes = req.collect().await.unwrap().to_bytes();
            let config: ServerConfig = match serde_json::from_slice(&body_bytes) {
                Ok(c) => c,
                Err(e) => return Ok(response(StatusCode::BAD_REQUEST, &format!("Invalid config: {}", e))),
            };

            let proxies_guard = proxies.read();
            let mut updated = 0;

            for addr in &config.listen {
                if let Some(proxy) = proxies_guard.get(addr) {
                    proxy.add_server(config.clone());
                    updated += 1;
                    tracing::info!("Hot reloaded config for {}", addr);
                } else {
                    tracing::warn!("No proxy found for listen address: {}", addr);
                }
            }
            
            if updated > 0 {
                Ok(response(StatusCode::OK, "Config updated"))
            } else {
                Ok(response(StatusCode::NOT_FOUND, "No matching server found"))
            }
        },
        _ => Ok(response(StatusCode::NOT_FOUND, "Not Found")),
    }
}

fn response(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}
