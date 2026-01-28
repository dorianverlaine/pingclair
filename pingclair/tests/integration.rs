use std::process::{Command, Child};
use std::time::Duration;
use std::path::PathBuf;
use std::io::Write;

struct TestServer {
    process: Child,
    config_path: PathBuf,
}

impl TestServer {
    fn new(config_body: &str) -> Self {
        let mut config_path = std::env::temp_dir();
        config_path.push(format!("pingclair-test-{}.json", uuid::Uuid::new_v4()));

        // Write config
        let mut file = std::fs::File::create(&config_path).unwrap();
        file.write_all(config_body.as_bytes()).unwrap();

        // Create temporary TLS store directory for testing
        let mut tls_store_path = std::env::temp_dir();
        tls_store_path.push(format!("pingclair-tls-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tls_store_path).unwrap();

        // Start server using the compiled binary (avoids cargo lock issues)
        let bin_path = env!("CARGO_BIN_EXE_pingclair");

        let process = Command::new(bin_path)
            .arg("run")
            .arg(config_path.to_str().unwrap())
            .env("PINGCLAIR_TLS_STORE", tls_store_path.to_str().unwrap())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("Failed to start server");

        Self {
            process,
            config_path,
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = std::fs::remove_file(&self.config_path);
    }
}

async fn wait_for_server(url: &str, server: &mut TestServer) -> bool {
    let client = reqwest::Client::new();
    for _ in 0..50 {
        // Check if process is still alive
        if let Ok(Some(status)) = server.process.try_wait() {
             // Process exited prematurely
             eprintln!("Server exited unexpectedly with status: {}", status);
             // Dump stderr
             if let Some(mut stderr) = server.process.stderr.take() {
                 use std::io::Read;
                 let mut s = String::new();
                 stderr.read_to_string(&mut s).unwrap();
                 eprintln!("STDERR:\n{}", s);
             }
             if let Some(mut stdout) = server.process.stdout.take() {
                 use std::io::Read;
                 let mut s = String::new();
                 stdout.read_to_string(&mut s).unwrap();
                 eprintln!("STDOUT:\n{}", s);
             }
             return false;
        }

        if client.get(url).send().await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    
    // Timeout
    eprintln!("Timeout waiting for server!");
     if let Some(mut stderr) = server.process.stderr.take() {
                 use std::io::Read;
                 let mut s = String::new();
                 stderr.read_to_string(&mut s).unwrap();
                 eprintln!("STDERR:\n{}", s);
     }
    false
}

#[tokio::test]
async fn test_static_file_server() {
    // 1. Setup static file content
    let tmp_dir = tempfile::tempdir().unwrap();
    let file_path = tmp_dir.path().join("index.html");
    std::fs::write(&file_path, "<h1>Hello World</h1>").unwrap();
    let root_path = tmp_dir.path().to_str().unwrap().replace("\\", "/");

    // 2. Create config (JSON format)
    let config = format!(r#"{{
        "servers": [
            {{
                "listen": ["127.0.0.1:9091"],
                "routes": [
                    {{
                        "path": "/",
                        "handler": {{
                            "type": "file_server",
                            "root": "{}"
                        }}
                    }}
                ]
            }}
        ]
    }}"#, root_path);

    // 3. Start Server
    let mut server = TestServer::new(&config);
    
    // 4. Wait
    assert!(wait_for_server("http://127.0.0.1:9091/index.html", &mut server).await, "Server failed to start");
    
    // 5. Assert
    let resp = reqwest::get("http://127.0.0.1:9091/index.html").await.unwrap();
    assert_eq!(resp.status(), 200);
    let text = resp.text().await.unwrap();
    assert_eq!(text, "<h1>Hello World</h1>");
}

#[tokio::test]
async fn test_admin_api_hot_reload() {
    // Setup content for v1 and v2
    let tmp_dir = tempfile::tempdir().unwrap();
    let v1_path = tmp_dir.path().join("v1.txt");
    let v2_path = tmp_dir.path().join("v2.txt");
    std::fs::write(&v1_path, "Version 1").unwrap();
    std::fs::write(&v2_path, "Version 2").unwrap();
    let root_path = tmp_dir.path().to_str().unwrap().replace("\\", "/");

    // 1. Start with initial config (JSON)
    let init_config = format!(r#"{{
        "admin": {{
            "enabled": true,
            "listen": "127.0.0.1:9092"
        }},
        "servers": [
            {{
                "listen": ["127.0.0.1:9093"],
                "routes": [
                    {{
                        "path": "/",
                        "handler": {{
                            "type": "file_server",
                            "root": "{}",
                            "index": ["v1.txt"]
                        }}
                    }}
                ]
            }}
        ]
    }}"#, root_path);

    let mut server = TestServer::new(&init_config);
    assert!(wait_for_server("http://127.0.0.1:9093/", &mut server).await, "Server V1 failed to start");
    
    // Check V1 (matches index v1.txt)
    let resp = reqwest::get("http://127.0.0.1:9093/").await.unwrap();
    assert_eq!(resp.text().await.unwrap(), "Version 1");
    
    // 2. Perform Hot Reload (JSON Payload)
    let new_config_obj = serde_json::json!({
        "listen": ["127.0.0.1:9093"],
        "routes": [
            {
                "path": "/",
                "handler": {
                    "type": "file_server",
                    "root": root_path,
                    "index": ["v2.txt"],
                    "browse": false
                }
            }
        ]
    });
    
    let client = reqwest::Client::new();
    let reload_resp = client.post("http://127.0.0.1:9092/config/0")
        .json(&new_config_obj)
        .send()
        .await
        .unwrap();
        
    assert_eq!(reload_resp.status(), 200);
    
    // 3. Check V2
    tokio::time::sleep(Duration::from_millis(200)).await;
    
    let resp_v2 = reqwest::get("http://127.0.0.1:9093/").await.unwrap();
    assert_eq!(resp_v2.text().await.unwrap(), "Version 2");
}

#[tokio::test]
async fn test_compression() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let file_path = tmp_dir.path().join("big.txt");
    // Create a large enough file to benefit from compression
    let content = "Pingclair Compression Test ".repeat(100);
    std::fs::write(&file_path, &content).unwrap();
    let root_path = tmp_dir.path().to_str().unwrap().replace("\\", "/");

    let config = format!(r#"{{
        "servers": [
            {{
                "listen": ["127.0.0.1:9094"],
                "routes": [
                    {{
                        "path": "/",
                        "handler": {{
                            "type": "file_server",
                            "root": "{}",
                            "compress": true
                        }}
                    }}
                ]
            }}
        ]
    }}"#, root_path);

    let mut server = TestServer::new(&config);
    assert!(wait_for_server("http://127.0.0.1:9094/big.txt", &mut server).await, "Server failed to start");

    let client = reqwest::Client::builder()
        .build()
        .unwrap();

    // Request with gzip
    let resp: reqwest::Response = client.get("http://127.0.0.1:9094/big.txt")
        .header("Accept-Encoding", "gzip")
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get("Content-Encoding").unwrap(), "gzip");
    
    let compressed_bytes = resp.bytes().await.expect("Failed to get bytes");
    
    // Decompress manually
    use flate2::read::GzDecoder;
    use std::io::Read;
    let mut decoder = GzDecoder::new(&compressed_bytes[..]);
    let mut decompressed = String::new();
    decoder.read_to_string(&mut decompressed).expect("Failed to decompress");
    
    assert_eq!(decompressed, content);

    // Request with brotli if supported
    let resp_br: reqwest::Response = client.get("http://127.0.0.1:9094/big.txt")
        .header("Accept-Encoding", "br")
        .send()
        .await
        .expect("Failed to send br request");
    
    // reqwest might not support br by default without features, but we can check the header if we manually set it
    // Our server implementation prioritize br > zstd > gzip
    if resp_br.headers().get("Content-Encoding").map(|v| v == "br").unwrap_or(false) {
        println!("Brotli verified");
    }
}
