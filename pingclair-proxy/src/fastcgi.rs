// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧵 Transport-neutral FastCGI request preparation and exchange.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

use bytes::Bytes;
use pingclair_core::config::FastCgiTransportConfig;
use pingora_http::RequestHeader;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::http_policy::{RequestVars, authority_host};
use crate::upstream::Upstream;

/// 🧵 A boxed stream lets the same exchange own TCP and Unix sockets.
trait FastCgiStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> FastCgiStream for T {}

/// 🚨 A failure category callers can translate into their downstream transport.
#[derive(Debug)]
pub(crate) enum ExchangeError {
    /// 🔌 The selected peer could not be reached.
    Dial(std::io::Error),
    /// ⏱️ The configured connection deadline elapsed.
    DialTimedOut,
    /// 📡 The FastCGI record exchange failed after connection establishment.
    Protocol(pingclair_fastcgi::FastCgiError),
    /// 🏗️ The selected backend does not expose a usable socket path.
    InvalidTarget,
}

impl ExchangeError {
    /// 🩺 Whether this failure is evidence about the responder, or about us.
    ///
    /// FastCGI dials the responder itself rather than going through Pingora's
    /// connector, so the original errno survives intact and needs none of the
    /// cause-chain archaeology documented in
    /// [`crate::upstream_failure::classify_connect_error`]. The two paths must
    /// still agree: an operator reading the log cannot be expected to know
    /// which upstream kind rewrote their error on the way out.
    pub(crate) fn origin(&self) -> crate::upstream_failure::FailureOrigin {
        use crate::upstream_failure::FailureOrigin;
        match self {
            Self::Dial(error) => crate::upstream_failure::classify_dial_error(error),
            // ⏱️ A deadline that elapsed is the responder failing to answer in
            // time, which is exactly what a health signal is for.
            Self::DialTimedOut => FailureOrigin::Remote,
            // 📡 Framing errors happen after the connection is up, so the
            // responder is the one that misbehaved.
            Self::Protocol(_) => FailureOrigin::Remote,
            // 🏗️ A backend with no usable socket path is a configuration
            // problem on this side. Benching it would not make the next
            // request find a path that was never there.
            Self::InvalidTarget => FailureOrigin::Local,
        }
    }
}

impl std::fmt::Display for ExchangeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dial(error) => write!(formatter, "FastCGI dial failed: {error}"),
            Self::DialTimedOut => formatter.write_str("FastCGI dial timed out"),
            Self::Protocol(error) => write!(formatter, "{error}"),
            Self::InvalidTarget => formatter.write_str("FastCGI target is invalid"),
        }
    }
}

impl From<pingclair_fastcgi::FastCgiError> for ExchangeError {
    fn from(error: pingclair_fastcgi::FastCgiError) -> Self {
        Self::Protocol(error)
    }
}

/// 🧵 One selected FastCGI connection shared by the H1/H2 and H3 paths.
pub(crate) struct Exchange {
    client: pingclair_fastcgi::Client<Box<dyn FastCgiStream>>,
}

impl Exchange {
    /// 🔌 Dials one load-balanced backend with the route's configured deadline.
    pub(crate) async fn connect(
        upstream: &Upstream,
        config: &FastCgiTransportConfig,
    ) -> Result<Self, ExchangeError> {
        let timeout = Duration::from_millis(config.dial_timeout_ms.unwrap_or(3_000));
        let stream: Box<dyn FastCgiStream> = match &upstream.addr {
            pingora_core::protocols::l4::socket::SocketAddr::Inet(address) => {
                match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(address)).await {
                    Ok(Ok(stream)) => Box::new(stream),
                    Ok(Err(error)) => return Err(ExchangeError::Dial(error)),
                    Err(_) => return Err(ExchangeError::DialTimedOut),
                }
            }
            #[cfg(unix)]
            pingora_core::protocols::l4::socket::SocketAddr::Unix(address) => {
                let path = address.as_pathname().ok_or(ExchangeError::InvalidTarget)?;
                match tokio::time::timeout(timeout, tokio::net::UnixStream::connect(path)).await {
                    Ok(Ok(stream)) => Box::new(stream),
                    Ok(Err(error)) => return Err(ExchangeError::Dial(error)),
                    Err(_) => return Err(ExchangeError::DialTimedOut),
                }
            }
        };
        Ok(Self {
            client: pingclair_fastcgi::Client::new(
                stream,
                1,
                config.read_timeout_ms.map(Duration::from_millis),
                config.write_timeout_ms.map(Duration::from_millis),
                config.capture_stderr,
            ),
        })
    }

    /// 🚀 Opens the responder request and sends its complete CGI environment.
    pub(crate) async fn begin(
        &mut self,
        environment: &BTreeMap<String, String>,
    ) -> Result<(), ExchangeError> {
        self.client.begin_request().await?;
        self.client.send_params(environment).await?;
        Ok(())
    }

    /// 📥 Streams one downstream request-body chunk as FastCGI `STDIN`.
    pub(crate) async fn send_body(&mut self, chunk: &[u8]) -> Result<(), ExchangeError> {
        self.client.send_stdin(chunk).await.map_err(Into::into)
    }

    /// 🏁 Completes the request body before the response header is read.
    pub(crate) async fn finish_body(&mut self) -> Result<(), ExchangeError> {
        self.client.finish_stdin().await.map_err(Into::into)
    }

    /// 🧾 Reads the CGI response header before downstream commitment.
    pub(crate) async fn read_response_header(
        &mut self,
    ) -> Result<pingclair_fastcgi::ResponseHeader, ExchangeError> {
        self.client.read_response_header().await.map_err(Into::into)
    }

    /// 📤 Reads one bounded response record.
    pub(crate) async fn read_body_chunk(&mut self) -> Result<Option<Bytes>, ExchangeError> {
        self.client.read_body_chunk().await.map_err(Into::into)
    }

    /// 🛑 Requests responder cancellation before the socket is dropped.
    pub(crate) async fn abort(&mut self) {
        self.client.abort().await;
    }

    /// ⚠️ Returns the bounded stderr captured by the protocol client.
    pub(crate) fn take_stderr(&mut self) -> Vec<u8> {
        self.client.take_stderr()
    }
}

/// 🧾 Request metadata needed to build a CGI environment without a transport session.
pub(crate) struct EnvironmentInput<'a> {
    pub(crate) request: &'a RequestHeader,
    pub(crate) remote_ip: IpAddr,
    pub(crate) remote_port: Option<u16>,
    pub(crate) scheme: &'static str,
    pub(crate) original_uri: &'a str,
    pub(crate) request_vars: &'a RequestVars,
}

/// 🧰 Applies configured upstream header templates before CGI conversion.
pub(crate) fn prepare_request_header(
    request: &RequestHeader,
    headers_up: &BTreeMap<String, String>,
    verified_client_ip: Option<&str>,
    scheme: &'static str,
    request_vars: &RequestVars,
) -> Result<RequestHeader, ()> {
    let mut prepared = request.clone();
    for (name, template) in headers_up {
        let resolved = crate::server::resolve_caddy_placeholders(
            template,
            request,
            verified_client_ip,
            scheme,
            request_vars,
        );
        prepared
            .insert_header(name.clone(), resolved.as_ref())
            .map_err(|_| ())?;
    }
    Ok(prepared)
}

/// 🧾 Builds the CGI variables shared by every downstream HTTP version.
pub(crate) fn build_environment(
    input: EnvironmentInput<'_>,
    config: &FastCgiTransportConfig,
) -> std::io::Result<BTreeMap<String, String>> {
    let request = input.request;
    let path = request.uri.path();
    let mut root = config.root.clone().unwrap_or_else(|| ".".to_string());
    if config.resolve_root_symlink {
        // 🔗 This option deliberately resolves on each request: deployment
        // symlinks may move while PHP opcache keeps the resolved script path.
        root = std::fs::canonicalize(&root)?.to_string_lossy().into_owned();
    }

    let split_position = split_position(path, &config.split_path);
    let (document_uri, mut path_info) = match split_position {
        Some(position) => (&path[..position], path[position..].to_string()),
        None => (path, String::new()),
    };
    if path_info.is_empty() {
        path_info = input
            .request_vars
            .get("http.matchers.file.remainder")
            .unwrap_or("")
            .to_string();
    }
    let script_name = if path_info.is_empty() {
        path.to_string()
    } else {
        path.trim_end_matches(&path_info).to_string()
    };
    let script_name = if script_name.starts_with('/') {
        script_name
    } else {
        format!("/{script_name}")
    };

    let authority = request_authority(request);
    let host = authority_host(authority);
    let port = http::uri::Authority::from_str(authority)
        .ok()
        .and_then(|authority| authority.port_u16())
        .unwrap_or(if input.scheme == "https" { 443 } else { 80 });
    let protocol = match request.version {
        http::Version::HTTP_2 => "HTTP/2.0",
        http::Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/1.1",
    };
    let request_uri = if input.original_uri.is_empty() {
        request.uri.to_string()
    } else {
        input.original_uri.to_string()
    };

    let mut environment = BTreeMap::new();
    environment.insert("AUTH_TYPE".to_string(), String::new());
    environment.insert(
        "CONTENT_TYPE".to_string(),
        request
            .headers
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_string(),
    );
    environment.insert("GATEWAY_INTERFACE".to_string(), "CGI/1.1".to_string());
    environment.insert("PATH_INFO".to_string(), path_info.clone());
    environment.insert(
        "QUERY_STRING".to_string(),
        request.uri.query().unwrap_or("").to_string(),
    );
    environment.insert("REMOTE_ADDR".to_string(), input.remote_ip.to_string());
    environment.insert("REMOTE_HOST".to_string(), input.remote_ip.to_string());
    environment.insert(
        "REMOTE_PORT".to_string(),
        input
            .remote_port
            .map_or_else(String::new, |port| port.to_string()),
    );
    environment.insert("REMOTE_IDENT".to_string(), String::new());
    environment.insert(
        "REMOTE_USER".to_string(),
        input
            .request_vars
            .get("http.auth.user.id")
            .unwrap_or("")
            .to_string(),
    );
    environment.insert(
        "REQUEST_METHOD".to_string(),
        request.method.as_str().to_string(),
    );
    environment.insert("REQUEST_SCHEME".to_string(), input.scheme.to_string());
    environment.insert("SERVER_NAME".to_string(), host.to_string());
    environment.insert("SERVER_PORT".to_string(), port.to_string());
    environment.insert("SERVER_PROTOCOL".to_string(), protocol.to_string());
    environment.insert(
        "SERVER_SOFTWARE".to_string(),
        format!("Pingclair/{}", env!("CARGO_PKG_VERSION")),
    );
    environment.insert("DOCUMENT_ROOT".to_string(), root.clone());
    environment.insert("DOCUMENT_URI".to_string(), document_uri.to_string());
    environment.insert("HTTP_HOST".to_string(), authority.to_string());
    environment.insert("REQUEST_URI".to_string(), request_uri);
    environment.insert(
        "SCRIPT_FILENAME".to_string(),
        join_root(&root, &script_name),
    );
    environment.insert("SCRIPT_NAME".to_string(), script_name.to_string());
    if !path_info.is_empty() {
        environment.insert("PATH_TRANSLATED".to_string(), join_root(&root, &path_info));
    }
    if input.scheme == "https" {
        environment.insert("HTTPS".to_string(), "on".to_string());
    }

    // 🧰 Operator variables override CGI defaults after placeholder expansion.
    let verified_client_ip = input.remote_ip.to_string();
    for (key, template) in &config.env {
        let resolved = crate::server::resolve_caddy_placeholders(
            template,
            request,
            Some(&verified_client_ip),
            input.scheme,
            input.request_vars,
        );
        environment.insert(key.clone(), resolved.into_owned());
    }

    // 🧾 End-to-end fields exclude hop-by-hop and dedicated CGI variables.
    //
    // 🛡️ CGI is the sink where a forwarded field stops being data and becomes
    // configuration: every request header arrives as an `HTTP_*` environment
    // variable, and environment variables are what libraries read to decide how
    // to behave. `Proxy: http://attacker` becomes `HTTP_PROXY`, which an HTTP
    // client inside the script will then route its own outbound requests
    // through. That is why the shared filter refuses `proxy` outright rather
    // than only here — but here is where it would have done the damage.
    let filter = crate::http_policy::OutboundRequestFilter::for_client(&request.headers);
    for name in request.headers.keys() {
        let lower = name.as_str().to_ascii_lowercase();
        // 🧾 Framing and CGI-reserved names: the script is told the length
        // through `CONTENT_LENGTH` and the host through `HTTP_HOST`, and an
        // underscore in a field name would alias a variable the server sets.
        if matches!(
            lower.as_str(),
            "host" | "content-length" | "transfer-encoding" | "trailer"
        ) || lower.contains('_')
        {
            continue;
        }
        if filter.blocks(&lower) {
            continue;
        }
        let variable = format!(
            "HTTP_{}",
            name.as_str().to_ascii_uppercase().replace('-', "_")
        );
        let joined = request
            .headers
            .get_all(name)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .collect::<Vec<_>>()
            .join(", ");
        environment.insert(variable, joined);
    }
    Ok(environment)
}

/// 🌐 Returns the authority carried by either HTTP/1 or HTTP/2/3.
fn request_authority(request: &RequestHeader) -> &str {
    request
        .uri
        .authority()
        .map(|authority| authority.as_str())
        .or_else(|| {
            request
                .headers
                .get(http::header::HOST)
                .and_then(|value| value.to_str().ok())
        })
        .unwrap_or("")
}

/// 🪚 Finds the first ASCII case-insensitive path split delimiter.
fn split_position(path: &str, split_path: &[String]) -> Option<usize> {
    let bytes = path.as_bytes();
    for split in split_path {
        if split.is_empty() || split.len() > bytes.len() {
            continue;
        }
        let needle = split.as_bytes();
        for index in 0..=bytes.len() - needle.len() {
            if bytes[index..index + needle.len()]
                .iter()
                .zip(needle)
                .all(|(left, right)| left.eq_ignore_ascii_case(right))
            {
                return Some(index + needle.len());
            }
        }
    }
    None
}

/// 📂 Joins a CGI path below its document root without allowing `..` escape.
fn join_root(root: &str, path: &str) -> String {
    if path.split('/').any(|segment| segment == "..") {
        return root.to_string();
    }
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty() {
        root.to_string()
    } else {
        format!("{}/{}", root.trim_end_matches('/'), trimmed)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EnvironmentInput, Exchange, FastCgiStream, build_environment, prepare_request_header,
    };
    use crate::http_policy::RequestVars;
    use pingclair_core::config::FastCgiTransportConfig;
    use pingora_http::RequestHeader;
    use std::collections::BTreeMap;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::io::AsyncReadExt;

    /// 🧪 Shared preparation preserves H3 protocol and original-URI semantics.
    #[test]
    fn h3_environment_uses_the_rewritten_script_and_original_uri() {
        let mut request =
            RequestHeader::build(http::Method::POST, b"/index.php/tail?x=1", None).unwrap();
        request.version = http::Version::HTTP_3;
        request.insert_header("host", "example.test:8443").unwrap();
        request.insert_header("x-role", "admin").unwrap();
        let config = FastCgiTransportConfig {
            root: Some("/srv/www".to_string()),
            split_path: vec![".php".to_string()],
            ..Default::default()
        };
        let environment = build_environment(
            EnvironmentInput {
                request: &request,
                remote_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 4)),
                remote_port: Some(44321),
                scheme: "https",
                original_uri: "/original.php?x=1",
                request_vars: &RequestVars::default(),
            },
            &config,
        )
        .unwrap();

        assert_eq!(environment["SERVER_PROTOCOL"], "HTTP/3.0");
        assert_eq!(environment["SCRIPT_FILENAME"], "/srv/www/index.php");
        assert_eq!(environment["PATH_INFO"], "/tail");
        assert_eq!(environment["REQUEST_URI"], "/original.php?x=1");
        assert_eq!(environment["REMOTE_PORT"], "44321");
        assert_eq!(environment["HTTP_X_ROLE"], "admin");
    }

    /// 🛡️ No client field becomes an environment variable it should not.
    ///
    /// The `HTTP_PROXY` case is the one worth naming. CGI turns every request
    /// field into an `HTTP_*` variable, and environment variables are how
    /// libraries are configured rather than how they are told about data — so
    /// `Proxy: http://attacker` used to arrive as `HTTP_PROXY`, and an HTTP
    /// client inside the script would route its own outbound calls through it.
    /// The field has no legitimate sender; there is nothing to preserve.
    #[test]
    fn the_shared_matrix_becomes_only_the_variables_it_should() {
        let mut request = RequestHeader::build(http::Method::GET, b"/index.php", None).unwrap();
        request.insert_header("host", "example.test").unwrap();
        for (name, value, _) in crate::http_policy::SANITIZER_MATRIX {
            request.append_header(*name, *value).unwrap();
        }
        let config = FastCgiTransportConfig {
            root: Some("/srv/www".to_string()),
            ..Default::default()
        };
        let environment = build_environment(
            EnvironmentInput {
                request: &request,
                remote_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 4)),
                remote_port: Some(44321),
                scheme: "https",
                original_uri: "/index.php",
                request_vars: &RequestVars::default(),
            },
            &config,
        )
        .unwrap();

        for (name, _value, expect_blocked) in crate::http_policy::SANITIZER_MATRIX {
            let variable = format!("HTTP_{}", name.to_ascii_uppercase().replace('-', "_"));
            assert_eq!(
                !environment.contains_key(&variable),
                *expect_blocked,
                "`{name}` became `{variable}` the wrong way"
            );
        }

        // 🧭 The verified identity is still what the script is told, and it
        // comes from the socket rather than from anything the client wrote.
        assert_eq!(environment["REMOTE_ADDR"], "192.0.2.4");
    }

    /// 🧰 Header templates are resolved once before they become CGI variables.
    #[test]
    fn configured_upstream_headers_reach_the_shared_environment() {
        let mut request = RequestHeader::build(http::Method::GET, b"/index.php", None).unwrap();
        request.insert_header("host", "example.test").unwrap();
        let headers_up = BTreeMap::from([(
            "X-Request-Method".to_string(),
            "{http.request.method}".to_string(),
        )]);
        let variables = RequestVars::default();
        let prepared = prepare_request_header(
            &request,
            &headers_up,
            Some("192.0.2.4"),
            "https",
            &variables,
        )
        .unwrap();
        let environment = build_environment(
            EnvironmentInput {
                request: &prepared,
                remote_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 4)),
                remote_port: Some(44321),
                scheme: "https",
                original_uri: "/index.php",
                request_vars: &variables,
            },
            &FastCgiTransportConfig::default(),
        )
        .unwrap();

        assert_eq!(environment["HTTP_X_REQUEST_METHOD"], "GET");
    }

    /// 🛑 Both downstream transports emit an explicit responder abort before teardown.
    #[tokio::test]
    async fn exchange_abort_writes_the_fastcgi_abort_record() {
        let (client_stream, mut responder_stream) = tokio::io::duplex(128);
        let stream: Box<dyn FastCgiStream> = Box::new(client_stream);
        let mut exchange = Exchange {
            client: pingclair_fastcgi::Client::new(stream, 1, None, None, false),
        };

        exchange.abort().await;
        let mut header = [0u8; 8];
        responder_stream.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0], 1, "the record must use FastCGI version 1");
        assert_eq!(header[1], 2, "record type 2 is ABORT_REQUEST");
        assert_eq!(u16::from_be_bytes([header[2], header[3]]), 1);
        assert_eq!(u16::from_be_bytes([header[4], header[5]]), 0);
    }
}
