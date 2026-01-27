//! Pingclairfile Parser
//!
//! Recursive descent parser that converts tokens into AST.

use crate::parser::ast::*;
use crate::parser::lexer::{tokenize, Location, LexError, Spanned, Token};
use std::collections::HashMap;
use thiserror::Error;

/// Parser error types
#[derive(Debug, Error)]
pub enum ParseError {
    #[error("Lexer error: {0}")]
    Lex(#[from] LexError),
    
    #[error("Unexpected token at position {position}: expected {expected}, found {found}")]
    UnexpectedToken {
        position: usize,
        expected: String,
        found: String,
    },
    
    #[error("Unexpected end of input, expected {expected}")]
    UnexpectedEof { expected: String },
    
    #[error("Invalid syntax at position {position}: {message}")]
    InvalidSyntax { position: usize, message: String },
}

type ParseResult<T> = Result<T, ParseError>;

/// Parser state
pub struct Parser {
    tokens: Vec<Spanned<Token>>,
    pos: usize,
}

impl Parser {
    /// Create a new parser from source code
    pub fn new(source: &str) -> ParseResult<Self> {
        let tokens = tokenize(source)?;
        Ok(Self { tokens, pos: 0 })
    }

    /// Parse the entire Pingclairfile
    pub fn parse(&mut self) -> ParseResult<Ast> {
        let mut ast = Ast::new();
        
        while !self.is_eof() {
            match self.peek() {
                Some(Token::Global) => {
                    let global = self.parse_global()?;
                    ast.global = Some(global);
                }
                Some(Token::Macro) => {
                    let macro_def = self.parse_macro_def()?;
                    ast.macros.push(macro_def);
                }
                Some(Token::Server) => {
                    let server = self.parse_server()?;
                    ast.servers.push(server);
                }
                Some(tok) => {
                    return Err(ParseError::UnexpectedToken {
                        position: self.current_span().start,
                        expected: "global, macro, or server".to_string(),
                        found: format!("{:?}", tok),
                    });
                }
                None => break,
            }
        }
        
        Ok(ast)
    }

    // ========================================
    // Global Block
    // ========================================

    fn parse_global(&mut self) -> ParseResult<Node<GlobalBlock>> {
        let start = self.current_span();
        self.expect(Token::Global)?;
        self.expect(Token::BraceOpen)?;
        
        let mut global = GlobalBlock::default();
        
        while !self.check(&Token::BraceClose) && !self.is_eof() {
            match self.peek() {
                Some(Token::Protocols) => {
                    self.advance();
                    self.expect(Token::Colon)?;
                    global.protocols = self.parse_protocol_list()?;
                    self.expect(Token::Semicolon)?;
                }
                Some(Token::Debug) => {
                    self.advance();
                    self.expect(Token::Colon)?;
                    global.debug = Some(self.parse_bool()?);
                    self.expect(Token::Semicolon)?;
                }
                Some(Token::Logging) => {
                    global.logging = Some(self.parse_logging_config()?);
                }
                _ => {
                    let directive = self.parse_directive()?;
                    global.directives.push(directive);
                }
            }
        }
        
        let end = self.current_span();
        self.expect(Token::BraceClose)?;
        
        Ok(Node::new(global, Location { start: start.start, end: end.end }))
    }

    fn parse_protocol_list(&mut self) -> ParseResult<Vec<Protocol>> {
        self.expect(Token::BracketOpen)?;
        let mut protocols = Vec::new();
        
        while !self.check(&Token::BracketClose) {
            match self.peek() {
                Some(Token::H1) => { self.advance(); protocols.push(Protocol::H1); }
                Some(Token::H2) => { self.advance(); protocols.push(Protocol::H2); }
                Some(Token::H3) => { self.advance(); protocols.push(Protocol::H3); }
                _ => break,
            }
            if !self.check(&Token::BracketClose) {
                self.expect(Token::Comma)?;
            }
        }
        
        self.expect(Token::BracketClose)?;
        Ok(protocols)
    }

    fn parse_logging_config(&mut self) -> ParseResult<LoggingConfig> {
        self.expect(Token::Logging)?;
        self.expect(Token::BraceOpen)?;
        
        let mut config = LoggingConfig {
            level: LogLevel::Info,
            format: LogFormat::default(),
        };
        
        while !self.check(&Token::BraceClose) && !self.is_eof() {
            match self.peek() {
                Some(Token::Level) => {
                    self.advance();
                    self.expect(Token::Colon)?;
                    config.level = self.parse_log_level()?;
                    self.expect(Token::Semicolon)?;
                }
                Some(Token::Format) => {
                    self.advance();
                    self.expect(Token::Colon)?;
                    config.format.format_type = self.parse_log_format_type()?;
                    self.expect(Token::Semicolon)?;
                }
                _ => break,
            }
        }
        
        self.expect(Token::BraceClose)?;
        Ok(config)
    }

    // ========================================
    // Macro Definition
    // ========================================

    fn parse_macro_def(&mut self) -> ParseResult<Node<MacroDef>> {
        let start = self.current_span();
        self.expect(Token::Macro)?;
        
        // macro name!()
        let name = self.expect_identifier()?;
        self.expect(Token::Bang)?;
        self.expect(Token::ParenOpen)?;
        
        // Parse parameters
        let mut params = Vec::new();
        while !self.check(&Token::ParenClose) && !self.is_eof() {
            if self.check(&Token::Variable(_ignore())) {
                if let Some(Token::Variable(var)) = self.advance() {
                    params.push(MacroParam {
                        name: var.trim_start_matches('$').to_string(),
                        ty: None,
                    });
                }
            } else {
                let param_name = self.expect_identifier()?;
                let ty = if self.check(&Token::Colon) {
                    self.advance();
                    Some(self.expect_identifier()?)
                } else {
                    None
                };
                params.push(MacroParam { name: param_name, ty });
            }
            if !self.check(&Token::ParenClose) {
                let _ = self.check(&Token::Comma) && self.advance().is_some();
            }
        }
        
        self.expect(Token::ParenClose)?;
        self.expect(Token::BraceOpen)?;
        
        // Parse body
        let mut body = Vec::new();
        while !self.check(&Token::BraceClose) && !self.is_eof() {
            body.push(self.parse_directive()?);
        }
        
        let end = self.current_span();
        self.expect(Token::BraceClose)?;
        
        Ok(Node::new(
            MacroDef { name, params, body },
            Location { start: start.start, end: end.end }
        ))
    }

    // ========================================
    // Server Block
    // ========================================

    fn parse_server(&mut self) -> ParseResult<Node<ServerBlock>> {
        let start = self.current_span();
        self.expect(Token::Server)?;
        
        let name = self.expect_string()?;
        self.expect(Token::BraceOpen)?;
        
        let mut server = ServerBlock::new(name);
        
        while !self.check(&Token::BraceClose) && !self.is_eof() {
            match self.peek() {
                Some(Token::Listen) => {
                    self.advance();
                    self.expect(Token::Colon)?;
                    server.listen = Some(self.parse_listen_addr()?);
                    self.expect(Token::Semicolon)?;
                }
                Some(Token::Bind) => {
                    self.advance();
                    self.expect(Token::Colon)?;
                    server.bind = Some(self.expect_string()?);
                    self.expect(Token::Semicolon)?;
                }
                Some(Token::Compress) => {
                    self.advance();
                    self.expect(Token::Colon)?;
                    server.compress = self.parse_compression_list()?;
                    self.expect(Token::Semicolon)?;
                }
                Some(Token::Log) => {
                    server.log = Some(self.parse_log_block()?);
                }
                Some(Token::Route) => {
                    server.routes = Some(self.parse_route_block()?);
                }
                Some(Token::Use) => {
                    let call = self.parse_macro_call()?;
                    server.directives.push(Directive::MacroCall(call));
                }
                Some(Token::Headers) => {
                    let headers = self.parse_headers_config()?;
                    server.directives.push(Directive::Headers(headers));
                }
                _ => {
                    let directive = self.parse_directive()?;
                    server.directives.push(directive);
                }
            }
        }
        
        let end = self.current_span();
        self.expect(Token::BraceClose)?;
        
        Ok(Node::new(server, Location { start: start.start, end: end.end }))
    }

    fn parse_listen_addr(&mut self) -> ParseResult<ListenAddr> {
        let addr_str = self.expect_string_or_url()?;
        
        // Parse URL format: http://host:port or https://host:port
        let (scheme, rest) = if addr_str.starts_with("https://") {
            (Scheme::Https, &addr_str[8..])
        } else if addr_str.starts_with("http://") {
            (Scheme::Http, &addr_str[7..])
        } else {
            (Scheme::Http, addr_str.as_str())
        };
        
        let (host, port) = if let Some(colon_pos) = rest.rfind(':') {
            let host = rest[..colon_pos].to_string();
            let port = rest[colon_pos+1..].parse::<u16>().ok();
            (host, port)
        } else {
            (rest.to_string(), None)
        };
        
        Ok(ListenAddr { scheme, host, port })
    }

    fn parse_compression_list(&mut self) -> ParseResult<Vec<CompressionAlgo>> {
        self.expect(Token::BracketOpen)?;
        let mut algos = Vec::new();
        
        while !self.check(&Token::BracketClose) {
            match self.peek() {
                Some(Token::Gzip) => { self.advance(); algos.push(CompressionAlgo::Gzip); }
                Some(Token::Br) => { self.advance(); algos.push(CompressionAlgo::Br); }
                Some(Token::Zstd) => { self.advance(); algos.push(CompressionAlgo::Zstd); }
                _ => break,
            }
            if !self.check(&Token::BracketClose) {
                let _ = self.check(&Token::Comma) && self.advance().is_some();
            }
        }
        
        self.expect(Token::BracketClose)?;
        Ok(algos)
    }

    // ========================================
    // Log Block
    // ========================================

    fn parse_log_block(&mut self) -> ParseResult<Node<LogBlock>> {
        let start = self.current_span();
        self.expect(Token::Log)?;
        self.expect(Token::BraceOpen)?;
        
        let mut log = LogBlock {
            output: LogOutput::Stdout,
            format: LogFormat::default(),
        };
        
        while !self.check(&Token::BraceClose) && !self.is_eof() {
            match self.peek() {
                Some(Token::Output) => {
                    self.advance();
                    self.expect(Token::Colon)?;
                    log.output = self.parse_log_output()?;
                    self.expect(Token::Semicolon)?;
                }
                Some(Token::Format) => {
                    self.advance();
                    self.expect(Token::Colon)?;
                    log.format = self.parse_log_format()?;
                    self.expect(Token::Semicolon)?;
                }
                _ => {
                    // Skip unknown
                    self.advance();
                }
            }
        }
        
        let end = self.current_span();
        self.expect(Token::BraceClose)?;
        
        Ok(Node::new(log, Location { start: start.start, end: end.end }))
    }

    fn parse_log_output(&mut self) -> ParseResult<LogOutput> {
        match self.peek() {
            Some(Token::File) => {
                self.advance();
                self.expect(Token::ParenOpen)?;
                let path = self.expect_string()?;
                self.expect(Token::ParenClose)?;
                Ok(LogOutput::File(path))
            }
            Some(Token::Stdout) => {
                self.advance();
                Ok(LogOutput::Stdout)
            }
            Some(Token::Stderr) => {
                self.advance();
                Ok(LogOutput::Stderr)
            }
            _ => Err(ParseError::UnexpectedToken {
                position: self.current_span().start,
                expected: "File, Stdout, or Stderr".to_string(),
                found: format!("{:?}", self.peek()),
            }),
        }
    }

    fn parse_log_format(&mut self) -> ParseResult<LogFormat> {
        let format_type = self.parse_log_format_type()?;
        
        let filter = if self.check(&Token::BraceOpen) {
            self.advance();
            let mut filter = LogFilter::default();
            
            while !self.check(&Token::BraceClose) && !self.is_eof() {
                if self.check(&Token::Filter) {
                    self.advance();
                    self.expect(Token::Colon)?;
                    self.expect(Token::BraceOpen)?;
                    
                    while !self.check(&Token::BraceClose) {
                        if self.check(&Token::Exclude) {
                            self.advance();
                            self.expect(Token::Colon)?;
                            filter.exclude = self.parse_string_array()?;
                            let _ = self.check(&Token::Comma) && self.advance().is_some();
                        } else {
                            self.advance();
                        }
                    }
                    
                    self.expect(Token::BraceClose)?;
                } else {
                    self.advance();
                }
                let _ = self.check(&Token::Comma) && self.advance().is_some();
            }
            
            self.expect(Token::BraceClose)?;
            Some(filter)
        } else {
            None
        };
        
        Ok(LogFormat { format_type, filter })
    }

    // ========================================
    // Route Block
    // ========================================

    fn parse_route_block(&mut self) -> ParseResult<Node<RouteBlock>> {
        let start = self.current_span();
        self.expect(Token::Route)?;
        self.expect(Token::BraceOpen)?;
        
        let mut arms = Vec::new();
        
        while !self.check(&Token::BraceClose) && !self.is_eof() {
            arms.push(self.parse_route_arm()?);
        }
        
        let end = self.current_span();
        self.expect(Token::BraceClose)?;
        
        Ok(Node::new(RouteBlock { arms }, Location { start: start.start, end: end.end }))
    }

    fn parse_route_arm(&mut self) -> ParseResult<Node<RouteArm>> {
        let start = self.current_span();
        
        // Check for match keyword or underscore (default)
        let matcher = if self.check(&Token::Match) {
            self.advance();
            Some(self.parse_matcher()?)
        } else if self.check(&Token::Underscore) {
            self.advance();
            None
        } else {
            return Err(ParseError::UnexpectedToken {
                position: self.current_span().start,
                expected: "match or _".to_string(),
                found: format!("{:?}", self.peek()),
            });
        };
        
        self.expect(Token::Arrow)?;
        self.expect(Token::BraceOpen)?;
        
        let handler = self.parse_handler()?;
        
        let end = self.current_span();
        self.expect(Token::BraceClose)?;
        
        Ok(Node::new(
            RouteArm { matcher, handler },
            Location { start: start.start, end: end.end }
        ))
    }

    fn parse_matcher(&mut self) -> ParseResult<Matcher> {
        let left = self.parse_matcher_primary()?;
        
        // Check for && or ||
        if self.check(&Token::And) {
            self.advance();
            let right = self.parse_matcher()?;
            return Ok(Matcher::And(Box::new(left), Box::new(right)));
        }
        
        if self.check(&Token::OrOr) {
            self.advance();
            let right = self.parse_matcher()?;
            return Ok(Matcher::Or(Box::new(left), Box::new(right)));
        }
        
        Ok(left)
    }

    fn parse_matcher_primary(&mut self) -> ParseResult<Matcher> {
        // Check for not
        if self.check(&Token::Not) {
            self.advance();
            let inner = self.parse_matcher_primary()?;
            return Ok(Matcher::Not(Box::new(inner)));
        }
        
        match self.peek() {
            Some(Token::Path) => self.parse_path_matcher(),
            Some(Token::Header) => self.parse_header_matcher(),
            Some(Token::Method) => self.parse_method_matcher(),
            Some(Token::Query) => self.parse_query_matcher(),
            Some(Token::Host) => self.parse_host_matcher(),
            Some(Token::RemoteIp) => self.parse_remote_ip_matcher(),
            Some(Token::Protocol) => self.parse_protocol_matcher(),
            Some(Token::ParenOpen) => {
                self.advance();
                let matcher = self.parse_matcher()?;
                self.expect(Token::ParenClose)?;
                Ok(matcher)
            }
            _ => Err(ParseError::UnexpectedToken {
                position: self.current_span().start,
                expected: "path, header, method, query, host, remote_ip, or protocol".to_string(),
                found: format!("{:?}", self.peek()),
            }),
        }
    }

    fn parse_path_matcher(&mut self) -> ParseResult<Matcher> {
        self.expect(Token::Path)?;
        self.expect(Token::ParenOpen)?;
        
        let mut patterns = Vec::new();
        
        loop {
            let pattern = self.expect_string_or_path()?;
            patterns.push(pattern);
            
            if self.check(&Token::Or) {
                self.advance();
            } else {
                break;
            }
        }
        
        self.expect(Token::ParenClose)?;
        
        Ok(Matcher::Path(PathMatcher { patterns }))
    }

    fn parse_header_matcher(&mut self) -> ParseResult<Matcher> {
        self.expect(Token::Header)?;
        self.expect(Token::ParenOpen)?;
        
        let name = self.expect_string()?;
        self.expect(Token::Comma)?;
        
        let condition = if self.check(&Token::Exists) {
            self.advance();
            HeaderCondition::Exists
        } else if self.check(&Token::Contains) {
            self.advance();
            self.expect(Token::ParenOpen)?;
            let value = self.expect_string()?;
            self.expect(Token::ParenClose)?;
            HeaderCondition::Contains(value)
        } else if self.check(&Token::StartsWith) {
            self.advance();
            self.expect(Token::ParenOpen)?;
            let value = self.expect_string()?;
            self.expect(Token::ParenClose)?;
            HeaderCondition::StartsWith(value)
        } else if self.check(&Token::EndsWith) {
            self.advance();
            self.expect(Token::ParenOpen)?;
            let value = self.expect_string()?;
            self.expect(Token::ParenClose)?;
            HeaderCondition::EndsWith(value)
        } else if self.check(&Token::Regex) {
            self.advance();
            self.expect(Token::ParenOpen)?;
            let value = self.expect_string()?;
            self.expect(Token::ParenClose)?;
            HeaderCondition::Regex(value)
        } else {
            let value = self.expect_string()?;
            HeaderCondition::Equals(value)
        };
        
        self.expect(Token::ParenClose)?;
        
        Ok(Matcher::Header(HeaderMatcher { name, condition }))
    }

    fn parse_method_matcher(&mut self) -> ParseResult<Matcher> {
        self.expect(Token::Method)?;
        self.expect(Token::ParenOpen)?;
        
        let mut methods = Vec::new();
        
        loop {
            let method_name = self.expect_identifier()?;
            let method = match method_name.to_uppercase().as_str() {
                "GET" => HttpMethod::Get,
                "POST" => HttpMethod::Post,
                "PUT" => HttpMethod::Put,
                "DELETE" => HttpMethod::Delete,
                "PATCH" => HttpMethod::Patch,
                "HEAD" => HttpMethod::Head,
                "OPTIONS" => HttpMethod::Options,
                _ => return Err(ParseError::InvalidSyntax {
                    position: self.current_span().start,
                    message: format!("Unknown HTTP method: {}", method_name),
                }),
            };
            methods.push(method);
            
            if self.check(&Token::Or) {
                self.advance();
            } else {
                break;
            }
        }
        
        self.expect(Token::ParenClose)?;
        
        Ok(Matcher::Method(methods))
    }

    fn parse_query_matcher(&mut self) -> ParseResult<Matcher> {
        self.expect(Token::Query)?;
        self.expect(Token::ParenOpen)?;
        
        let name = self.expect_string()?;
        self.expect(Token::Comma)?;
        
        let condition = if self.check(&Token::Exists) {
            self.advance();
            HeaderCondition::Exists
        } else {
            let value = self.expect_string()?;
            HeaderCondition::Equals(value)
        };
        
        self.expect(Token::ParenClose)?;
        
        Ok(Matcher::Query(QueryMatcher { name, condition }))
    }

    fn parse_host_matcher(&mut self) -> ParseResult<Matcher> {
        self.expect(Token::Host)?;
        self.expect(Token::ParenOpen)?;
        let mut hosts = Vec::new();
        loop {
            hosts.push(self.expect_string()?);
            if self.check(&Token::Or) {
                self.advance();
            } else {
                break;
            }
        }
        self.expect(Token::ParenClose)?;
        Ok(Matcher::Host(hosts))
    }

    fn parse_remote_ip_matcher(&mut self) -> ParseResult<Matcher> {
        self.expect(Token::RemoteIp)?;
        self.expect(Token::ParenOpen)?;
        let mut ips = Vec::new();
        loop {
            ips.push(self.expect_string()?);
            if self.check(&Token::Or) {
                self.advance();
            } else {
                break;
            }
        }
        self.expect(Token::ParenClose)?;
        Ok(Matcher::RemoteIp(ips))
    }

    fn parse_protocol_matcher(&mut self) -> ParseResult<Matcher> {
        self.expect(Token::Protocol)?;
        self.expect(Token::ParenOpen)?;
        let mut protocols = Vec::new();
        loop {
            protocols.push(self.expect_string()?);
            if self.check(&Token::Or) {
                self.advance();
            } else {
                break;
            }
        }
        self.expect(Token::ParenClose)?;
        Ok(Matcher::Protocol(protocols))
    }

    // ========================================
    // Handlers
    // ========================================

    fn parse_handler(&mut self) -> ParseResult<Handler> {
        let mut handlers = Vec::new();
        
        while !self.check(&Token::BraceClose) && !self.is_eof() {
            match self.peek() {
                Some(Token::Proxy) => {
                    handlers.push(Handler::Proxy(Box::new(self.parse_proxy_config()?)));
                }
                Some(Token::Respond) => {
                    handlers.push(Handler::Respond(self.parse_respond_config()?));
                }
                Some(Token::Redirect) => {
                    handlers.push(Handler::Redirect(self.parse_redirect_config()?));
                }
                Some(Token::Headers) => {
                    handlers.push(Handler::Headers(self.parse_headers_config()?));
                }
                Some(Token::FileServer) => {
                    handlers.push(Handler::FileServer(self.parse_file_server_config()?));
                }
                Some(Token::Handle) => {
                    handlers.push(Handler::Handle(self.parse_handle_block()?));
                }
                Some(Token::Plugin) => {
                    let (name, args) = self.parse_plugin_call()?;
                    handlers.push(Handler::Plugin { name, args });
                }
                Some(Token::Use) => {
                    // Macro calls in handlers - parse as part of proxy config
                    break;
                }
                _ => break,
            }
        }
        
        if handlers.len() == 1 {
            Ok(handlers.pop().unwrap())
        } else if handlers.is_empty() {
            Ok(Handler::Respond(ResponseConfig {
                status: 200,
                body: None,
                headers: HashMap::new(),
            }))
        } else {
            Ok(Handler::Pipeline(handlers))
        }
    }

    fn parse_proxy_config(&mut self) -> ParseResult<ProxyConfig> {
        self.expect(Token::Proxy)?;
        
        // Parse upstream(s)
        let upstreams = if self.check(&Token::BracketOpen) {
            self.parse_string_array()?
        } else {
            vec![self.expect_string_or_url()?]
        };
        
        let mut config = ProxyConfig::new(upstreams);
        
        if self.check(&Token::BraceOpen) {
            self.advance();
            
            while !self.check(&Token::BraceClose) && !self.is_eof() {
                match self.peek() {
                    Some(Token::FlushInterval) => {
                        self.advance();
                        self.expect(Token::Colon)?;
                        config.flush_interval = Some(self.parse_flush_interval()?);
                        self.expect(Token::Semicolon)?;
                    }
                    Some(Token::HeaderUp) => {
                        self.advance();
                        self.expect(Token::Colon)?;
                        let headers = self.parse_header_map()?;
                        config.header_up.extend(headers);
                        self.expect(Token::Semicolon)?;
                    }
                    Some(Token::Transport) => {
                        config.transport = Some(self.parse_transport_config()?);
                    }
                    Some(Token::Use) => {
                        let call = self.parse_macro_call()?;
                        config.macro_calls.push(call);
                    }
                    _ => {
                        self.advance();
                    }
                }
            }
            
            self.expect(Token::BraceClose)?;
        }
        
        Ok(config)
    }

    fn parse_flush_interval(&mut self) -> ParseResult<FlushInterval> {
        if self.check(&Token::Immediate) {
            self.advance();
            Ok(FlushInterval::Immediate)
        } else if let Some(Token::Duration(ms)) = self.peek().cloned() {
            self.advance();
            Ok(FlushInterval::Duration(ms))
        } else {
            Err(ParseError::UnexpectedToken {
                position: self.current_span().start,
                expected: "Immediate or duration".to_string(),
                found: format!("{:?}", self.peek()),
            })
        }
    }

    fn parse_transport_config(&mut self) -> ParseResult<TransportConfig> {
        self.expect(Token::Transport)?;
        self.expect(Token::BraceOpen)?;
        
        let mut config = TransportConfig {
            read_timeout: None,
            write_timeout: None,
        };
        
        while !self.check(&Token::BraceClose) && !self.is_eof() {
            match self.peek() {
                Some(Token::ReadTimeout) => {
                    self.advance();
                    self.expect(Token::Colon)?;
                    if let Some(Token::Duration(ms)) = self.peek().cloned() {
                        self.advance();
                        config.read_timeout = Some(ms);
                    }
                    self.expect(Token::Semicolon)?;
                }
                Some(Token::WriteTimeout) => {
                    self.advance();
                    self.expect(Token::Colon)?;
                    if let Some(Token::Duration(ms)) = self.peek().cloned() {
                        self.advance();
                        config.write_timeout = Some(ms);
                    }
                    self.expect(Token::Semicolon)?;
                }
                _ => {
                    self.advance();
                }
            }
        }
        
        self.expect(Token::BraceClose)?;
        Ok(config)
    }

    fn parse_respond_config(&mut self) -> ParseResult<ResponseConfig> {
        self.expect(Token::Respond)?;
        
        let status = if let Some(Token::Integer(n)) = self.peek().cloned() {
            self.advance();
            n as u16
        } else {
            200
        };
        
        let (body, headers) = if self.check(&Token::BraceOpen) {
            self.advance();
            let mut body = None;
            let headers = HashMap::new();
            
            while !self.check(&Token::BraceClose) && !self.is_eof() {
                if self.check(&Token::Body) {
                    self.advance();
                    self.expect(Token::Colon)?;
                    body = Some(self.parse_expr()?);
                    self.expect(Token::Semicolon)?;
                } else {
                    self.advance();
                }
            }
            
            self.expect(Token::BraceClose)?;
            (body, headers)
        } else {
            (None, HashMap::new())
        };
        
        Ok(ResponseConfig { status, body, headers })
    }

    fn parse_redirect_config(&mut self) -> ParseResult<RedirectConfig> {
        self.expect(Token::Redirect)?;
        
        let to = self.expect_string_or_url()?;
        
        let code = if let Some(Token::Integer(n)) = self.peek().cloned() {
            self.advance();
            n as u16
        } else {
            302
        };
        
        self.expect(Token::Semicolon)?;
        
        Ok(RedirectConfig { to, code })
    }

    fn parse_file_server_config(&mut self) -> ParseResult<FileServerConfig> {
        self.expect(Token::FileServer)?;
        let mut config = FileServerConfig {
            root: ".".to_string(),
            index: vec!["index.html".to_string()],
            browse: false,
            compress: true,
        };
        
        if self.check(&Token::BraceOpen) {
            self.advance();
            while !self.check(&Token::BraceClose) && !self.is_eof() {
                let key = self.expect_identifier()?;
                self.expect(Token::Colon)?;
                match key.as_str() {
                    "root" => {
                        config.root = self.expect_string()?;
                    }
                    "index" => {
                        config.index = self.parse_string_array()?;
                    }
                    "browse" => {
                        config.browse = self.parse_bool()?;
                    }
                    "compress" => {
                        config.compress = self.parse_bool()?;
                    }
                    _ => {
                        return Err(ParseError::InvalidSyntax {
                            position: self.current_span().start,
                            message: format!("Unknown file_server option: {}", key),
                        });
                    }
                }
                self.expect(Token::Semicolon)?;
            }
            self.expect(Token::BraceClose)?;
        }
        Ok(config)
    }

    fn parse_handle_block(&mut self) -> ParseResult<Vec<Node<Directive>>> {
        self.expect(Token::Handle)?;
        self.expect(Token::BraceOpen)?;
        let mut directives = Vec::new();
        while !self.check(&Token::BraceClose) && !self.is_eof() {
            let start = self.current_span();
            let directive = self.parse_directive()?;
            let end = self.current_span();
            directives.push(Node::new(directive, Location { start: start.start, end: end.end }));
        }
        self.expect(Token::BraceClose)?;
        Ok(directives)
    }

    fn parse_plugin_call(&mut self) -> ParseResult<(String, Vec<Expr>)> {
        self.expect(Token::Plugin)?;
        let name = self.expect_string()?;
        let mut args = Vec::new();
        while !self.check(&Token::Semicolon) && !self.is_eof() {
            args.push(self.parse_expr()?);
            if self.check(&Token::Comma) {
                self.advance();
            }
        }
        self.expect(Token::Semicolon)?;
        Ok((name, args))
    }

    fn parse_headers_config(&mut self) -> ParseResult<HeadersConfig> {
        self.expect(Token::Headers)?;
        self.expect(Token::BraceOpen)?;
        
        let mut config = HeadersConfig::default();
        
        while !self.check(&Token::BraceClose) && !self.is_eof() {
            match self.peek() {
                Some(Token::Set) => {
                    self.advance();
                    self.expect(Token::Colon)?;
                    config.set = self.parse_string_map()?;
                    self.expect(Token::Semicolon)?;
                }
                Some(Token::Add) => {
                    self.advance();
                    self.expect(Token::Colon)?;
                    config.add = self.parse_string_map()?;
                    self.expect(Token::Semicolon)?;
                }
                Some(Token::Remove) => {
                    self.advance();
                    self.expect(Token::Colon)?;
                    config.remove = self.parse_string_array()?;
                    self.expect(Token::Semicolon)?;
                }
                _ => {
                    self.advance();
                }
            }
        }
        
        self.expect(Token::BraceClose)?;
        Ok(config)
    }

    // ========================================
    // Macro Call
    // ========================================

    fn parse_macro_call(&mut self) -> ParseResult<MacroCall> {
        self.expect(Token::Use)?;
        
        let name = self.expect_identifier()?;
        self.expect(Token::Bang)?;
        self.expect(Token::ParenOpen)?;
        
        let mut args = Vec::new();
        while !self.check(&Token::ParenClose) && !self.is_eof() {
            args.push(self.parse_expr()?);
            if !self.check(&Token::ParenClose) {
                let _ = self.check(&Token::Comma) && self.advance().is_some();
            }
        }
        
        self.expect(Token::ParenClose)?;
        self.expect(Token::Semicolon)?;
        
        Ok(MacroCall { name, args })
    }

    // ========================================
    // Directives
    // ========================================

    fn parse_directive(&mut self) -> ParseResult<Directive> {
        if self.check(&Token::Use) {
            let call = self.parse_macro_call()?;
            return Ok(Directive::MacroCall(call));
        }
        
        if self.check(&Token::Headers) {
            let headers = self.parse_headers_config()?;
            return Ok(Directive::Headers(headers));
        }
        
        // Generic key: value; directive
        let key = self.expect_identifier()?;
        self.expect(Token::Colon)?;
        let value = self.parse_expr()?;
        self.expect(Token::Semicolon)?;
        
        Ok(Directive::Setting { key, value })
    }

    // ========================================
    // Expressions
    // ========================================

    fn parse_expr(&mut self) -> ParseResult<Expr> {
        match self.peek().cloned() {
            Some(Token::String(s)) => {
                self.advance();
                Ok(Expr::String(s))
            }
            Some(Token::Integer(n)) => {
                self.advance();
                Ok(Expr::Integer(n))
            }
            Some(Token::Duration(ms)) => {
                self.advance();
                Ok(Expr::Duration(ms))
            }
            Some(Token::True) => {
                self.advance();
                Ok(Expr::Bool(true))
            }
            Some(Token::False) => {
                self.advance();
                Ok(Expr::Bool(false))
            }
            Some(Token::Variable(v)) => {
                self.advance();
                Ok(Expr::Variable(Variable { path: v }))
            }
            Some(Token::Url(u)) => {
                self.advance();
                Ok(Expr::String(u))
            }
            Some(Token::BracketOpen) => {
                self.parse_array_expr()
            }
            Some(Token::BraceOpen) => {
                self.parse_map_expr()
            }
            Some(Token::Identifier(s)) => {
                self.advance();
                Ok(Expr::Ident(s))
            }
            _ => Err(ParseError::UnexpectedToken {
                position: self.current_span().start,
                expected: "expression".to_string(),
                found: format!("{:?}", self.peek()),
            }),
        }
    }

    fn parse_array_expr(&mut self) -> ParseResult<Expr> {
        self.expect(Token::BracketOpen)?;
        let mut items = Vec::new();
        
        while !self.check(&Token::BracketClose) && !self.is_eof() {
            items.push(self.parse_expr()?);
            if !self.check(&Token::BracketClose) {
                let _ = self.check(&Token::Comma) && self.advance().is_some();
            }
        }
        
        self.expect(Token::BracketClose)?;
        Ok(Expr::Array(items))
    }

    fn parse_map_expr(&mut self) -> ParseResult<Expr> {
        self.expect(Token::BraceOpen)?;
        let mut map = HashMap::new();
        
        while !self.check(&Token::BraceClose) && !self.is_eof() {
            let key = self.expect_string()?;
            self.expect(Token::Colon)?;
            let value = self.parse_expr()?;
            map.insert(key, value);
            if !self.check(&Token::BraceClose) {
                let _ = self.check(&Token::Comma) && self.advance().is_some();
            }
        }
        
        self.expect(Token::BraceClose)?;
        Ok(Expr::Map(map))
    }

    // ========================================
    // Helper methods
    // ========================================

    fn parse_header_map(&mut self) -> ParseResult<HashMap<String, Expr>> {
        self.expect(Token::BraceOpen)?;
        let mut map = HashMap::new();
        
        while !self.check(&Token::BraceClose) && !self.is_eof() {
            let key = self.expect_string()?;
            self.expect(Token::Colon)?;
            let value = self.parse_expr()?;
            map.insert(key, value);
            if !self.check(&Token::BraceClose) {
                let _ = self.check(&Token::Comma) && self.advance().is_some();
            }
        }
        
        self.expect(Token::BraceClose)?;
        Ok(map)
    }

    fn parse_string_map(&mut self) -> ParseResult<HashMap<String, String>> {
        self.expect(Token::BraceOpen)?;
        let mut map = HashMap::new();
        
        while !self.check(&Token::BraceClose) && !self.is_eof() {
            let key = self.expect_string()?;
            self.expect(Token::Colon)?;
            let value = self.expect_string()?;
            map.insert(key, value);
            if !self.check(&Token::BraceClose) {
                let _ = self.check(&Token::Comma) && self.advance().is_some();
            }
        }
        
        self.expect(Token::BraceClose)?;
        Ok(map)
    }

    fn parse_string_array(&mut self) -> ParseResult<Vec<String>> {
        self.expect(Token::BracketOpen)?;
        let mut items = Vec::new();
        
        while !self.check(&Token::BracketClose) && !self.is_eof() {
            items.push(self.expect_string()?);
            if !self.check(&Token::BracketClose) {
                let _ = self.check(&Token::Comma) && self.advance().is_some();
            }
        }
        
        self.expect(Token::BracketClose)?;
        Ok(items)
    }

    fn parse_bool(&mut self) -> ParseResult<bool> {
        match self.peek() {
            Some(Token::True) => { self.advance(); Ok(true) }
            Some(Token::False) => { self.advance(); Ok(false) }
            _ => Err(ParseError::UnexpectedToken {
                position: self.current_span().start,
                expected: "true or false".to_string(),
                found: format!("{:?}", self.peek()),
            }),
        }
    }

    fn parse_log_level(&mut self) -> ParseResult<LogLevel> {
        match self.peek() {
            Some(Token::Trace) => { self.advance(); Ok(LogLevel::Trace) }
            Some(Token::Debug) => { self.advance(); Ok(LogLevel::Debug) }
            Some(Token::Info) => { self.advance(); Ok(LogLevel::Info) }
            Some(Token::Warn) => { self.advance(); Ok(LogLevel::Warn) }
            Some(Token::Error) => { self.advance(); Ok(LogLevel::Error) }
            _ => Err(ParseError::UnexpectedToken {
                position: self.current_span().start,
                expected: "log level".to_string(),
                found: format!("{:?}", self.peek()),
            }),
        }
    }

    fn parse_log_format_type(&mut self) -> ParseResult<LogFormatType> {
        match self.peek() {
            Some(Token::Json) => { self.advance(); Ok(LogFormatType::Json) }
            Some(Token::Text) => { self.advance(); Ok(LogFormatType::Text) }
            _ => Err(ParseError::UnexpectedToken {
                position: self.current_span().start,
                expected: "Json or Text".to_string(),
                found: format!("{:?}", self.peek()),
            }),
        }
    }

    // ========================================
    // Token utilities
    // ========================================

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos).map(|s| &s.value)
    }

    fn advance(&mut self) -> Option<Token> {
        if self.pos < self.tokens.len() {
            let token = self.tokens[self.pos].value.clone();
            self.pos += 1;
            Some(token)
        } else {
            None
        }
    }

    fn check(&self, token: &Token) -> bool {
        match (self.peek(), token) {
            (Some(Token::String(_)), Token::String(_)) => true,
            (Some(Token::Integer(_)), Token::Integer(_)) => true,
            (Some(Token::Duration(_)), Token::Duration(_)) => true,
            (Some(Token::Identifier(_)), Token::Identifier(_)) => true,
            (Some(Token::Variable(_)), Token::Variable(_)) => true,
            (Some(Token::Url(_)), Token::Url(_)) => true,
            (Some(Token::PathPattern(_)), Token::PathPattern(_)) => true,
            (Some(Token::IpAddr(_)), Token::IpAddr(_)) => true,
            (Some(a), b) => std::mem::discriminant(a) == std::mem::discriminant(b),
            _ => false,
        }
    }

    fn expect(&mut self, expected: Token) -> ParseResult<()> {
        if self.check(&expected) {
            self.advance();
            Ok(())
        } else {
            Err(ParseError::UnexpectedToken {
                position: self.current_span().start,
                expected: format!("{:?}", expected),
                found: format!("{:?}", self.peek()),
            })
        }
    }

    fn expect_identifier(&mut self) -> ParseResult<String> {
        if let Some(Token::Identifier(s)) = self.peek().cloned() {
            self.advance();
            Ok(s)
        } else {
            Err(ParseError::UnexpectedToken {
                position: self.current_span().start,
                expected: "identifier".to_string(),
                found: format!("{:?}", self.peek()),
            })
        }
    }

    fn expect_string(&mut self) -> ParseResult<String> {
        if let Some(Token::String(s)) = self.peek().cloned() {
            self.advance();
            Ok(s)
        } else {
            Err(ParseError::UnexpectedToken {
                position: self.current_span().start,
                expected: "string".to_string(),
                found: format!("{:?}", self.peek()),
            })
        }
    }

    fn expect_string_or_url(&mut self) -> ParseResult<String> {
        match self.peek().cloned() {
            Some(Token::String(s)) => { self.advance(); Ok(s) }
            Some(Token::Url(s)) => { self.advance(); Ok(s) }
            Some(Token::IpAddr(s)) => { self.advance(); Ok(s) }
            _ => Err(ParseError::UnexpectedToken {
                position: self.current_span().start,
                expected: "string or URL".to_string(),
                found: format!("{:?}", self.peek()),
            }),
        }
    }

    fn expect_string_or_path(&mut self) -> ParseResult<String> {
        match self.peek().cloned() {
            Some(Token::String(s)) => { self.advance(); Ok(s) }
            Some(Token::PathPattern(s)) => { self.advance(); Ok(s) }
            _ => Err(ParseError::UnexpectedToken {
                position: self.current_span().start,
                expected: "string or path".to_string(),
                found: format!("{:?}", self.peek()),
            }),
        }
    }

    fn is_eof(&self) -> bool {
        self.pos >= self.tokens.len()
    }

    fn current_span(&self) -> Location {
        self.tokens
            .get(self.pos)
            .map(|s| s.span)
            .unwrap_or(Location { start: 0, end: 0 })
    }
}

/// Helper function for pattern matching that ignores the value
fn _ignore<T: Default>() -> T {
    T::default()
}

/// Parse a Pingclairfile source string into an AST
pub fn parse(source: &str) -> ParseResult<Ast> {
    let mut parser = Parser::new(source)?;
    parser.parse()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty() {
        let ast = parse("").unwrap();
        assert!(ast.global.is_none());
        assert!(ast.servers.is_empty());
    }

    #[test]
    fn test_parse_global() {
        let ast = parse(r#"
            global {
                protocols: [H1, H2];
                debug: false;
            }
        "#).unwrap();
        
        assert!(ast.global.is_some());
        let global = &ast.global.unwrap().inner;
        assert_eq!(global.protocols.len(), 2);
        assert_eq!(global.debug, Some(false));
    }

    #[test]
    fn test_parse_macro_def() {
        let ast = parse(r#"
            macro security_headers!() {
                headers {
                    remove: ["Server"];
                }
            }
        "#).unwrap();
        
        assert_eq!(ast.macros.len(), 1);
        assert_eq!(ast.macros[0].inner.name, "security_headers");
    }

    #[test]
    fn test_parse_server() {
        let ast = parse(r#"
            server "example.com" {
                listen: "http://127.0.0.1:8080";
                bind: "127.0.0.1";
                compress: [Gzip, Br];
            }
        "#).unwrap();
        
        assert_eq!(ast.servers.len(), 1);
        let server = &ast.servers[0].inner;
        assert_eq!(server.name, "example.com");
        assert!(server.listen.is_some());
        assert_eq!(server.bind, Some("127.0.0.1".to_string()));
        assert_eq!(server.compress.len(), 2);
    }

    #[test]
    fn test_parse_route() {
        let ast = parse(r#"
            server "example.com" {
                route {
                    match path("/api/*") => {
                        proxy "http://localhost:3000" {
                            flush_interval: Immediate;
                        }
                    }
                    
                    _ => {
                        respond 404 { body: "Not found"; }
                    }
                }
            }
        "#).unwrap();
        
        let server = &ast.servers[0].inner;
        assert!(server.routes.is_some());
        let routes = server.routes.as_ref().unwrap();
        assert_eq!(routes.inner.arms.len(), 2);
    }

    #[test]
    fn test_parse_log_block() {
        let ast = parse(r#"
            server "example.com" {
                log {
                    output: File("/var/log/example.log");
                    format: Json {
                        filter: {
                            exclude: ["request.headers"],
                        },
                    };
                }
            }
        "#).unwrap();
        
        let server = &ast.servers[0].inner;
        assert!(server.log.is_some());
        let log = server.log.as_ref().unwrap();
        matches!(&log.inner.output, LogOutput::File(p) if p == "/var/log/example.log");
    }

    #[test]
    fn test_parse_header_matcher() {
        let ast = parse(r#"
            server "example.com" {
                route {
                    match header("Cf-Access-Jwt-Assertion", exists) => {
                        proxy "http://localhost:3000"
                    }
                }
            }
        "#).unwrap();
        
        let server = &ast.servers[0].inner;
        let routes = server.routes.as_ref().unwrap();
        let arm = &routes.inner.arms[0].inner;
        assert!(arm.matcher.is_some());
        matches!(&arm.matcher, Some(Matcher::Header(_)));
    }

    #[test]
    fn test_parse_multiple_paths() {
        let ast = parse(r#"
            server "example.com" {
                route {
                    match path("/api/*" | "/v1/*" | "/v2/*") => {
                        proxy "http://localhost:3000"
                    }
                }
            }
        "#).unwrap();
        
        let server = &ast.servers[0].inner;
        let routes = server.routes.as_ref().unwrap();
        if let Some(Matcher::Path(pm)) = &routes.inner.arms[0].inner.matcher {
            assert_eq!(pm.patterns.len(), 3);
        }
    }
}
