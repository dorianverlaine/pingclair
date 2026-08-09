// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧵 FastCGI 1.1 client: speaks the record framing PHP-FPM speaks.
//!
//! The FastCGI protocol is a set of length-prefixed records multiplexed over
//! one connection. A request sends `BEGIN_REQUEST`, a stream of `PARAMS`
//! records holding the CGI environment, and a `STDIN` stream carrying the
//! request body; the responder answers with `STDOUT` records whose first
//! chunk contains CGI headers (`Status: 200 OK`, then blank line), followed
//! by the body, then an empty `STDOUT` record and an `END_REQUEST` record.
//!
//! Everything in this module stays protocol-only: no HTTP types, no
//! configuration, and no buffering of whole bodies. The caller streams
//! request chunks in and reads response chunks out, so a 20 MB response
//! costs one record's worth of memory (at most 65,500 bytes).
//!
//! The wire format and the request choreography mirror Caddy's client
//! (`modules/caddyhttp/reverseproxy/fastcgi/` at `ff6da121`), including the
//! 65,500-byte record ceiling and the padding-to-8-bytes rule.

use bytes::Bytes;
use std::collections::BTreeMap;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

// MARK: - Wire constants

/// 📡 FastCGI protocol version; version 1 is the only version in use.
pub(crate) const VERSION: u8 = 1;

/// 🧱 Record types defined by the FastCGI specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordType {
    /// 🚀 Opens one request on the connection.
    BeginRequest = 1,
    /// 🛑 Asks the responder to stop processing a request.
    AbortRequest = 2,
    /// 🏁 The responder finished a request; carries status and result.
    EndRequest = 3,
    /// 🧾 Name-value pairs describing the request (the CGI environment).
    Params = 4,
    /// 📥 Request body stream; an empty record ends the stream.
    Stdin = 5,
    /// 📤 Response body stream; an empty record ends the stream.
    Stdout = 6,
    /// ⚠️ Diagnostic output from the responder, never part of the body.
    Stderr = 7,
}

impl TryFrom<u8> for RecordType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            1 => Self::BeginRequest,
            2 => Self::AbortRequest,
            3 => Self::EndRequest,
            4 => Self::Params,
            5 => Self::Stdin,
            6 => Self::Stdout,
            7 => Self::Stderr,
            _ => return Err(()),
        })
    }
}

/// 🎭 The role a request asks the responder to play; PHP-FPM answers as a
/// responder, which is the only role this client uses.
#[derive(Debug, Clone, Copy)]
#[repr(u16)]
pub enum Role {
    /// 🎭 Produces a response document for the request.
    Responder = 1,
}

/// 🏁 The protocol status an `END_REQUEST` record reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProtocolStatus {
    /// ✅ The request completed normally; `app_status` is the application's.
    RequestComplete = 0,
    /// 🚫 The connection cannot multiplex another request.
    CantMultiplexConnections = 1,
    /// 🏋️ The responder was overloaded and rejected the request.
    Overloaded = 2,
    /// 🎭 The responder does not know the requested role.
    UnknownRole = 3,
}

impl TryFrom<u8> for ProtocolStatus {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0 => Self::RequestComplete,
            1 => Self::CantMultiplexConnections,
            2 => Self::Overloaded,
            3 => Self::UnknownRole,
            _ => return Err(()),
        })
    }
}

/// 🧮 A record's content may never exceed this many bytes; the limit comes
/// from the 16-bit content-length field minus the eight header bytes.
pub const MAX_RECORD_CONTENT: usize = 65_500;

/// 🧾 The response header block may never exceed this many bytes.
///
/// The bound is what keeps the header parse from turning a misbehaving
/// responder into an unbounded allocation. 64 KiB is generous for CGI
/// headers (the HTTP header limit this proxy enforces is the same order of
/// magnitude) and tiny next to the record ceiling.
pub const MAX_HEADER_BYTES: usize = 64 * 1024;

/// ⚠️ Stderr collected per request is capped so a chatty responder cannot
/// grow memory with log lines nobody reads.
pub const MAX_STDERR_BYTES: usize = 64 * 1024;

/// 📏 The CGI header block ends at the first blank line.
pub(crate) const HEADER_TERMINATOR: &[u8] = b"\r\n\r\n";

// MARK: - Errors

/// 🚨 Why a FastCGI exchange failed, without tying the module to HTTP.
#[derive(Debug)]
pub enum FastCgiError {
    /// 🔌 The underlying stream failed.
    Io(std::io::Error),
    /// ⏱️ A read or write exceeded the configured deadline.
    TimedOut,
    /// 📡 A record violated the framing rules (version, length, ordering).
    Protocol(String),
    /// 🏁 The responder rejected or abandoned the request.
    Rejected(ProtocolStatus),
}

impl std::fmt::Display for FastCgiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "FastCGI I/O error: {error}"),
            Self::TimedOut => write!(f, "FastCGI deadline exceeded"),
            Self::Protocol(message) => write!(f, "FastCGI protocol error: {message}"),
            Self::Rejected(status) => {
                write!(f, "FastCGI responder rejected the request: {status:?}")
            }
        }
    }
}

impl From<std::io::Error> for FastCgiError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

// MARK: - Client

/// 🧵 One FastCGI request on one stream.
///
/// The client owns the record framing and the CGI header parse; the caller
/// owns the HTTP meaning. Request IDs are fixed at construction because
/// this proxy opens one connection per request, exactly like Caddy's client.
pub struct Client<S> {
    stream: S,
    request_id: u16,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    capture_stderr: bool,
    stderr: Vec<u8>,
    pending_body: Bytes,
    /// 🏁 Set when the responder's end-of-stream was observed.
    finished: bool,
    response_status: Option<u16>,
}

/// 🧾 The parsed CGI header block that opens a responder's `STDOUT` stream.
#[derive(Debug)]
pub struct ResponseHeader {
    /// 📟 HTTP status parsed from `Status:`, defaulting to 200.
    pub status: u16,
    /// 💬 Optional reason phrase from the same header.
    pub reason: Option<String>,
    /// 🧾 Header names and values as the responder wrote them.
    pub headers: Vec<(String, String)>,
    /// 📤 Body bytes that arrived in the same record as the header block.
    pub first_body: Bytes,
}

impl<S> Client<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// 🧩 Creates a client for one request on `stream`.
    pub fn new(
        stream: S,
        request_id: u16,
        read_timeout: Option<Duration>,
        write_timeout: Option<Duration>,
        capture_stderr: bool,
    ) -> Self {
        Self {
            stream,
            request_id,
            read_timeout,
            write_timeout,
            capture_stderr,
            stderr: Vec::new(),
            pending_body: Bytes::new(),
            finished: false,
            response_status: None,
        }
    }

    /// 🚀 Sends `BEGIN_REQUEST` for a responder-role request.
    pub async fn begin_request(&mut self) -> Result<(), FastCgiError> {
        let mut content = [0u8; 8];
        content[..2].copy_from_slice(&(Role::Responder as u16).to_be_bytes());
        // 🧩 Keep-connection is off: every request gets its own connection,
        // so the flag has no meaning and staying zero matches Caddy.
        self.write_record(RecordType::BeginRequest, &content).await
    }

    /// 🧾 Sends the CGI environment as a stream of `PARAMS` records.
    ///
    /// A single name-value pair can exceed the record ceiling; the pair is
    /// then truncated rather than dropped, matching Caddy's client. The
    /// final empty `PARAMS` record ends the stream.
    pub async fn send_params(
        &mut self,
        params: &BTreeMap<String, String>,
    ) -> Result<(), FastCgiError> {
        let mut record = Vec::with_capacity(MAX_RECORD_CONTENT);
        for (name, value) in params {
            let mut pair = Vec::with_capacity(1 + 1 + name.len() + value.len());
            encode_size(&mut pair, name.len());
            encode_size(&mut pair, value.len());
            pair.extend_from_slice(name.as_bytes());
            // 🧮 A value longer than the record ceiling is truncated, not
            // dropped, so the earlier pairs still reach the responder.
            let value = &value.as_bytes()[..value.len().min(MAX_RECORD_CONTENT - pair.len())];
            pair.extend_from_slice(value);
            if record.len() + pair.len() > MAX_RECORD_CONTENT {
                self.write_record(RecordType::Params, &record).await?;
                record.clear();
            }
            record.extend_from_slice(&pair);
        }
        if !record.is_empty() {
            self.write_record(RecordType::Params, &record).await?;
        }
        self.write_record(RecordType::Params, &[]).await
    }

    /// 📥 Sends one request-body chunk as a `STDIN` record.
    ///
    /// The caller streams chunks in, so a large upload never lives whole in
    /// memory. The record ceiling splits an oversized chunk into several
    /// records before writing.
    pub async fn send_stdin(&mut self, chunk: &[u8]) -> Result<(), FastCgiError> {
        for part in chunk.chunks(MAX_RECORD_CONTENT) {
            self.write_record(RecordType::Stdin, part).await?;
        }
        Ok(())
    }

    /// 🏁 Ends the `STDIN` stream with the required empty record.
    pub async fn finish_stdin(&mut self) -> Result<(), FastCgiError> {
        self.write_record(RecordType::Stdin, &[]).await
    }

    /// 🛑 Asks the responder to stop, best effort, when the client left.
    ///
    /// Dropping the stream would also abort the request; sending the record
    /// first is polite and costs nothing when the write fails.
    pub async fn abort(&mut self) {
        let _ = self.write_record(RecordType::AbortRequest, &[]).await;
    }

    /// 🧾 Reads the CGI header block that opens the response.
    ///
    /// Returns the parsed headers plus any body bytes that shared the final
    /// record, so a header split across records is handled without losing
    /// body bytes.
    pub async fn read_response_header(&mut self) -> Result<ResponseHeader, FastCgiError> {
        let mut header_bytes = Vec::with_capacity(1024);
        loop {
            if let Some(offset) = find_terminator(&header_bytes) {
                let (block, remainder) = header_bytes.split_at(offset + HEADER_TERMINATOR.len());
                let mut parsed = parse_cgi_header(block)?;
                self.pending_body = Bytes::copy_from_slice(remainder);
                parsed.first_body = self.pending_body.clone();
                self.response_status = Some(parsed.status);
                return Ok(parsed);
            }
            if header_bytes.len() >= MAX_HEADER_BYTES {
                return Err(FastCgiError::Protocol(format!(
                    "response header exceeds the {MAX_HEADER_BYTES}-byte bound"
                )));
            }
            let Some(content) = self.read_stream_record(RecordType::Stdout).await? else {
                return Err(FastCgiError::Protocol(
                    "responder ended the stream before CGI headers completed".into(),
                ));
            };
            if !content.is_empty() {
                header_bytes.extend_from_slice(&content);
            }
        }
    }

    /// 📤 Reads the next response body chunk; `None` means the response ended.
    ///
    /// Stderr records are consumed and optionally retained for logging;
    /// `END_REQUEST` finishes the stream. Memory stays bounded by one record.
    pub async fn read_body_chunk(&mut self) -> Result<Option<Bytes>, FastCgiError> {
        if self.finished {
            return Ok(None);
        }
        if !self.pending_body.is_empty() {
            return Ok(Some(std::mem::take(&mut self.pending_body)));
        }
        loop {
            let Some(content) = self.read_stream_record(RecordType::Stdout).await? else {
                self.finished = true;
                return Ok(None);
            };
            // 📭 An empty STDOUT record is not the end by itself; the
            // responder closes the exchange with END_REQUEST, and some
            // responders send the empty record early.
            if !content.is_empty() {
                return Ok(Some(content));
            }
        }
    }

    /// ⚠️ Returns collected stderr, bounded, and clears the buffer.
    pub fn take_stderr(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.stderr)
    }

    /// 📟 The status parsed from the response header, when one was read.
    pub fn response_status(&self) -> Option<u16> {
        self.response_status
    }

    /// 📡 Reads records until one of `expected` type arrives.
    ///
    /// Stderr records are collected or discarded according to
    /// `capture_stderr`; `END_REQUEST` stops the stream and reports a
    /// non-complete protocol status as an error. Returns `None` at the
    /// stream's end (empty record for a stream type, or `END_REQUEST`).
    async fn read_stream_record(
        &mut self,
        expected: RecordType,
    ) -> Result<Option<Bytes>, FastCgiError> {
        loop {
            let (record_type, content) = self.read_record().await?;
            match record_type {
                RecordType::Stderr => {
                    if self.capture_stderr && self.stderr.len() < MAX_STDERR_BYTES {
                        let room = MAX_STDERR_BYTES - self.stderr.len();
                        self.stderr
                            .extend_from_slice(&content[..content.len().min(room)]);
                    }
                }
                RecordType::EndRequest => {
                    let (app_status, protocol_status) = parse_end_request(&content)?;
                    if protocol_status != ProtocolStatus::RequestComplete {
                        return Err(FastCgiError::Rejected(protocol_status));
                    }
                    if app_status != 0 {
                        tracing::warn!(
                            app_status,
                            "⚠️ FastCGI responder finished with a nonzero application status"
                        );
                    }
                    return Ok(None);
                }
                RecordType::AbortRequest
                | RecordType::BeginRequest
                | RecordType::Params
                | RecordType::Stdin => {
                    return Err(FastCgiError::Protocol(format!(
                        "responder sent a request-direction {:?} record",
                        record_type
                    )));
                }
                other if other == expected => {
                    return Ok(Some(content));
                }
                other => {
                    return Err(FastCgiError::Protocol(format!(
                        "unexpected record type {other:?} while reading {expected:?}"
                    )));
                }
            }
        }
    }

    /// 📡 Reads one record's header, content, and padding.
    async fn read_record(&mut self) -> Result<(RecordType, Bytes), FastCgiError> {
        let mut header = [0u8; 8];
        self.read_exact(&mut header).await?;
        if header[0] != VERSION {
            return Err(FastCgiError::Protocol(format!(
                "unsupported protocol version {}",
                header[0]
            )));
        }
        let record_type = RecordType::try_from(header[1])
            .map_err(|()| FastCgiError::Protocol(format!("unknown record type {}", header[1])))?;
        let request_id = u16::from_be_bytes([header[2], header[3]]);
        if request_id != self.request_id {
            return Err(FastCgiError::Protocol(format!(
                "record for request {request_id}, expected {}",
                self.request_id
            )));
        }
        let content_length = u16::from_be_bytes([header[4], header[5]]) as usize;
        let padding_length = header[6] as usize;
        let mut content = vec![0u8; content_length];
        self.read_exact(&mut content).await?;
        if padding_length > 0 {
            let mut padding = vec![0u8; padding_length];
            self.read_exact(&mut padding).await?;
        }
        Ok((record_type, Bytes::from(content)))
    }

    /// 📤 Writes one record, framing `content` and padding it to 8 bytes.
    async fn write_record(
        &mut self,
        record_type: RecordType,
        content: &[u8],
    ) -> Result<(), FastCgiError> {
        if content.len() > MAX_RECORD_CONTENT {
            return Err(FastCgiError::Protocol(format!(
                "record content exceeds the {MAX_RECORD_CONTENT}-byte ceiling"
            )));
        }
        let padding_length = (8 - (content.len() % 8)) % 8;
        let mut frame = Vec::with_capacity(8 + content.len() + padding_length);
        frame.push(VERSION);
        frame.push(record_type as u8);
        frame.extend_from_slice(&self.request_id.to_be_bytes());
        frame.extend_from_slice(&(content.len() as u16).to_be_bytes());
        frame.push(padding_length as u8);
        frame.push(0);
        frame.extend_from_slice(content);
        frame.resize(frame.len() + padding_length, 0);
        self.write_all(&frame).await?;
        Ok(())
    }

    /// 📥 Reads exactly `buffer.len()` bytes under the read deadline.
    async fn read_exact(&mut self, buffer: &mut [u8]) -> Result<(), FastCgiError> {
        match self.read_timeout {
            Some(timeout) => tokio::time::timeout(timeout, self.stream.read_exact(buffer))
                .await
                .map_err(|_| FastCgiError::TimedOut)?
                .map(|_| ())
                .map_err(FastCgiError::from),
            None => self
                .stream
                .read_exact(buffer)
                .await
                .map(|_| ())
                .map_err(FastCgiError::from),
        }
    }

    /// 📤 Writes a whole buffer under the write deadline.
    async fn write_all(&mut self, buffer: &[u8]) -> Result<(), FastCgiError> {
        match self.write_timeout {
            Some(timeout) => tokio::time::timeout(timeout, self.stream.write_all(buffer))
                .await
                .map_err(|_| FastCgiError::TimedOut)?
                .map_err(FastCgiError::from),
            None => self
                .stream
                .write_all(buffer)
                .await
                .map_err(FastCgiError::from),
        }
    }
}

// MARK: - Record helpers

/// 📐 Encodes one name or value length the FastCGI way: one byte up to 127,
/// otherwise four bytes with the high bit set.
fn encode_size(out: &mut Vec<u8>, size: usize) {
    if size > 127 {
        out.extend_from_slice(&((size as u32) | (1 << 31)).to_be_bytes());
    } else {
        out.push(size as u8);
    }
}

/// 🏁 Splits an `END_REQUEST` record into its application status and result.
fn parse_end_request(content: &[u8]) -> Result<(u32, ProtocolStatus), FastCgiError> {
    if content.len() != 8 {
        return Err(FastCgiError::Protocol(format!(
            "END_REQUEST record has {} content bytes, expected 8",
            content.len()
        )));
    }
    let app_status = u32::from_be_bytes([content[0], content[1], content[2], content[3]]);
    let status = ProtocolStatus::try_from(content[4])
        .map_err(|()| FastCgiError::Protocol(format!("unknown protocol status {}", content[4])))?;
    Ok((app_status, status))
}

/// 🔍 Finds the CGI header terminator, returning the offset of its first byte.
fn find_terminator(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(HEADER_TERMINATOR.len())
        .position(|window| window == HEADER_TERMINATOR)
}

/// 🧾 Parses one CGI header block (up to and including the blank line).
///
/// `Status:` becomes the HTTP status; every other line becomes a header.
/// The header names keep their original casing, which HTTP treats
/// case-insensitively.
fn parse_cgi_header(block: &[u8]) -> Result<ResponseHeader, FastCgiError> {
    let text = std::str::from_utf8(block)
        .map_err(|_| FastCgiError::Protocol("CGI header block is not valid UTF-8".into()))?;
    let mut status = 200u16;
    let mut reason = None;
    let mut headers = Vec::new();
    for line in text.split("\r\n") {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(FastCgiError::Protocol(format!(
                "CGI header line without a colon: {line:?}"
            )));
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("status") {
            let (code, phrase) = value
                .split_once(' ')
                .map_or((value, None), |(code, phrase)| (code, Some(phrase)));
            status = code
                .trim()
                .parse::<u16>()
                .map_err(|_| FastCgiError::Protocol(format!("bad Status header: {value:?}")))?;
            reason = phrase.map(str::to_string);
        } else {
            headers.push((name.to_string(), value.to_string()));
        }
    }
    Ok(ResponseHeader {
        status,
        reason,
        headers,
        first_body: Bytes::new(),
    })
}

// MARK: - Tests

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
    use tokio::time::Duration;

    /// 🧪 A scripted FastCGI responder used by the protocol tests.
    struct ScriptedResponder {
        stream: tokio::io::DuplexStream,
    }

    impl ScriptedResponder {
        async fn read_record(&mut self) -> (u8, Vec<u8>) {
            let mut header = [0u8; 8];
            self.stream.read_exact(&mut header).await.unwrap();
            assert_eq!(header[0], 1, "responder saw the wrong protocol version");
            let content_length = u16::from_be_bytes([header[4], header[5]]) as usize;
            let padding = header[6] as usize;
            let mut content = vec![0u8; content_length];
            self.stream.read_exact(&mut content).await.unwrap();
            let mut skip = vec![0u8; padding];
            self.stream.read_exact(&mut skip).await.unwrap();
            (header[1], content)
        }

        async fn write_record(&mut self, record_type: u8, content: &[u8]) {
            let padding = (8 - (content.len() % 8)) % 8;
            let mut frame = Vec::with_capacity(8 + content.len() + padding);
            frame.push(1);
            frame.push(record_type);
            frame.extend_from_slice(&1u16.to_be_bytes());
            frame.extend_from_slice(&(content.len() as u16).to_be_bytes());
            frame.push(padding as u8);
            frame.push(0);
            frame.extend_from_slice(content);
            frame.resize(frame.len() + padding, 0);
            self.stream.write_all(&frame).await.unwrap();
        }

        async fn finish_request(&mut self, app_status: u32, protocol_status: u8) {
            let mut end = [0u8; 8];
            end[..4].copy_from_slice(&app_status.to_be_bytes());
            end[4] = protocol_status;
            self.write_record(3, &end).await;
        }
    }

    /// 🧪 Sends a whole request and reads the CGI headers plus the body.
    #[tokio::test]
    async fn round_trip_streams_params_stdin_and_body() {
        let (client_half, server_half) = duplex(64 * 1024);
        let mut responder = ScriptedResponder {
            stream: server_half,
        };
        let server = tokio::spawn(async move {
            let (record_type, content) = responder.read_record().await;
            assert_eq!(record_type, 1, "BEGIN_REQUEST came first");
            assert_eq!(
                u16::from_be_bytes([content[0], content[1]]),
                1,
                "responder role was requested"
            );

            let (record_type, content) = responder.read_record().await;
            assert_eq!(record_type, 4, "PARAMS followed BEGIN_REQUEST");
            let text = std::str::from_utf8(&content).unwrap();
            assert!(text.contains("REQUEST_METHOD"));
            assert!(text.contains("GET"));
            let (record_type, content) = responder.read_record().await;
            assert_eq!(record_type, 4);
            assert!(content.is_empty(), "PARAMS ends with an empty record");

            let (record_type, content) = responder.read_record().await;
            assert_eq!(record_type, 5, "STDIN follows PARAMS");
            assert_eq!(content, b"hello");
            let (record_type, content) = responder.read_record().await;
            assert_eq!(record_type, 5);
            assert!(content.is_empty(), "STDIN ends with an empty record");

            let cgi = b"Status: 201 Created\r\nContent-Type: text/plain\r\nX-Probe: yes\r\n\r\n";
            responder.write_record(6, cgi).await;
            responder.write_record(6, b"world").await;
            responder.write_record(6, &[]).await;
            responder.finish_request(0, 0).await;
        });

        let mut client = Client::new(client_half, 1, Some(Duration::from_secs(5)), None, false);
        client.begin_request().await.unwrap();
        let mut params = BTreeMap::new();
        params.insert("REQUEST_METHOD".to_string(), "GET".to_string());
        client.send_params(&params).await.unwrap();
        client.send_stdin(b"hello").await.unwrap();
        client.finish_stdin().await.unwrap();

        let header = client.read_response_header().await.unwrap();
        assert_eq!(header.status, 201);
        assert_eq!(header.reason.as_deref(), Some("Created"));
        assert!(
            header
                .headers
                .iter()
                .any(|(name, value)| name == "Content-Type" && value == "text/plain")
        );
        let mut body = Vec::new();
        while let Some(chunk) = client.read_body_chunk().await.unwrap() {
            body.extend_from_slice(&chunk);
        }
        assert_eq!(body, b"world");
        server.await.unwrap();
    }

    /// 🧪 A header split across records and a body sharing the last record
    /// must both survive the parse.
    #[tokio::test]
    async fn header_split_across_records_keeps_first_body_bytes() {
        let (client_half, server_half) = duplex(64 * 1024);
        let mut responder = ScriptedResponder {
            stream: server_half,
        };
        let server = tokio::spawn(async move {
            for _ in 0..3 {
                let _ = responder.read_record().await;
            }
            responder
                .write_record(6, b"Status: 200 OK\r\nContent-T")
                .await;
            responder
                .write_record(6, b"ype: text/plain\r\n\r\npartial")
                .await;
            responder.write_record(6, &[]).await;
            responder.finish_request(0, 0).await;
        });

        let mut client = Client::new(client_half, 1, Some(Duration::from_secs(5)), None, false);
        client.begin_request().await.unwrap();
        client.send_params(&BTreeMap::new()).await.unwrap();
        client.finish_stdin().await.unwrap();
        let header = client.read_response_header().await.unwrap();
        assert_eq!(header.status, 200);
        assert!(
            header
                .headers
                .iter()
                .any(|(name, value)| name == "Content-Type" && value == "text/plain")
        );
        let first = client.read_body_chunk().await.unwrap().unwrap();
        assert_eq!(&first[..], b"partial");
        assert!(client.read_body_chunk().await.unwrap().is_none());
        server.await.unwrap();
    }

    /// ⚠️ Stderr records are consumed without entering the body, and are
    /// retained when capture is on.
    #[tokio::test]
    async fn stderr_is_skipped_from_the_body_and_captured_on_request() {
        let (client_half, server_half) = duplex(64 * 1024);
        let mut responder = ScriptedResponder {
            stream: server_half,
        };
        let server = tokio::spawn(async move {
            for _ in 0..3 {
                let _ = responder.read_record().await;
            }
            responder.write_record(7, b"PHP Notice: something").await;
            responder.write_record(6, b"Status: 200 OK\r\n\r\nok").await;
            responder.write_record(6, &[]).await;
            responder.finish_request(0, 0).await;
        });

        let mut client = Client::new(client_half, 1, Some(Duration::from_secs(5)), None, true);
        client.begin_request().await.unwrap();
        client.send_params(&BTreeMap::new()).await.unwrap();
        client.finish_stdin().await.unwrap();
        let header = client.read_response_header().await.unwrap();
        assert_eq!(header.status, 200);
        let mut body = Vec::new();
        while let Some(chunk) = client.read_body_chunk().await.unwrap() {
            body.extend_from_slice(&chunk);
        }
        assert_eq!(body, b"ok");
        assert!(
            String::from_utf8(client.take_stderr())
                .unwrap()
                .contains("PHP Notice")
        );
        server.await.unwrap();
    }

    /// 🏁 A responder that reports overload must surface as a rejection.
    #[tokio::test]
    async fn overloaded_responder_is_a_rejection() {
        let (client_half, server_half) = duplex(64 * 1024);
        let mut responder = ScriptedResponder {
            stream: server_half,
        };
        let server = tokio::spawn(async move {
            for _ in 0..3 {
                let _ = responder.read_record().await;
            }
            responder
                .write_record(6, b"Status: 503 Service Unavailable\r\n\r\n")
                .await;
            responder.write_record(6, &[]).await;
            responder.finish_request(0, 2).await;
        });

        let mut client = Client::new(client_half, 1, Some(Duration::from_secs(5)), None, false);
        client.begin_request().await.unwrap();
        client.send_params(&BTreeMap::new()).await.unwrap();
        client.finish_stdin().await.unwrap();
        let header = client.read_response_header().await.unwrap();
        assert_eq!(header.status, 503);
        let result = client.read_body_chunk().await;
        assert!(
            matches!(
                result,
                Err(FastCgiError::Rejected(ProtocolStatus::Overloaded))
            ),
            "overload must surface as a rejection, got {result:?}"
        );
        server.await.unwrap();
    }

    /// 📏 The header bound fails closed instead of growing without limit.
    #[tokio::test]
    async fn oversized_header_block_is_rejected() {
        let (client_half, server_half) = duplex(128 * 1024);
        let mut responder = ScriptedResponder {
            stream: server_half,
        };
        let server = tokio::spawn(async move {
            for _ in 0..3 {
                let _ = responder.read_record().await;
            }
            // 🧮 One record can hold at most 65,500 content bytes, so the
            // oversized block must arrive as several records.
            responder
                .write_record(6, &vec![b'x'; MAX_RECORD_CONTENT])
                .await;
            responder
                .write_record(6, &vec![b'x'; MAX_HEADER_BYTES + 1024 - MAX_RECORD_CONTENT])
                .await;
            responder.write_record(6, &[]).await;
            responder.finish_request(0, 0).await;
        });

        let mut client = Client::new(client_half, 1, Some(Duration::from_secs(5)), None, false);
        client.begin_request().await.unwrap();
        client.send_params(&BTreeMap::new()).await.unwrap();
        client.finish_stdin().await.unwrap();
        let error = client
            .read_response_header()
            .await
            .expect_err("bound errors");
        assert!(
            matches!(&error, FastCgiError::Protocol(message) if message.contains("header")),
            "got {error:?}"
        );
        server.await.unwrap();
    }

    /// 🧮 The 1-byte and 4-byte length encodings match the wire format.
    #[test]
    fn size_encoding_switches_at_127() {
        let mut small = Vec::new();
        encode_size(&mut small, 42);
        assert_eq!(small, vec![42]);

        let mut large = Vec::new();
        encode_size(&mut large, 200);
        assert_eq!(large.len(), 4);
        assert_eq!(
            u32::from_be_bytes([large[0], large[1], large[2], large[3]]),
            200 | (1 << 31)
        );
    }

    /// 🧪 Many parameters are split across multiple PARAMS records so no
    /// record exceeds the framing ceiling.
    #[tokio::test]
    async fn many_params_split_into_multiple_records() {
        let (client_half, server_half) = duplex(128 * 1024);
        let mut responder = ScriptedResponder {
            stream: server_half,
        };
        let server = tokio::spawn(async move {
            let (record_type, _) = responder.read_record().await;
            assert_eq!(record_type, 1);
            let mut records = 0;
            loop {
                let (record_type, content) = responder.read_record().await;
                assert_eq!(record_type, 4);
                if content.is_empty() {
                    break;
                }
                records += 1;
            }
            assert!(records >= 2, "the params needed multiple records");
            let (record_type, content) = responder.read_record().await;
            assert_eq!(record_type, 5);
            assert!(content.is_empty());
            responder.write_record(6, b"Status: 200 OK\r\n\r\n").await;
            responder.write_record(6, &[]).await;
            responder.finish_request(0, 0).await;
        });

        let mut client = Client::new(client_half, 1, Some(Duration::from_secs(5)), None, false);
        client.begin_request().await.unwrap();
        let mut params = BTreeMap::new();
        for index in 0..2_000 {
            params.insert(format!("VAR_{index}"), "v".repeat(40));
        }
        client.send_params(&params).await.unwrap();
        client.finish_stdin().await.unwrap();
        let header = client.read_response_header().await.unwrap();
        assert_eq!(header.status, 200);
        server.await.unwrap();
    }

    /// ⏱️ A responder that never answers trips the read deadline.
    #[tokio::test]
    async fn read_deadline_fails_closed() {
        let (client_half, _server_half) = duplex(1024);
        // 🧹 The server half is dropped, so reads would block forever
        // without the deadline.
        let mut client = Client::new(client_half, 1, Some(Duration::from_millis(50)), None, false);
        client.begin_request().await.unwrap();
        client.send_params(&BTreeMap::new()).await.unwrap();
        client.finish_stdin().await.unwrap();
        let error = client
            .read_response_header()
            .await
            .expect_err("deadline fires");
        assert!(matches!(error, FastCgiError::TimedOut));
    }
}
