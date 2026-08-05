// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🗜️ Response content-coding negotiation and streaming encoders.
//!
//! Two concerns live here, both kept out of the `ProxyHttp` impl so they are
//! testable without a live Pingora `Session`:
//!
//! 1. **Negotiation** — picking one coding from what the client will accept
//!    and what this server was configured to offer.
//! 2. **Encoding** — feeding response body chunks through that coding without
//!    ever holding the whole body in memory.
//!
//! The bounded-memory property is the load-bearing one. An encoder that only
//! emits output when the body ends turns a large proxied response into a
//! resident copy of that entire response — an OOM an attacker can trigger by
//! requesting a big file. Every encoder here is driven chunk-in / chunk-out.

use bytes::Bytes;
use flate2::Compression;
use flate2::write::GzEncoder;
use pingclair_core::config::Encoding;
use std::io::Write;

/// Compression level used for proxied responses.
///
/// Fastest setting on purpose. A reverse proxy compresses on the request path
/// with the client waiting, so CPU spent chasing a marginally better ratio is
/// latency the client pays on every single response — unlike static files,
/// which can be compressed once and cached.
const ZSTD_LEVEL: i32 = 1;

// MARK: - Negotiation

/// 🤝 Picks the coding to use for a response, or `None` for identity.
///
/// `offered` is the server's preference order (the order `encode` listed the
/// codings). The quality-value reading lives in `pingclair-core` because
/// `pingclair-static` needs exactly the same rules, and for a while the two
/// crates each had their own: this one was correct and unreachable — nothing in
/// production called it — while the static path used `header.contains("gzip")`
/// and therefore compressed for a client that had sent `gzip;q=0`. One
/// implementation, so a fix here cannot fail to reach a served file.
pub fn negotiate(accept_encoding: &str, offered: &[Encoding]) -> Option<Encoding> {
    if offered.is_empty() {
        return None;
    }
    let tokens: Vec<&str> = offered.iter().map(|e| e.token()).collect();
    let chosen = pingclair_core::encoding::negotiate(accept_encoding, &tokens)?;
    offered.iter().copied().find(|e| e.token() == chosen)
}

// MARK: - Streaming encoders

/// A streaming encoder for one response body, bounded to one chunk of memory.
pub enum ResponseEncoder {
    Gzip(GzEncoder<Vec<u8>>),
    /// Boxed because `zstd`'s encoder holds a sizable internal context and
    /// this enum lives inline in every request's context.
    Zstd(Box<zstd::stream::write::Encoder<'static, Vec<u8>>>),
}

impl ResponseEncoder {
    /// Creates the encoder for a negotiated coding.
    ///
    /// Fallible only because `zstd` allocates its compression context up
    /// front; a failure here means the response goes out uncompressed, which
    /// is always a safe outcome.
    pub fn new(encoding: Encoding) -> std::io::Result<Self> {
        Ok(match encoding {
            Encoding::Gzip => Self::Gzip(GzEncoder::new(Vec::new(), Compression::fast())),
            Encoding::Zstd => Self::Zstd(Box::new(zstd::stream::write::Encoder::new(
                Vec::new(),
                ZSTD_LEVEL,
            )?)),
        })
    }

    /// The `Content-Encoding` token this encoder produces.
    pub fn token(&self) -> &'static str {
        match self {
            Self::Gzip(_) => Encoding::Gzip.token(),
            Self::Zstd(_) => Encoding::Zstd.token(),
        }
    }

    fn writer(&mut self) -> &mut dyn Write {
        match self {
            Self::Gzip(encoder) => encoder,
            Self::Zstd(encoder) => encoder.as_mut(),
        }
    }

    /// Drains whatever the encoder has flushed into its output buffer.
    fn take_output(&mut self) -> Vec<u8> {
        match self {
            Self::Gzip(encoder) => std::mem::take(encoder.get_mut()),
            Self::Zstd(encoder) => std::mem::take(encoder.get_mut()),
        }
    }

    /// Finishes the stream, returning the trailing bytes.
    ///
    /// Both codings need this: gzip appends a CRC32 + length trailer, zstd an
    /// end-of-frame marker. A body truncated before this point does not
    /// decode.
    fn finish(self) -> std::io::Result<Vec<u8>> {
        match self {
            Self::Gzip(encoder) => encoder.finish(),
            Self::Zstd(encoder) => encoder.finish(),
        }
    }
}

/// Feeds one response body chunk through the negotiated encoder.
///
/// 🏗️ ARCHITECTURE: real streaming, not full-body buffering.
///
/// A naive implementation accumulates every chunk and emits output once, at
/// `end_of_stream` — so a large upstream response (or an adversarial client
/// requesting one) means buffering the *entire* body in memory before the
/// first byte goes out: an OOM risk independent of how much of the response
/// actually needs to be in flight at once. Here we force a sync flush after
/// every chunk, pushing whatever the codec has buffered internally out into
/// its small `Vec<u8>`, then drain that Vec as this chunk's output via
/// `mem::take`. Memory use is bounded by one chunk's worth of compressed
/// bytes, regardless of total response size.
///
/// The per-chunk flush costs some ratio — both codecs must close a block at
/// every flush point — which is the deliberate trade for a proxy that must
/// not let response size drive memory use.
pub fn stream_chunk(
    encoder_slot: &mut Option<ResponseEncoder>,
    body: &mut Option<Bytes>,
    end_of_stream: bool,
) {
    if encoder_slot.is_none() {
        return;
    }

    // Feed this chunk into the encoder.
    if let Some(chunk) = body.as_ref()
        && let Some(encoder) = encoder_slot.as_mut()
        && let Err(e) = encoder.writer().write_all(chunk)
    {
        tracing::warn!(
            "⚠️ Compression failed, aborting compression for the rest of this response: {}",
            e
        );
        // Bail out of compression entirely; the client already received a
        // Content-Encoding header for this response so we cannot fall back to
        // plaintext mid-stream — better to end the response short than to send
        // a client a body it can't decode.
        *encoder_slot = None;
        *body = None;
        return;
    }

    if end_of_stream {
        if let Some(encoder) = encoder_slot.take() {
            match encoder.finish() {
                Ok(tail) => *body = Some(Bytes::from(tail)),
                Err(e) => {
                    tracing::warn!("⚠️ Compression finalize failed: {}", e);
                    *body = Some(Bytes::new());
                }
            }
        }
        return;
    }

    if let Some(encoder) = encoder_slot.as_mut() {
        if let Err(e) = encoder.writer().flush() {
            tracing::warn!("⚠️ Compression flush failed: {}", e);
        }
        let out = encoder.take_output();
        *body = Some(Bytes::from(out));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    // MARK: - Negotiation

    const BOTH: &[Encoding] = &[Encoding::Zstd, Encoding::Gzip];

    #[test]
    fn picks_the_server_preferred_coding_when_the_client_is_indifferent() {
        assert_eq!(negotiate("gzip, zstd", BOTH), Some(Encoding::Zstd));
        assert_eq!(
            negotiate("gzip, zstd", &[Encoding::Gzip, Encoding::Zstd]),
            Some(Encoding::Gzip)
        );
    }

    #[test]
    fn falls_back_to_the_only_coding_the_client_accepts() {
        assert_eq!(negotiate("gzip", BOTH), Some(Encoding::Gzip));
        assert_eq!(negotiate("zstd", BOTH), Some(Encoding::Zstd));
    }

    #[test]
    fn honors_client_quality_values_over_server_order() {
        // Server prefers zstd, but this client clearly wants gzip.
        assert_eq!(
            negotiate("zstd;q=0.1, gzip;q=1.0", BOTH),
            Some(Encoding::Gzip)
        );
        assert_eq!(
            negotiate("zstd;q=1.0, gzip;q=0.5", BOTH),
            Some(Encoding::Zstd)
        );
    }

    /// `q=0` means "not acceptable" — sending it anyway breaks the client.
    #[test]
    fn treats_q_zero_as_a_refusal() {
        assert_eq!(negotiate("zstd;q=0, gzip", BOTH), Some(Encoding::Gzip));
        assert_eq!(negotiate("gzip;q=0, zstd;q=0", BOTH), None);
        assert_eq!(negotiate("gzip;q=0.000", BOTH), None);
    }

    #[test]
    fn wildcard_accepts_anything_not_named() {
        assert_eq!(negotiate("*", BOTH), Some(Encoding::Zstd));
        // An explicit refusal beats the wildcard even when listed after it.
        assert_eq!(negotiate("*, zstd;q=0", BOTH), Some(Encoding::Gzip));
        assert_eq!(negotiate("zstd;q=0, *", BOTH), Some(Encoding::Gzip));
        // ...and a wildcard refusal is not overridden by server preference.
        assert_eq!(negotiate("*;q=0", BOTH), None);
        assert_eq!(negotiate("*;q=0, gzip", BOTH), Some(Encoding::Gzip));
    }

    #[test]
    fn ignores_codings_this_proxy_cannot_produce() {
        // Brotli is common in real headers and must not be selected.
        assert_eq!(negotiate("br", BOTH), None);
        assert_eq!(negotiate("br, gzip", BOTH), Some(Encoding::Gzip));
        assert_eq!(negotiate("deflate, identity", BOTH), None);
    }

    #[test]
    fn empty_offer_list_disables_compression() {
        assert_eq!(negotiate("gzip, zstd, br", &[]), None);
    }

    #[test]
    fn handles_absent_whitespace_and_case_variation() {
        assert_eq!(negotiate("", BOTH), None);
        assert_eq!(negotiate("  GZIP  ", BOTH), Some(Encoding::Gzip));
        assert_eq!(
            negotiate("gzip ;  q = 0.9 , zstd;q=1", BOTH),
            Some(Encoding::Zstd)
        );
        // Legacy alias still seen from old clients.
        assert_eq!(negotiate("x-gzip", BOTH), Some(Encoding::Gzip));
    }

    /// A junk q-parameter must not silently disable a coding the client asked
    /// for — advisory header, so degrade to "acceptable" rather than refuse.
    #[test]
    fn malformed_quality_values_are_treated_as_acceptable() {
        assert_eq!(negotiate("gzip;q=banana", BOTH), Some(Encoding::Gzip));
        assert_eq!(negotiate("gzip;q=", BOTH), Some(Encoding::Gzip));
        assert_eq!(negotiate("gzip;q=NaN", BOTH), Some(Encoding::Gzip));
        // Out-of-range values clamp instead of being rejected outright.
        assert_eq!(negotiate("gzip;q=5", BOTH), Some(Encoding::Gzip));
        assert_eq!(
            negotiate("gzip;q=-1, zstd;q=0.2", BOTH),
            Some(Encoding::Zstd)
        );
    }

    // MARK: - Encoders

    fn drive(encoding: Encoding, chunks: &[&[u8]]) -> (Vec<u8>, usize) {
        let mut slot = Some(ResponseEncoder::new(encoding).unwrap());
        let mut wire = Vec::new();
        let mut largest_chunk = 0;

        for chunk in chunks {
            let mut body = Some(Bytes::copy_from_slice(chunk));
            stream_chunk(&mut slot, &mut body, false);
            let out = body.unwrap_or_default();
            largest_chunk = largest_chunk.max(out.len());
            wire.extend_from_slice(&out);
        }

        let mut tail = None;
        stream_chunk(&mut slot, &mut tail, true);
        wire.extend_from_slice(&tail.unwrap_or_default());
        (wire, largest_chunk)
    }

    fn decompress(encoding: Encoding, wire: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        match encoding {
            Encoding::Gzip => {
                flate2::read::GzDecoder::new(wire)
                    .read_to_end(&mut out)
                    .unwrap();
            }
            Encoding::Zstd => {
                zstd::stream::read::Decoder::new(wire)
                    .unwrap()
                    .read_to_end(&mut out)
                    .unwrap();
            }
        }
        out
    }

    #[test]
    fn round_trips_a_multi_chunk_body_for_every_coding() {
        for encoding in [Encoding::Gzip, Encoding::Zstd] {
            let chunks: Vec<Vec<u8>> = (0..16)
                .map(|i| format!("chunk {i}: {}\n", "payload ".repeat(64)).into_bytes())
                .collect();
            let expected: Vec<u8> = chunks.concat();
            let refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();

            let (wire, _) = drive(encoding, &refs);
            assert_eq!(
                decompress(encoding, &wire),
                expected,
                "{} round-trip mismatch",
                encoding.token()
            );
        }
    }

    #[test]
    fn round_trips_an_empty_body_for_every_coding() {
        for encoding in [Encoding::Gzip, Encoding::Zstd] {
            let (wire, _) = drive(encoding, &[]);
            assert!(
                decompress(encoding, &wire).is_empty(),
                "{} should decode to an empty body",
                encoding.token()
            );
        }
    }

    /// 🛡️ The OOM guard, stated as a test rather than a comment.
    ///
    /// Drives 64 MiB through each encoder and asserts no single emitted chunk
    /// approaches the body size. A buffer-everything implementation emits the
    /// whole compressed body in one piece at `end_of_stream` and fails here.
    #[test]
    fn memory_stays_bounded_by_chunk_size_not_body_size() {
        const CHUNK: usize = 64 * 1024;
        const CHUNKS: usize = 1024; // 64 MiB total

        for encoding in [Encoding::Gzip, Encoding::Zstd] {
            let mut slot = Some(ResponseEncoder::new(encoding).unwrap());

            // Payload must be incompressible *and* unique per chunk. Repeating
            // one block instead lets zstd's window dedupe 64 MiB down to a few
            // KB, which makes the "output is flowing" assertion below trivially
            // false for reasons that have nothing to do with buffering.
            let mut rng: u64 = 0x2545_F491_4F6C_DD1D;
            let mut next_chunk = || {
                (0..CHUNK)
                    .map(|_| {
                        rng ^= rng << 13;
                        rng ^= rng >> 7;
                        rng ^= rng << 17;
                        rng as u8
                    })
                    .collect::<Vec<u8>>()
            };

            let mut largest = 0usize;
            let mut total = 0usize;
            for _ in 0..CHUNKS {
                let mut body = Some(Bytes::from(next_chunk()));
                stream_chunk(&mut slot, &mut body, false);
                let out = body.unwrap_or_default();
                largest = largest.max(out.len());
                total += out.len();
            }
            let mut tail = None;
            stream_chunk(&mut slot, &mut tail, true);

            // Generous ceiling: a few chunks' worth. The failure mode this
            // catches is off by three orders of magnitude, not by a factor.
            let ceiling = CHUNK * 4;
            assert!(
                largest <= ceiling,
                "{}: largest emitted chunk {largest} exceeds {ceiling}; \
                 encoder is buffering the body instead of streaming it",
                encoding.token()
            );
            // Incompressible input, so a streaming encoder must have pushed
            // out roughly the whole body already. A buffering one emits
            // nothing until `finish()`.
            assert!(
                total > (CHUNK * CHUNKS) / 2,
                "{}: only {total} bytes emitted before end_of_stream — output \
                 was withheld until the end",
                encoding.token()
            );
        }
    }

    /// Every chunk must be emitted as it is fed, not held back — this is what
    /// keeps a slow-trickle response (SSE-shaped traffic that still qualifies
    /// for compression) flowing instead of stalling until it ends.
    #[test]
    fn each_chunk_produces_output_before_the_stream_ends() {
        for encoding in [Encoding::Gzip, Encoding::Zstd] {
            let mut slot = Some(ResponseEncoder::new(encoding).unwrap());
            let mut emitted_per_chunk = Vec::new();

            for i in 0..8 {
                let mut body = Some(Bytes::from(format!("event: tick {i}\n\n")));
                stream_chunk(&mut slot, &mut body, false);
                emitted_per_chunk.push(body.unwrap_or_default().len());
            }

            assert!(
                emitted_per_chunk.iter().all(|len| *len > 0),
                "{}: some chunk produced no output: {emitted_per_chunk:?}",
                encoding.token()
            );
        }
    }

    /// A flushed prefix must be decodable on its own — otherwise a client
    /// reading incrementally sees nothing until the response completes, and
    /// per-chunk flushing buys us nothing.
    #[test]
    fn a_flushed_prefix_decodes_without_the_trailer() {
        for encoding in [Encoding::Gzip, Encoding::Zstd] {
            let mut slot = Some(ResponseEncoder::new(encoding).unwrap());
            let mut wire = Vec::new();
            for i in 0..4 {
                let mut body = Some(Bytes::from(format!("line {i}\n")));
                stream_chunk(&mut slot, &mut body, false);
                wire.extend_from_slice(&body.unwrap_or_default());
            }

            // Decode the prefix, tolerating the missing end-of-stream marker.
            let mut out = Vec::new();
            match encoding {
                Encoding::Gzip => {
                    let _ = flate2::read::GzDecoder::new(&wire[..]).read_to_end(&mut out);
                }
                Encoding::Zstd => {
                    let _ = zstd::stream::read::Decoder::new(&wire[..])
                        .unwrap()
                        .read_to_end(&mut out);
                }
            }
            assert!(
                out.starts_with(b"line 0\n"),
                "{}: flushed prefix did not decode incrementally, got {out:?}",
                encoding.token()
            );
        }
    }

    #[test]
    fn a_none_encoder_leaves_the_body_untouched() {
        let mut slot: Option<ResponseEncoder> = None;
        let mut body = Some(Bytes::from_static(b"plaintext"));
        stream_chunk(&mut slot, &mut body, false);
        assert_eq!(body.as_deref(), Some(&b"plaintext"[..]));

        stream_chunk(&mut slot, &mut body, true);
        assert_eq!(body.as_deref(), Some(&b"plaintext"[..]));
    }

    #[test]
    fn encoder_reports_its_content_encoding_token() {
        assert_eq!(
            ResponseEncoder::new(Encoding::Gzip).unwrap().token(),
            "gzip"
        );
        assert_eq!(
            ResponseEncoder::new(Encoding::Zstd).unwrap().token(),
            "zstd"
        );
    }
}
