// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔐 Borrowed ClientHello parsing across TLS records without reassembly allocation.

/// 🔎 A classification never exposes metadata from an incomplete handshake.
#[derive(Debug)]
pub enum Classification<'a> {
    /// 📥 Absolute input size needed before another parse can make progress.
    NeedMore(usize),
    /// 🧭 Not a supported ClientHello, including malformed input; try non-TLS routes.
    NotTls,
    /// 🔐 A complete ClientHello with borrowed SNI and ALPN fields.
    Tls(ClientHello<'a>),
}

/// 🔐 Validated metadata borrows the original wire buffer, even across records.
#[derive(Debug)]
pub struct ClientHello<'a> {
    sni: Option<Cursor<'a>>,
    alpn: Option<Cursor<'a>>,
}

impl ClientHello<'_> {
    /// 🏷️ Compares an exact SNI without allocating or normalizing client input.
    pub fn matches_sni(&self, name: &str) -> bool {
        self.sni
            .is_some_and(|sni| sni.equals(name.as_bytes(), true))
    }

    /// 🤝 Tests protocol membership rather than searching a comma-joined string.
    pub fn offers_alpn(&self, protocol: &str) -> bool {
        let Some(mut protocols) = self.alpn else {
            return false;
        };
        while protocols.left > 0 {
            let Ok(length) = protocols.byte() else {
                return false;
            };
            let Ok(field) = protocols.take(length.into()) else {
                return false;
            };
            if field.equals(protocol.as_bytes(), false) {
                return true;
            }
        }
        false
    }
}

#[derive(Debug)]
enum ParseError {
    More(usize),
    Declined,
}
type Result<T> = std::result::Result<T, ParseError>;

/// 📦 A bounded logical field whose bytes may span several TLS records.
#[derive(Clone, Copy, Debug)]
struct Cursor<'a> {
    wire: &'a [u8],
    pos: usize,
    end: usize,
    left: usize,
}

impl<'a> Cursor<'a> {
    fn record(&mut self) -> Result<()> {
        while self.pos == self.end {
            let header_end = self.pos.checked_add(5).ok_or(ParseError::Declined)?;
            if self.wire.len() < header_end {
                return Err(ParseError::More(header_end));
            }
            let header = &self.wire[self.pos..header_end];
            if header[0] != 22 || header[1] != 3 {
                return Err(ParseError::Declined);
            }
            self.end = header_end + usize::from(u16::from_be_bytes([header[3], header[4]]));
            if self.wire.len() < self.end {
                return Err(ParseError::More(self.end));
            }
            self.pos = header_end;
        }
        Ok(())
    }

    fn byte(&mut self) -> Result<u8> {
        if self.left == 0 {
            return Err(ParseError::Declined);
        }
        self.record()?;
        let value = self.wire[self.pos];
        self.pos += 1;
        self.left -= 1;
        Ok(value)
    }

    fn word(&mut self) -> Result<usize> {
        Ok(usize::from(u16::from_be_bytes([
            self.byte()?,
            self.byte()?,
        ])))
    }

    fn take(&mut self, length: usize) -> Result<Self> {
        if length > self.left {
            return Err(ParseError::Declined);
        }
        let mut field = *self;
        field.left = length;
        let mut remaining = length;
        while remaining > 0 {
            self.record()?;
            let amount = remaining.min(self.end - self.pos);
            self.pos += amount;
            self.left -= amount;
            remaining -= amount;
        }
        Ok(field)
    }

    fn equals(mut self, bytes: &[u8], insensitive: bool) -> bool {
        self.left == bytes.len()
            && bytes.iter().all(|expected| {
                self.byte().is_ok_and(|actual| {
                    if insensitive {
                        actual.eq_ignore_ascii_case(expected)
                    } else {
                        actual == *expected
                    }
                })
            })
    }
}

/// 🔎 Classifies only complete ClientHellos; the caller bounds input and waiting.
///
/// 📌 Like nginx ssl_preread, unsupported or malformed input declines TLS
/// matching. A preread buffer overflow or deadline is the driver's close path.
pub fn classify(wire: &[u8]) -> Classification<'_> {
    // 🧭 Plain protocols can route without waiting for a full TLS header.
    if wire.first().is_some_and(|first| *first != 22) {
        return Classification::NotTls;
    }
    match parse(wire) {
        Ok(hello) => Classification::Tls(hello),
        Err(ParseError::More(size)) => Classification::NeedMore(size),
        Err(ParseError::Declined) => Classification::NotTls,
    }
}

fn parse(wire: &[u8]) -> Result<ClientHello<'_>> {
    let mut input = Cursor {
        wire,
        pos: 0,
        end: 0,
        left: usize::MAX,
    };
    if input.byte()? != 1 {
        return Err(ParseError::Declined);
    }
    let length = (usize::from(input.byte()?) << 16) | input.word()?;
    input.left = length;
    // 🔐 Validate the whole declared handshake before publishing any fields.
    let mut hello = input.take(length)?;
    hello.take(34)?;
    let session = usize::from(hello.byte()?);
    if session > 32 {
        return Err(ParseError::Declined);
    }
    hello.take(session)?;
    let ciphers = hello.word()?;
    if ciphers == 0 || ciphers % 2 != 0 {
        return Err(ParseError::Declined);
    }
    hello.take(ciphers)?;
    let compression = usize::from(hello.byte()?);
    if compression == 0 {
        return Err(ParseError::Declined);
    }
    hello.take(compression)?;
    let mut metadata = ClientHello {
        sni: None,
        alpn: None,
    };
    if hello.left == 0 {
        return Ok(metadata);
    }
    let extensions = hello.word()?;
    if extensions != hello.left {
        return Err(ParseError::Declined);
    }
    let mut saw_sni = false;
    let mut saw_alpn = false;
    while hello.left > 0 {
        let kind = hello.word()?;
        let length = hello.word()?;
        let mut extension = hello.take(length)?;
        match kind {
            0 => {
                if saw_sni {
                    return Err(ParseError::Declined);
                }
                saw_sni = true;
                let length = extension.word()?;
                if length == 0 || length != extension.left {
                    return Err(ParseError::Declined);
                }
                if extension.byte()? != 0 {
                    return Err(ParseError::Declined);
                }
                let name = extension.word()?;
                if name == 0 || name != extension.left {
                    return Err(ParseError::Declined);
                }
                metadata.sni = Some(extension.take(name)?);
            }
            16 => {
                if saw_alpn {
                    return Err(ParseError::Declined);
                }
                saw_alpn = true;
                let length = extension.word()?;
                if length == 0 || length != extension.left {
                    return Err(ParseError::Declined);
                }
                metadata.alpn = Some(extension);
                while extension.left > 0 {
                    let length = usize::from(extension.byte()?);
                    if length == 0 {
                        return Err(ParseError::Declined);
                    }
                    extension.take(length)?;
                }
            }
            _ => {}
        }
    }
    Ok(metadata)
}

#[cfg(test)]
#[path = "hello_tests.rs"]
mod tests;
