//! Minimal HAP HTTP/1.1 request encoder and response parser.
//!
//! HAP uses an HTTP/1.1-shaped framing over TCP with its own content types
//! (`application/pairing+tlv8`, `application/hap+json`). This module encodes a
//! request to bytes and parses a response (or detects that more bytes are
//! needed) from a buffer. It is transport-agnostic: the same parser is reused
//! over plaintext sockets (pre-session) and over the decrypted plaintext of the
//! record layer (post-session).

use crate::error::{Result, TransportError};

/// A parsed HAP HTTP response.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct HapResponse {
    /// The HTTP status code (e.g. 200, 204, 470).
    pub status: u16,
    /// The `Content-Type` header value, or an empty string if absent.
    pub content_type: String,
    /// The fully-assembled response body.
    pub body: Vec<u8>,
}

/// The result of attempting to parse a response from a (possibly partial)
/// buffer.
#[derive(Debug)]
#[non_exhaustive]
pub enum ParseOutcome {
    /// A complete response was parsed; `consumed` bytes were used from the
    /// front of the buffer.
    Complete {
        /// The parsed response.
        response: HapResponse,
        /// How many bytes were consumed from the front of the buffer.
        consumed: usize,
    },
    /// The buffer does not yet contain a full message; read more and retry.
    Incomplete,
}

/// The first line of a non-HTTP message we still must demux on the secure
/// session: `EVENT/1.0 200 OK`. Used by `session.rs`.
pub(crate) const EVENT_PREFIX: &[u8] = b"EVENT/1.0";
/// The start-line prefix of a HAP `HTTP/1.1` response.
pub(crate) const HTTP_PREFIX: &[u8] = b"HTTP/1.1";

/// Encode a HAP HTTP/1.1 request into bytes ready for the wire.
///
/// Emits the request line, a `Content-Type` header, a `Content-Length` header
/// (always present, `0` for empty bodies), the header terminator, and the body.
/// HAP servers key off `Content-Length`; we never chunk requests.
pub fn encode_request(method: &str, path: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
    let head = format!(
        "{method} {path} HTTP/1.1\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let mut out = Vec::with_capacity(head.len() + body.len());
    out.extend_from_slice(head.as_bytes());
    out.extend_from_slice(body);
    out
}

/// Attempt to parse one HTTP response from the front of `buf`.
///
/// # Errors
///
/// [`TransportError::MalformedHttp`] for an unparsable status line or headers;
/// [`TransportError::UnsupportedEncoding`] for a transfer encoding other than
/// `chunked`.
pub fn parse_response(buf: &[u8]) -> Result<ParseOutcome> {
    parse_message(buf, HTTP_PREFIX)
}

/// Shared message parser for both `HTTP/1.1` responses and `EVENT/1.0` pushes.
/// `expected_prefix` is the first token that must begin the start line.
///
/// # Errors
///
/// [`TransportError::MalformedHttp`] for an unparsable start line or headers;
/// [`TransportError::UnsupportedEncoding`] for an unsupported transfer encoding.
pub(crate) fn parse_message(buf: &[u8], expected_prefix: &[u8]) -> Result<ParseOutcome> {
    let Some(headers_end) = find_subslice(buf, b"\r\n\r\n") else {
        return Ok(ParseOutcome::Incomplete);
    };
    let header_block = &buf[..headers_end];
    let body_start = headers_end + 4;

    let mut lines = split_crlf(header_block);
    let start_line = lines
        .next()
        .ok_or_else(|| TransportError::MalformedHttp("empty start line".into()))?;
    if !start_line.starts_with(expected_prefix) {
        return Err(TransportError::MalformedHttp(format!(
            "unexpected start line: {}",
            String::from_utf8_lossy(start_line)
        )));
    }
    let status = parse_status_code(start_line)?;

    let mut content_type = String::new();
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    for line in lines {
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            return Err(TransportError::MalformedHttp("header without colon".into()));
        };
        let name = String::from_utf8_lossy(&line[..colon])
            .trim()
            .to_ascii_lowercase();
        let value = String::from_utf8_lossy(&line[colon + 1..])
            .trim()
            .to_string();
        match name.as_str() {
            "content-type" => content_type = value,
            "content-length" => {
                content_length = Some(
                    value
                        .parse()
                        .map_err(|_| TransportError::MalformedHttp("bad Content-Length".into()))?,
                );
            }
            "transfer-encoding" => {
                if value.eq_ignore_ascii_case("chunked") {
                    chunked = true;
                } else {
                    return Err(TransportError::UnsupportedEncoding(value));
                }
            }
            _ => {}
        }
    }

    let rest = &buf[body_start..];
    let (body, body_len) = if chunked {
        match decode_chunked(rest)? {
            Some((body, len)) => (body, len),
            None => return Ok(ParseOutcome::Incomplete),
        }
    } else {
        let len = content_length.unwrap_or(0);
        if rest.len() < len {
            return Ok(ParseOutcome::Incomplete);
        }
        (rest[..len].to_vec(), len)
    };

    Ok(ParseOutcome::Complete {
        response: HapResponse {
            status,
            content_type,
            body,
        },
        consumed: body_start + body_len,
    })
}

fn parse_status_code(start_line: &[u8]) -> Result<u16> {
    let mut parts = start_line.split(|&b| b == b' ');
    let _proto = parts.next();
    let code = parts
        .next()
        .ok_or_else(|| TransportError::MalformedHttp("missing status code".into()))?;
    std::str::from_utf8(code)
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| TransportError::MalformedHttp("non-numeric status code".into()))
}

/// Decode a chunked body. Returns `Ok(None)` if the terminating `0\r\n\r\n`
/// has not yet arrived.
fn decode_chunked(mut rest: &[u8]) -> Result<Option<(Vec<u8>, usize)>> {
    let mut body = Vec::new();
    let mut consumed = 0usize;
    loop {
        let Some(nl) = find_subslice(rest, b"\r\n") else {
            return Ok(None);
        };
        let size_str = std::str::from_utf8(&rest[..nl])
            .map_err(|_| TransportError::MalformedHttp("bad chunk size".into()))?
            .trim();
        let size = usize::from_str_radix(size_str, 16)
            .map_err(|_| TransportError::MalformedHttp("bad chunk size".into()))?;
        let after_size = nl + 2;
        if size == 0 {
            let end = after_size + 2;
            if rest.len() < end {
                return Ok(None);
            }
            consumed += end;
            return Ok(Some((body, consumed)));
        }
        let chunk_end = after_size + size + 2;
        if rest.len() < chunk_end {
            return Ok(None);
        }
        body.extend_from_slice(&rest[after_size..after_size + size]);
        consumed += chunk_end;
        rest = &rest[chunk_end..];
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn split_crlf(block: &[u8]) -> impl Iterator<Item = &[u8]> {
    block
        .split(|&b| b == b'\n')
        .map(|l| if let [rest @ .., b'\r'] = l { rest } else { l })
}

/// Test-only re-exports.
#[doc(hidden)]
pub mod http_test_support {
    pub use super::{encode_request, parse_response, HapResponse, ParseOutcome};
}
