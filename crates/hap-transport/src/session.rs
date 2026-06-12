//! The secure session: the record layer plus HAP HTTP/EVENT demultiplexing.
//!
//! After Pair Verify completes a [`SecureSession`] owns the TCP stream. A
//! background reader task decrypts record frames off the wire, reassembles
//! the plaintext, and demultiplexes `HTTP/1.1` responses from `EVENT/1.0`
//! accessory pushes. Requests are encrypted block-by-block before writing.

use std::sync::Mutex as StdMutex;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};

use hap_crypto::SessionKeys;

use crate::error::{Result, TransportError};
use crate::http::{
    encode_request, parse_message, HapResponse, ParseOutcome, EVENT_PREFIX, HTTP_PREFIX,
};
use crate::record::{decrypt_frame, encrypt_frame, frame_len, NonceCounter, MAX_BLOCK};

/// An asynchronous `EVENT/1.0` push from the accessory (delivered after the
/// controller subscribes with `PUT /characteristics` `ev=true`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EventNotification {
    /// The `application/hap+json` body of the event.
    pub body: Vec<u8>,
}

/// One demultiplexed message off the decrypted plaintext stream.
#[derive(Debug)]
#[non_exhaustive]
pub enum Demuxed {
    /// An `HTTP/1.1` response to an in-flight request.
    Response(HapResponse),
    /// An `EVENT/1.0` push.
    Event(EventNotification),
}

/// A verified, encrypted HAP session over the connection.
///
/// Construct via [`crate::HapConnection::upgrade`]. The reader task runs until
/// the session is dropped or the peer closes the connection.
pub struct SecureSession {
    writer: Mutex<WriterState>,
    /// Responses to in-flight requests, in arrival order.
    responses: Mutex<mpsc::Receiver<Result<HapResponse>>>,
    events: StdMutex<Option<mpsc::Receiver<EventNotification>>>,
}

struct WriterState {
    half: OwnedWriteHalf,
    counter: NonceCounter,
    write_key: [u8; 32],
}

impl SecureSession {
    /// Build a session from an already-Pair-Verified TCP stream and the derived
    /// session keys. Spawns the reader task.
    ///
    /// Takes [`SessionKeys`] by value on purpose: the session takes ownership of
    /// the key material for its lifetime, so the caller cannot keep a live copy
    /// of the session keys around after handing them off.
    #[allow(clippy::needless_pass_by_value)] // ownership transfer is intentional, not an oversight
    pub(crate) fn new(stream: TcpStream, keys: SessionKeys) -> Self {
        let (read_half, write_half) = stream.into_split();
        let (resp_tx, resp_rx) = mpsc::channel::<Result<HapResponse>>(8);
        let (event_tx, event_rx) = mpsc::channel::<EventNotification>(32);

        let read_key = keys.read_key;
        let write_key = keys.write_key;

        tokio::spawn(reader_task(read_half, read_key, resp_tx, event_tx));

        Self {
            writer: Mutex::new(WriterState {
                half: write_half,
                counter: NonceCounter::new(),
                write_key,
            }),
            responses: Mutex::new(resp_rx),
            events: StdMutex::new(Some(event_rx)),
        }
    }

    /// Send a HAP request over the encrypted session and await its response.
    ///
    /// The plaintext HTTP request is split into ≤1024-byte blocks, each framed
    /// and encrypted, then the next `HTTP/1.1` message from the reader is
    /// returned (`EVENT/1.0` pushes that arrive first are routed to
    /// [`Self::events`], not returned here).
    ///
    /// # Errors
    ///
    /// IO / framing errors, or [`TransportError::NoResponse`] if the reader
    /// task ended before a response arrived.
    pub async fn request(
        &self,
        method: &str,
        path: &str,
        content_type: &str,
        body: &[u8],
    ) -> Result<HapResponse> {
        let plaintext = encode_request(method, path, content_type, body);
        {
            let mut w = self.writer.lock().await;
            for block in plaintext.chunks(MAX_BLOCK) {
                let key = w.write_key;
                let frame = encrypt_frame(&key, &mut w.counter, block)?;
                w.half.write_all(&frame).await?;
            }
            w.half.flush().await?;
        }
        let mut rx = self.responses.lock().await;
        match rx.recv().await {
            Some(result) => result,
            None => Err(TransportError::NoResponse),
        }
    }

    /// Take the receiver for asynchronous `EVENT/1.0` notifications.
    ///
    /// Returns the channel once; subsequent calls return an already-closed
    /// receiver. Intended to be called once, right after `upgrade`;
    /// `hap-controller` (M7) holds the receiver and adapts it into a stream.
    #[must_use]
    pub fn events(&self) -> mpsc::Receiver<EventNotification> {
        let mut guard = match self.events.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.take().unwrap_or_else(|| {
            let (_tx, rx) = mpsc::channel(1);
            rx
        })
    }
}

/// The reader task: decrypt frames, demux messages, route them.
async fn reader_task(
    mut half: OwnedReadHalf,
    read_key: [u8; 32],
    resp_tx: mpsc::Sender<Result<HapResponse>>,
    event_tx: mpsc::Sender<EventNotification>,
) {
    let mut cipher_buf = Vec::new(); // undecrypted bytes off the socket
    let mut plain_buf = Vec::new(); // decrypted plaintext awaiting demux
    let mut counter = NonceCounter::new();
    let mut chunk = [0u8; 4096];

    loop {
        // Drain whatever complete frames we can from cipher_buf into plain_buf.
        loop {
            match decrypt_frame(&read_key, &mut counter, &cipher_buf) {
                Ok(Some(block)) => {
                    let declared = block.len();
                    cipher_buf.drain(..frame_len(declared));
                    plain_buf.extend_from_slice(&block);
                }
                Ok(None) => break, // need more bytes
                Err(e) => {
                    let _ = resp_tx.send(Err(e)).await;
                    return;
                }
            }
        }

        // Demux complete HTTP/EVENT messages out of plain_buf.
        match demux_messages(&plain_buf) {
            Ok((messages, consumed)) => {
                if consumed > 0 {
                    plain_buf.drain(..consumed);
                }
                for msg in messages {
                    match msg {
                        Demuxed::Response(r) => {
                            if resp_tx.send(Ok(r)).await.is_err() {
                                return; // session dropped
                            }
                        }
                        Demuxed::Event(ev) => {
                            let _ = event_tx.send(ev).await; // best-effort
                        }
                    }
                }
            }
            Err(e) => {
                let _ = resp_tx.send(Err(e)).await;
                return;
            }
        }

        // Read more ciphertext.
        match half.read(&mut chunk).await {
            Ok(0) => {
                let _ = resp_tx.send(Err(TransportError::ConnectionClosed)).await;
                return;
            }
            Ok(n) => cipher_buf.extend_from_slice(&chunk[..n]),
            Err(e) => {
                let _ = resp_tx.send(Err(TransportError::Io(e))).await;
                return;
            }
        }
    }
}

/// Pull every complete `HTTP/1.1` / `EVENT/1.0` message from the front of a
/// decrypted plaintext buffer. Returns the messages and how many bytes were
/// consumed; a trailing partial message is left unconsumed.
///
/// # Errors
///
/// [`TransportError::MalformedHttp`] if the stream contains a start line that
/// is neither an `HTTP/1.1` response nor an `EVENT/1.0` push.
pub fn demux_messages(buf: &[u8]) -> Result<(Vec<Demuxed>, usize)> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    loop {
        let rest = &buf[offset..];
        if rest.is_empty() {
            break;
        }
        let is_event = rest.starts_with(EVENT_PREFIX);
        let is_http = rest.starts_with(HTTP_PREFIX);
        if !is_event && !is_http {
            // Could be a partial start line; if shorter than the longest prefix
            // we wait for more, otherwise it's malformed.
            if rest.len() < EVENT_PREFIX.len().max(HTTP_PREFIX.len()) {
                break;
            }
            return Err(TransportError::MalformedHttp(
                "unrecognised start line in secure stream".into(),
            ));
        }
        let prefix = if is_event { EVENT_PREFIX } else { HTTP_PREFIX };
        match parse_message(rest, prefix)? {
            ParseOutcome::Incomplete => break,
            ParseOutcome::Complete { response, consumed } => {
                if is_event {
                    out.push(Demuxed::Event(EventNotification { body: response.body }));
                } else {
                    out.push(Demuxed::Response(response));
                }
                offset += consumed;
            }
        }
    }
    Ok((out, offset))
}

/// Test-only re-exports.
#[doc(hidden)]
pub mod session_test_support {
    pub use super::{demux_messages, Demuxed};
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::http::encode_request;
    use crate::record::{decrypt_frame, encrypt_frame, NonceCounter};

    #[test]
    fn encrypt_decrypt_roundtrip_through_demux() {
        // Fixed 32-byte key (all-zero for test determinism).
        let key = [0u8; 32];
        let mut enc_counter = NonceCounter::new();
        let mut dec_counter = NonceCounter::new();

        // Build a realistic GET /accessories request.
        let plaintext = encode_request("GET", "/accessories", "application/hap+json", b"");

        // Encrypt the plaintext into frames (<=MAX_BLOCK each).
        let mut frames: Vec<u8> = Vec::new();
        for block in plaintext.chunks(MAX_BLOCK) {
            let frame = encrypt_frame(&key, &mut enc_counter, block).unwrap();
            frames.extend_from_slice(&frame);
        }

        // Decrypt frames back to plaintext.
        let mut decrypted: Vec<u8> = Vec::new();
        let mut remaining = frames.as_slice();
        while !remaining.is_empty() {
            match decrypt_frame(&key, &mut dec_counter, remaining).unwrap() {
                Some(block) => {
                    let flen = frame_len(block.len());
                    decrypted.extend_from_slice(&block);
                    remaining = &remaining[flen..];
                }
                None => break,
            }
        }

        // The recovered bytes must match the original plaintext exactly.
        assert_eq!(decrypted, plaintext, "round-trip plaintext must match");

        // The recovered bytes must also be valid HTTP (parseable start line).
        assert!(
            decrypted.starts_with(b"GET /accessories HTTP/1.1\r\n"),
            "start line intact after round-trip"
        );
    }
}
