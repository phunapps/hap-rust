//! The HAP secure record layer (ChaCha20-Poly1305 framing).
//!
//! After Pair Verify, every byte of the HTTP stream is carried inside record
//! frames. One plaintext block (at most [`MAX_BLOCK`] bytes) becomes:
//!
//! ```text
//! [ 2-byte LE length ][ ciphertext (= len bytes) ][ 16-byte Poly1305 tag ]
//! ```
//!
//! The 2-byte length prefix is *also* the AEAD additional authenticated data
//! (AAD). The 96-bit nonce is four zero bytes followed by a 64-bit
//! little-endian frame counter that increments once per frame, with a separate
//! counter per direction. The actual cipher comes from `hap-crypto`; this
//! module only frames and tracks counters.

use hap_crypto::aead::{chacha20poly1305_open, chacha20poly1305_seal};

use crate::error::{Result, TransportError};

/// Maximum plaintext payload of a single record frame.
pub(crate) const MAX_BLOCK: usize = 1024;
/// Length of the ChaCha20-Poly1305 authentication tag.
pub(crate) const TAG_LEN: usize = 16;
/// Length of the frame's length prefix.
pub(crate) const LEN_PREFIX: usize = 2;

/// A per-direction 64-bit frame counter that builds the 96-bit record nonce.
#[derive(Debug, Clone, Copy)]
pub struct NonceCounter(u64);

impl NonceCounter {
    /// A fresh counter starting at zero (the value for the first frame in a
    /// direction).
    #[must_use]
    pub fn new() -> Self {
        Self(0)
    }

    /// A counter pre-set to `value` (used by vector tests to reproduce a
    /// captured frame at a known counter).
    #[must_use]
    pub fn at(value: u64) -> Self {
        Self(value)
    }

    /// The current 96-bit nonce: 4 zero bytes followed by the counter as
    /// little-endian.
    fn nonce(self) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&self.0.to_le_bytes());
        n
    }

    /// Advance to the next frame's counter.
    fn advance(&mut self) {
        self.0 = self.0.wrapping_add(1);
    }
}

impl Default for NonceCounter {
    fn default() -> Self {
        Self::new()
    }
}

/// Encrypt one plaintext block into a complete on-wire frame, advancing
/// `counter` by one.
///
/// # Errors
///
/// [`TransportError::InvalidFrameLength`] if `block` exceeds [`MAX_BLOCK`] (or,
/// defensively, if the sealed AEAD reports the input length is out of range).
pub fn encrypt_frame(key: &[u8; 32], counter: &mut NonceCounter, block: &[u8]) -> Result<Vec<u8>> {
    if block.len() > MAX_BLOCK {
        return Err(TransportError::InvalidFrameLength(block.len()));
    }
    let len = u16::try_from(block.len())
        .map_err(|_| TransportError::InvalidFrameLength(block.len()))?;
    let aad = len.to_le_bytes(); // the length prefix doubles as AAD
    let nonce = counter.nonce();
    let ciphertext_and_tag = chacha20poly1305_seal(key, &nonce, &aad, block)
        .map_err(|_| TransportError::InvalidFrameLength(block.len()))?;
    counter.advance();

    let mut frame = Vec::with_capacity(LEN_PREFIX + ciphertext_and_tag.len());
    frame.extend_from_slice(&aad);
    frame.extend_from_slice(&ciphertext_and_tag);
    Ok(frame)
}

/// Try to decrypt one frame from the front of `buf`, advancing `counter` by one
/// on success.
///
/// Returns `Ok(None)` when `buf` does not yet hold a complete frame (the caller
/// should read more bytes and retry). On success returns the plaintext block.
///
/// # Errors
///
/// [`TransportError::Decrypt`] if authentication fails (tampered/replayed/wrong
/// key); [`TransportError::InvalidFrameLength`] if the declared length exceeds
/// [`MAX_BLOCK`].
pub fn decrypt_frame(
    key: &[u8; 32],
    counter: &mut NonceCounter,
    buf: &[u8],
) -> Result<Option<Vec<u8>>> {
    if buf.len() < LEN_PREFIX {
        return Ok(None);
    }
    let declared = usize::from(u16::from_le_bytes([buf[0], buf[1]]));
    if declared > MAX_BLOCK {
        return Err(TransportError::InvalidFrameLength(declared));
    }
    let total = LEN_PREFIX + declared + TAG_LEN;
    if buf.len() < total {
        return Ok(None);
    }
    let aad = &buf[..LEN_PREFIX];
    let ciphertext_and_tag = &buf[LEN_PREFIX..total];
    let nonce = counter.nonce();
    let plaintext = chacha20poly1305_open(key, &nonce, aad, ciphertext_and_tag)
        .map_err(|_| TransportError::Decrypt)?;
    counter.advance();
    Ok(Some(plaintext))
}

/// How many bytes a complete frame for a `declared`-length block occupies.
pub(crate) fn frame_len(declared: usize) -> usize {
    LEN_PREFIX + declared + TAG_LEN
}

/// Test-only re-exports.
#[doc(hidden)]
pub mod record_test_support {
    pub use super::{decrypt_frame, encrypt_frame, NonceCounter};
}
