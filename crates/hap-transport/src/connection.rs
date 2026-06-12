//! The pre-session HAP connection: plaintext HTTP/1.1 over TCP.

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use hap_crypto::SessionKeys;

use crate::error::{Result, TransportError};
use crate::http::{encode_request, parse_response, HapResponse, ParseOutcome};
use crate::session::SecureSession;

/// A TCP connection to a HAP accessory, before a secure session is established.
///
/// Used to drive the plaintext phases of pairing (`POST /pair-setup`,
/// `POST /pair-verify`). After Pair Verify yields [`SessionKeys`], call
/// [`Self::upgrade`] to wrap all further traffic in the record layer.
pub struct HapConnection {
    stream: TcpStream,
}

impl HapConnection {
    /// Open a TCP connection to `addr` (the address from a
    /// [`crate::DiscoveredAccessory`]).
    ///
    /// # Errors
    ///
    /// [`TransportError::Io`] if the connection cannot be established.
    pub async fn connect(addr: SocketAddr) -> Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        stream.set_nodelay(true)?; // HAP is request/response; avoid Nagle delays.
        Ok(Self { stream })
    }

    /// Send a plaintext HAP request and await its response.
    ///
    /// Only valid before [`Self::upgrade`]; used for the pairing endpoints.
    ///
    /// # Errors
    ///
    /// [`TransportError::Io`] on socket failure, [`TransportError::MalformedHttp`]
    /// on an unparsable response, or [`TransportError::ConnectionClosed`] if the
    /// peer closes before a full response arrives.
    pub async fn request(
        &mut self,
        method: &str,
        path: &str,
        content_type: &str,
        body: &[u8],
    ) -> Result<HapResponse> {
        let request = encode_request(method, path, content_type, body);
        self.stream.write_all(&request).await?;
        self.stream.flush().await?;

        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match parse_response(&buf)? {
                ParseOutcome::Complete { response, .. } => return Ok(response),
                ParseOutcome::Incomplete => {}
            }
            let n = self.stream.read(&mut chunk).await?;
            if n == 0 {
                return Err(TransportError::ConnectionClosed);
            }
            buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// Consume the connection and wrap it in the secure record layer using the
    /// session keys derived from Pair Verify (M3).
    ///
    /// All subsequent traffic (`GET /accessories`, `GET`/`PUT /characteristics`,
    /// `PUT /pairings`) goes through the returned [`SecureSession`], and the
    /// accessory's `EVENT/1.0` pushes are demultiplexed onto its event channel.
    #[must_use]
    pub fn upgrade(self, keys: SessionKeys) -> SecureSession {
        SecureSession::new(self.stream, keys)
    }
}
