//! Internal transport seam for the pairing orchestration loops.
//!
//! The loops in [`setup`](crate::setup), [`verify`](crate::verify), and
//! [`pairings`](crate::pairings) do not call `hap_transport` types directly.
//! They depend on these tiny request traits so the loops can be exercised
//! against a recorded request→response script in tests without a live socket.
//! Real impls forward to the corresponding `hap_transport` methods.

use async_trait::async_trait;

use crate::error::Result;

/// The HAP content type for every pairing TLV8 body.
pub(crate) const PAIRING_TLV8: &str = "application/pairing+tlv8";

/// A pre-secure-session connection that can POST a pairing TLV8 body.
///
/// Implemented by [`HapConnection`](hap_transport::HapConnection) for the
/// `/pair-setup` and `/pair-verify` exchanges.
#[async_trait]
pub(crate) trait PairingConn {
    /// POST `body` (content type `application/pairing+tlv8`) to `path` and
    /// return the response body bytes.
    ///
    /// # Errors
    /// Propagates any [`TransportError`](hap_transport::TransportError) from the
    /// underlying connection as [`PairingError::Transport`](crate::PairingError::Transport).
    async fn post_tlv8(&mut self, path: &str, body: &[u8]) -> Result<Vec<u8>>;
}

/// An established secure session that can issue a pairing TLV8 request.
///
/// Implemented by [`SecureSession`](hap_transport::SecureSession) for the
/// `/pairings` exchanges.
#[async_trait]
pub(crate) trait PairingSession {
    /// POST `body` (content type `application/pairing+tlv8`) to `path` over the
    /// encrypted session and return the decrypted response body bytes.
    ///
    /// HAP pairing-management (`/pairings`) uses POST, not PUT — only
    /// `/characteristics` writes are PUT.
    ///
    /// # Errors
    /// Propagates any [`TransportError`](hap_transport::TransportError) as
    /// [`PairingError::Transport`](crate::PairingError::Transport).
    async fn post_tlv8(&mut self, path: &str, body: &[u8]) -> Result<Vec<u8>>;
}

#[async_trait]
impl PairingConn for hap_transport::HapConnection {
    async fn post_tlv8(&mut self, path: &str, body: &[u8]) -> Result<Vec<u8>> {
        let resp = self.request("POST", path, PAIRING_TLV8, body).await?;
        Ok(resp.body)
    }
}

#[async_trait]
impl PairingSession for hap_transport::SecureSession {
    async fn post_tlv8(&mut self, path: &str, body: &[u8]) -> Result<Vec<u8>> {
        let resp = self.request("POST", path, PAIRING_TLV8, body).await?;
        Ok(resp.body)
    }
}
