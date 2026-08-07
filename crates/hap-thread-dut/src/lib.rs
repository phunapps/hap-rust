//! A HomeKit-over-Thread (CoAP) **reference accessory** — a device-under-test
//! for exercising HAP-over-Thread *controllers* (such as `hap-thread`).
//!
//! HAP-over-Thread is HAP PDUs carried in CoAP over UDP/IPv6. This crate is the
//! *accessory* side of that protocol: a CoAP server that answers the four HAP
//! resources — `/0` identify, `/1` Pair Setup, `/2` Pair Verify, and `/` for
//! encrypted post-verify traffic — so a controller can be driven end-to-end
//! without Apple hardware. It is a test/reference tool, not a product.
//!
//! # Status
//! Incremental. Implemented: the CoAP server transport and `identify`. Pair
//! Setup / Pair Verify (accessory side), the secure session, the characteristic
//! database, and event push are being added; until then those resources return
//! `4.04 Not Found`.
#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use coap_lite::{CoapOption, MessageClass, MessageType, Packet, ResponseType};
use tokio::net::UdpSocket;

pub mod error;

pub use error::{DutError, Result};

/// CoAP resource paths (single Uri-Path segment; the root is the empty string).
const PATH_IDENTIFY: &str = "0";
const PATH_PAIR_SETUP: &str = "1";
const PATH_PAIR_VERIFY: &str = "2";
const PATH_SECURE: &str = "";

/// Receive buffer for a single CoAP datagram.
const RECV_BUF: usize = 1500;

/// The reference accessory: its identity and (forthcoming) attribute database.
pub struct ReferenceAccessory {
    /// The accessory's pairing identifier (`AccessoryPairingID`).
    pairing_id: String,
}

impl ReferenceAccessory {
    /// Create a reference accessory with the given pairing id (a MAC-shaped
    /// string such as `"AA:BB:CC:DD:EE:FF"`).
    pub fn new(pairing_id: impl Into<String>) -> Self {
        Self {
            pairing_id: pairing_id.into(),
        }
    }

    /// The accessory's pairing identifier.
    pub fn pairing_id(&self) -> &str {
        &self.pairing_id
    }

    /// Bind a UDP CoAP server to `addr` and serve requests until the task is
    /// dropped. Returns the actual bound address via `on_bound` (useful when
    /// binding to port 0 in tests) before entering the serve loop.
    ///
    /// # Errors
    /// [`DutError::Io`] if the socket cannot be bound or a fatal receive error
    /// occurs.
    pub async fn serve<F>(self: Arc<Self>, addr: SocketAddr, on_bound: F) -> Result<()>
    where
        F: FnOnce(SocketAddr),
    {
        let socket = UdpSocket::bind(addr).await?;
        let local = socket.local_addr()?;
        tracing::info!(%local, pairing_id = %self.pairing_id, "hap-thread-dut listening");
        on_bound(local);

        let mut buf = vec![0u8; RECV_BUF];
        loop {
            let (n, peer) = socket.recv_from(&mut buf).await?;
            let req = match Packet::from_bytes(&buf[..n]) {
                Ok(p) => p,
                Err(e) => {
                    tracing::debug!(error = %e, "dropping malformed CoAP datagram");
                    continue;
                }
            };
            let path = req
                .get_first_option(CoapOption::UriPath)
                .map(|v| String::from_utf8_lossy(v).into_owned())
                .unwrap_or_default();
            let (code, payload) = self.handle(&path, &req.payload);

            let mut resp = Packet::new();
            resp.header.set_type(MessageType::Acknowledgement);
            resp.header.code = MessageClass::Response(code);
            resp.header.message_id = req.header.message_id;
            resp.set_token(req.get_token().to_vec());
            resp.payload = payload;
            match resp.to_bytes() {
                Ok(bytes) => {
                    if let Err(e) = socket.send_to(&bytes, peer).await {
                        tracing::debug!(error = %e, "failed to send CoAP response");
                    }
                }
                Err(e) => tracing::debug!(error = %e, "failed to encode CoAP response"),
            }
        }
    }

    /// Route one request to its handler, returning the CoAP response code and
    /// payload. Synchronous today (identify and the crypto handlers do no
    /// awaiting); the server loop drives it between awaited socket operations.
    fn handle(&self, path: &str, payload: &[u8]) -> (ResponseType, Vec<u8>) {
        match path {
            PATH_IDENTIFY => {
                tracing::info!("identify");
                (ResponseType::Changed, Vec::new())
            }
            PATH_PAIR_SETUP => {
                tracing::debug!(len = payload.len(), "pair-setup (not yet implemented)");
                (ResponseType::NotFound, Vec::new())
            }
            PATH_PAIR_VERIFY => {
                tracing::debug!(len = payload.len(), "pair-verify (not yet implemented)");
                (ResponseType::NotFound, Vec::new())
            }
            PATH_SECURE => {
                tracing::debug!(len = payload.len(), "secure PDU (not yet implemented)");
                (ResponseType::NotFound, Vec::new())
            }
            other => {
                tracing::debug!(path = other, "unknown resource");
                (ResponseType::NotFound, Vec::new())
            }
        }
    }
}
