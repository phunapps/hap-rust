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
//! Incremental. Implemented: the CoAP server, `identify`, and **Pair Verify**
//! (against a pre-provisioned pairing, via [`ReferenceAccessory::provision_controller`]).
//! Pair Setup, the secure characteristic database (read/write), and event push
//! are being added; until then `/1` returns `4.04` and `/` (post-verify) is a
//! stub.
#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use coap_lite::{CoapOption, MessageClass, MessageType, Packet, ResponseType};
use hap_crypto::ControllerKeypair;
use hap_tlv8::Tlv8Map;
use tokio::net::UdpSocket;

mod hap;
mod light;
mod pairing;
mod pdu;
mod session;

pub mod error;

pub use error::{DutError, Result};
pub use light::{LightActuator, LoggingActuator, SerialLedActuator};

use pairing::VerifyInProgress;
use session::AccessorySession;

/// CoAP resource paths (single Uri-Path segment; the root is the empty string).
const PATH_IDENTIFY: &str = "0";
const PATH_PAIR_SETUP: &str = "1";
const PATH_PAIR_VERIFY: &str = "2";
const PATH_SECURE: &str = "";

/// Receive buffer for a single CoAP datagram.
const RECV_BUF: usize = 1500;

/// The reference accessory: its identity, the paired controller, the live Pair
/// Verify / session state, and a single Lightbulb `On` characteristic.
pub struct ReferenceAccessory {
    pairing_id: String,
    keypair: ControllerKeypair,
    /// The paired controller `(id, ltpk)`, if provisioned.
    controller: Mutex<Option<(String, [u8; 32])>>,
    /// In-progress Pair Verify state (between M1 and M3).
    verify: Mutex<Option<VerifyInProgress>>,
    /// The established secure session, once Pair Verify completes.
    session: Mutex<Option<AccessorySession>>,
    /// The Lightbulb `On` characteristic value.
    on: AtomicBool,
    /// Where a written `On` value is applied (LED, log, …).
    actuator: Box<dyn LightActuator>,
}

impl ReferenceAccessory {
    /// The instance id of the Lightbulb `On` characteristic (what a controller
    /// reads and writes).
    pub const ON_IID: u16 = 9;

    /// Create a reference accessory with the given pairing id (a MAC-shaped
    /// string such as `"AA:BB:CC:DD:EE:FF"`). A fresh long-term Ed25519 identity
    /// is generated and the `On` characteristic starts off, logging writes.
    pub fn new(pairing_id: impl Into<String>) -> Self {
        Self::with_actuator(pairing_id, Box::new(LoggingActuator))
    }

    /// Create a reference accessory whose `On` writes drive `actuator`.
    pub fn with_actuator(pairing_id: impl Into<String>, actuator: Box<dyn LightActuator>) -> Self {
        let pairing_id = pairing_id.into();
        let keypair = ControllerKeypair::generate(pairing_id.clone());
        Self {
            pairing_id,
            keypair,
            controller: Mutex::new(None),
            verify: Mutex::new(None),
            session: Mutex::new(None),
            on: AtomicBool::new(false),
            actuator,
        }
    }

    /// The accessory's pairing identifier.
    pub fn pairing_id(&self) -> &str {
        &self.pairing_id
    }

    /// The current `On` value.
    pub fn is_on(&self) -> bool {
        self.on.load(Ordering::SeqCst)
    }

    /// The accessory's long-term Ed25519 public key — a controller needs this
    /// (as `AccessoryPairing::ltpk`) to run Pair Verify.
    pub fn accessory_ltpk(&self) -> [u8; 32] {
        self.keypair.ltpk()
    }

    /// Provision a paired controller (its id and long-term public key), as Pair
    /// Setup would establish. Required before Pair Verify will succeed.
    pub fn provision_controller(
        &self,
        controller_id: impl Into<String>,
        controller_ltpk: [u8; 32],
    ) {
        if let Ok(mut c) = self.controller.lock() {
            *c = Some((controller_id.into(), controller_ltpk));
        }
    }

    /// Bind a UDP CoAP server to `addr` and serve until the task is dropped.
    /// Reports the actual bound address via `on_bound` before serving.
    ///
    /// # Errors
    /// [`DutError::Io`] if the socket cannot be bound or a fatal receive occurs.
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
    /// payload.
    fn handle(&self, path: &str, payload: &[u8]) -> (ResponseType, Vec<u8>) {
        match path {
            PATH_IDENTIFY => {
                tracing::info!("identify");
                (ResponseType::Changed, Vec::new())
            }
            PATH_PAIR_VERIFY => self.pair_verify(payload),
            PATH_PAIR_SETUP => {
                tracing::debug!("pair-setup (not yet implemented)");
                (ResponseType::NotFound, Vec::new())
            }
            PATH_SECURE => self.secure_pdu(payload),
            other => {
                tracing::debug!(path = other, "unknown resource");
                (ResponseType::NotFound, Vec::new())
            }
        }
    }

    /// Drive Pair Verify: M1→M2 (fresh) or M3→M4 (using the stored M1 state).
    fn pair_verify(&self, payload: &[u8]) -> (ResponseType, Vec<u8>) {
        let state = Tlv8Map::parse(payload)
            .ok()
            .and_then(|m| m.get_u8(hap::tlv::STATE).ok().flatten());
        match state {
            Some(hap::tlv::STATE_M1) => {
                match pairing::handle_m1(&self.keypair, &self.pairing_id, payload) {
                    Ok((m2, progress)) => {
                        if let Ok(mut v) = self.verify.lock() {
                            *v = Some(progress);
                        }
                        (ResponseType::Changed, m2)
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "pair-verify M1 failed");
                        (ResponseType::BadRequest, Vec::new())
                    }
                }
            }
            Some(hap::tlv::STATE_M3) => {
                let progress = self.verify.lock().ok().and_then(|mut v| v.take());
                let controller = self.controller.lock().ok().and_then(|c| c.clone());
                let (Some(progress), Some((cid, cltpk))) = (progress, controller) else {
                    tracing::debug!("pair-verify M3 without M1 / unprovisioned controller");
                    return (ResponseType::BadRequest, Vec::new());
                };
                match pairing::handle_m3(&progress, &cid, &cltpk, payload) {
                    Ok((m4, maybe_session)) => {
                        if let Some(sess) = maybe_session {
                            if let Ok(mut s) = self.session.lock() {
                                *s = Some(sess);
                            }
                            tracing::info!("pair-verify complete — session established");
                        } else {
                            tracing::warn!("pair-verify M3 rejected (auth)");
                        }
                        (ResponseType::Changed, m4)
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "pair-verify M3 failed");
                        (ResponseType::BadRequest, Vec::new())
                    }
                }
            }
            _ => (ResponseType::BadRequest, Vec::new()),
        }
    }

    /// Handle an encrypted PDU on `/`: decrypt with the session, serve each
    /// batched characteristic request, and seal the batched response.
    fn secure_pdu(&self, payload: &[u8]) -> (ResponseType, Vec<u8>) {
        let Ok(mut guard) = self.session.lock() else {
            return (ResponseType::InternalServerError, Vec::new());
        };
        let Some(session) = guard.as_mut() else {
            tracing::debug!("secure PDU before Pair Verify");
            return (ResponseType::Unauthorized, Vec::new());
        };
        let Ok(plaintext) = session.open_request(payload) else {
            tracing::debug!("secure PDU failed to decrypt");
            return (ResponseType::Unauthorized, Vec::new());
        };
        let Ok(requests) = pdu::decode_requests(&plaintext) else {
            return (ResponseType::BadRequest, Vec::new());
        };
        let mut responses = Vec::new();
        for req in &requests {
            responses.extend_from_slice(&self.handle_char(req));
        }
        match session.seal_response(&responses) {
            Ok(sealed) => (ResponseType::Changed, sealed),
            Err(_) => (ResponseType::InternalServerError, Vec::new()),
        }
    }

    /// Serve one characteristic request against the Lightbulb `On` characteristic,
    /// returning its response PDU.
    fn handle_char(&self, req: &pdu::Request) -> Vec<u8> {
        if req.iid != Self::ON_IID {
            return pdu::encode_response(req.tid, pdu::STATUS_INVALID_INSTANCE_ID, &[]);
        }
        match req.opcode {
            pdu::OP_CHAR_READ => {
                let body = pdu::value_body(&[u8::from(self.is_on())]);
                pdu::encode_response(req.tid, pdu::STATUS_SUCCESS, &body)
            }
            pdu::OP_CHAR_WRITE => match pdu::extract_value(&req.body) {
                Ok(value) => {
                    let on = value.first().copied().unwrap_or(0) != 0;
                    self.on.store(on, Ordering::SeqCst);
                    self.actuator.set(on);
                    tracing::info!(on, "lightbulb On written");
                    pdu::encode_response(req.tid, pdu::STATUS_SUCCESS, &[])
                }
                Err(_) => pdu::encode_response(req.tid, pdu::STATUS_UNSUPPORTED, &[]),
            },
            _ => pdu::encode_response(req.tid, pdu::STATUS_UNSUPPORTED, &[]),
        }
    }
}
