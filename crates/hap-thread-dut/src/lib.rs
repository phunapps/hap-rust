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
//! Incremental. Implemented: the CoAP server, `identify`, **Pair Setup** (M1–M6
//! SRP, enabled via [`ReferenceAccessory::with_setup_code`]), **Pair Verify**
//! (also usable against a pre-provisioned pairing via
//! [`ReferenceAccessory::provision_controller`]), and Lightbulb `On`
//! read/write over the encrypted session. The full characteristic database
//! (`0x09`) and event push are not yet implemented.
#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};

use coap_lite::block_handler::BlockValue;
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

use pairing::{SetupInProgress, VerifyInProgress};
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
    /// The setup code Pair Setup authenticates against, if this accessory
    /// supports pairing (`None` leaves the `/1` resource a `4.04`).
    setup_code: Option<String>,
    /// The paired controller `(id, ltpk)`, if provisioned.
    controller: Mutex<Option<(String, [u8; 32])>>,
    /// In-progress Pair Setup state (between M1/M3/M5).
    setup: Mutex<Option<SetupInProgress>>,
    /// In-progress Pair Verify state (between M1 and M3).
    verify: Mutex<Option<VerifyInProgress>>,
    /// The established secure session, once Pair Verify completes.
    session: Mutex<Option<AccessorySession>>,
    /// The Lightbulb `On` characteristic value.
    on: AtomicBool,
    /// Where a written `On` value is applied (LED, log, …).
    actuator: Box<dyn LightActuator>,
    /// Message-id source for separately-delivered CON responses (slow mode).
    next_mid: AtomicU16,
    /// If set, answer with an empty ACK then a *separate* CON (RFC 7252 §5.2.2),
    /// exercising the controller's token correlation (F1).
    slow: bool,
    /// If set, fragment any response larger than this into Block2 blocks
    /// (RFC 7959), exercising the controller's reassembly (F2).
    blockwise: Option<usize>,
    /// The in-flight block-wise response, cached by request token so Block2
    /// continuations are served without re-processing (and, for secure reads,
    /// without re-decrypting under an advanced session nonce).
    block_cache: Mutex<Option<BlockwiseResponse>>,
}

/// A cached block-wise response awaiting further Block2 requests (F2).
struct BlockwiseResponse {
    /// The request token every block of this transfer shares.
    token: Vec<u8>,
    /// The response code all its blocks carry.
    code: ResponseType,
    /// The full response payload, sliced per Block2 request.
    payload: Vec<u8>,
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
            setup_code: None,
            controller: Mutex::new(None),
            setup: Mutex::new(None),
            verify: Mutex::new(None),
            session: Mutex::new(None),
            on: AtomicBool::new(false),
            actuator,
            next_mid: AtomicU16::new(1),
            slow: false,
            blockwise: None,
            block_cache: Mutex::new(None),
        }
    }

    /// Behave like a *slow* accessory: empty-ACK each request, then deliver the
    /// response as a separate CON (RFC 7252 §5.2.2). Exercises the controller's
    /// token-correlation path (BRINGUP F1).
    #[must_use]
    pub fn with_slow_responses(mut self) -> Self {
        self.slow = true;
        self
    }

    /// Fragment any response larger than `block_size` into Block2 blocks
    /// (RFC 7959). Exercises the controller's reassembly path (BRINGUP F2); the
    /// synthetic attribute database (see [`Self::synthetic_database`]) is sized to
    /// span several blocks.
    #[must_use]
    pub fn with_blockwise_responses(mut self, block_size: usize) -> Self {
        self.blockwise = Some(block_size.max(16));
        self
    }

    /// The synthetic attribute-database body the accessory returns for a
    /// `ReadDatabase` (`0x09`) request — a deterministic pattern, deliberately
    /// larger than a typical CoAP block so [`Self::with_blockwise_responses`] can
    /// fragment it. (The real `0x09` tree decode is deferred to a later
    /// milestone; this exists to exercise the transport.)
    #[must_use]
    pub fn synthetic_database() -> Vec<u8> {
        (0..2000u32)
            .map(|i| u8::try_from(i % 251).unwrap_or(0))
            .collect()
    }

    /// Enable Pair Setup against `setup_code` (the 8-digit code a controller
    /// pairs with, hyphenated or bare). Without this, the `/1` Pair Setup
    /// resource returns `4.04` and only a pre-[`provision`](Self::provision_controller)ed
    /// controller can Pair Verify.
    #[must_use]
    pub fn with_setup_code(mut self, setup_code: impl Into<String>) -> Self {
        self.setup_code = Some(setup_code.into());
        self
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
            // Drop empty ACKs — a controller acknowledging one of our separate
            // (slow-mode) responses; there is nothing to answer.
            if req.header.get_type() == MessageType::Acknowledgement
                && req.header.code == MessageClass::Empty
            {
                continue;
            }

            // Block-wise continuation (Block2 num > 0): serve the next fragment
            // of the cached response without re-running the request handler.
            if self.blockwise.is_some() {
                if let Some(num) = requested_block(&req) {
                    if num > 0 {
                        self.serve_cached_block(&socket, peer, &req, num).await;
                        continue;
                    }
                }
            }

            let path = req
                .get_first_option(CoapOption::UriPath)
                .map(|v| String::from_utf8_lossy(v).into_owned())
                .unwrap_or_default();
            let (code, payload) = self.handle(&path, &req.payload);
            self.send_response(&socket, peer, &req, code, payload).await;
        }
    }

    /// Send `payload` as the response to `req`, in the framing this accessory is
    /// configured for: block-wise (F2), slow/separate (F1), or a plain
    /// piggy-backed ACK.
    async fn send_response(
        &self,
        socket: &UdpSocket,
        peer: SocketAddr,
        req: &Packet,
        code: ResponseType,
        payload: Vec<u8>,
    ) {
        let token = req.get_token().to_vec();

        // Block-wise: cache the whole payload, answer block 0, let the controller
        // pull the rest with Block2 continuations.
        if let Some(bs) = self.blockwise {
            if payload.len() > bs {
                if let Ok(mut cache) = self.block_cache.lock() {
                    *cache = Some(BlockwiseResponse {
                        token: token.clone(),
                        code,
                        payload: payload.clone(),
                    });
                }
                self.send_block(
                    socket,
                    peer,
                    req.header.message_id,
                    &token,
                    code,
                    &payload,
                    0,
                    bs,
                )
                .await;
                return;
            }
        }

        if self.slow {
            // Empty ACK now; the real answer follows as a separate CON that
            // reuses the request token (RFC 7252 §5.2.2).
            self.send_empty_ack(socket, peer, req.header.message_id)
                .await;
            let mut con = Packet::new();
            con.header.set_type(MessageType::Confirmable);
            con.header.code = MessageClass::Response(code);
            con.header.message_id = self.next_mid.fetch_add(1, Ordering::Relaxed);
            con.set_token(token);
            con.payload = payload;
            self.send_packet(socket, peer, &con).await;
            return;
        }

        // Default: a piggy-backed ACK.
        let mut ack = Packet::new();
        ack.header.set_type(MessageType::Acknowledgement);
        ack.header.code = MessageClass::Response(code);
        ack.header.message_id = req.header.message_id;
        ack.set_token(token);
        ack.payload = payload;
        self.send_packet(socket, peer, &ack).await;
    }

    /// Serve Block2 fragment `num` of the cached block-wise response (if its token
    /// matches the request).
    async fn serve_cached_block(
        &self,
        socket: &UdpSocket,
        peer: SocketAddr,
        req: &Packet,
        num: u16,
    ) {
        let Some(bs) = self.blockwise else { return };
        let token = req.get_token().to_vec();
        let cached = self.block_cache.lock().ok().and_then(|c| {
            c.as_ref()
                .filter(|b| b.token == token)
                .map(|b| (b.code, b.payload.clone()))
        });
        let Some((code, payload)) = cached else {
            tracing::debug!("Block2 continuation with no matching cached response");
            return;
        };
        self.send_block(
            socket,
            peer,
            req.header.message_id,
            &token,
            code,
            &payload,
            usize::from(num),
            bs,
        )
        .await;
    }

    /// Send Block2 fragment `num` (block size `bs`) of `full` as a piggy-backed
    /// ACK, setting the more-bit and clearing the cache after the last fragment.
    #[allow(clippy::too_many_arguments)]
    async fn send_block(
        &self,
        socket: &UdpSocket,
        peer: SocketAddr,
        message_id: u16,
        token: &[u8],
        code: ResponseType,
        full: &[u8],
        num: usize,
        bs: usize,
    ) {
        let start = num.saturating_mul(bs).min(full.len());
        let end = start.saturating_add(bs).min(full.len());
        let more = end < full.len();

        let mut resp = Packet::new();
        resp.header.set_type(MessageType::Acknowledgement);
        resp.header.code = MessageClass::Response(code);
        resp.header.message_id = message_id;
        resp.set_token(token.to_vec());
        if let Ok(bv) = BlockValue::new(num, more, bs) {
            resp.add_option_as(CoapOption::Block2, bv);
        }
        resp.payload = full[start..end].to_vec();
        self.send_packet(socket, peer, &resp).await;

        if !more {
            if let Ok(mut cache) = self.block_cache.lock() {
                *cache = None;
            }
        }
    }

    /// Send an empty ACK (`0.00`) echoing `message_id`.
    async fn send_empty_ack(&self, socket: &UdpSocket, peer: SocketAddr, message_id: u16) {
        let mut ack = Packet::new();
        ack.header.set_type(MessageType::Acknowledgement);
        ack.header.code = MessageClass::Empty;
        ack.header.message_id = message_id;
        self.send_packet(socket, peer, &ack).await;
    }

    /// Encode and send one CoAP packet, logging (not failing) on error.
    async fn send_packet(&self, socket: &UdpSocket, peer: SocketAddr, packet: &Packet) {
        match packet.to_bytes() {
            Ok(bytes) => {
                if let Err(e) = socket.send_to(&bytes, peer).await {
                    tracing::debug!(error = %e, "failed to send CoAP response");
                }
            }
            Err(e) => tracing::debug!(error = %e, "failed to encode CoAP response"),
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
            PATH_PAIR_SETUP => self.pair_setup(payload),
            PATH_SECURE => self.secure_pdu(payload),
            other => {
                tracing::debug!(path = other, "unknown resource");
                (ResponseType::NotFound, Vec::new())
            }
        }
    }

    /// Drive Pair Setup: M1→M2 (SRP start), M3→M4 (SRP verify), or M5→M6 (the
    /// long-term key exchange that provisions the controller as a pairing).
    fn pair_setup(&self, payload: &[u8]) -> (ResponseType, Vec<u8>) {
        let Some(setup_code) = self.setup_code.as_deref() else {
            tracing::debug!("pair-setup requested but no setup code configured");
            return (ResponseType::NotFound, Vec::new());
        };
        let state = Tlv8Map::parse(payload)
            .ok()
            .and_then(|m| m.get_u8(hap::tlv::STATE).ok().flatten());
        match state {
            Some(hap::tlv::STATE_M1) => match pairing::handle_setup_m1(setup_code, payload) {
                Ok((m2, progress)) => {
                    if let Ok(mut s) = self.setup.lock() {
                        *s = Some(progress);
                    }
                    (ResponseType::Changed, m2)
                }
                Err(e) => {
                    tracing::debug!(error = %e, "pair-setup M1 failed");
                    (ResponseType::BadRequest, Vec::new())
                }
            },
            Some(hap::tlv::STATE_M3) => {
                let progress = self.setup.lock().ok().and_then(|mut s| s.take());
                let Some(SetupInProgress::AwaitingM3 { server }) = progress else {
                    tracing::debug!("pair-setup M3 without a pending M1");
                    return (ResponseType::BadRequest, Vec::new());
                };
                match pairing::handle_setup_m3(&server, payload) {
                    Ok((m4, Some(session_key))) => {
                        if let Ok(mut s) = self.setup.lock() {
                            *s = Some(SetupInProgress::AwaitingM5 { session_key });
                        }
                        (ResponseType::Changed, m4)
                    }
                    Ok((m4, None)) => {
                        tracing::warn!("pair-setup M3 rejected (wrong setup code)");
                        (ResponseType::Changed, m4)
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "pair-setup M3 failed");
                        (ResponseType::BadRequest, Vec::new())
                    }
                }
            }
            Some(hap::tlv::STATE_M5) => {
                let progress = self.setup.lock().ok().and_then(|mut s| s.take());
                let Some(SetupInProgress::AwaitingM5 { session_key }) = progress else {
                    tracing::debug!("pair-setup M5 without a completed M3");
                    return (ResponseType::BadRequest, Vec::new());
                };
                match pairing::handle_setup_m5(
                    &session_key,
                    &self.keypair,
                    &self.pairing_id,
                    payload,
                ) {
                    Ok((m6, Some((cid, cltpk)))) => {
                        self.provision_controller(cid, cltpk);
                        tracing::info!("pair-setup complete — controller provisioned");
                        (ResponseType::Changed, m6)
                    }
                    Ok((m6, None)) => {
                        tracing::warn!("pair-setup M5 rejected (auth)");
                        (ResponseType::Changed, m6)
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "pair-setup M5 failed");
                        (ResponseType::BadRequest, Vec::new())
                    }
                }
            }
            _ => (ResponseType::BadRequest, Vec::new()),
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
        // ReadDatabase (`0x09`) is a global op (iid 0): return the synthetic
        // attribute database, which block-wise mode fragments over Block2.
        if req.opcode == pdu::OP_READ_DATABASE {
            return pdu::encode_response(req.tid, pdu::STATUS_SUCCESS, &Self::synthetic_database());
        }
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

/// The Block2 block number a request is asking for, if it carries a Block2
/// option (RFC 7959).
fn requested_block(req: &Packet) -> Option<u16> {
    req.get_first_option_as::<BlockValue>(CoapOption::Block2)
        .and_then(std::result::Result::ok)
        .map(|b| b.num)
}
