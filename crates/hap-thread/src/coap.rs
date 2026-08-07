//! CoAP transport binding: POST HAP payloads to an accessory's CoAP resources.
//!
//! HAP-over-Thread uses four CoAP resources, all POST: `/0` identify, `/1`
//! pair-setup, `/2` pair-verify, and `/` (the root) for every encrypted
//! post-verify PDU. The [`CoapTransport`] trait abstracts a single
//! request/response so the pairing and session layers are testable without a
//! socket; [`UdpCoapTransport`] is the real UDP/IPv6 implementation and
//! [`MockCoapTransport`] a queue-driven test double.
//!
//! The response *code* is returned alongside the payload because it is
//! load-bearing: `2.04 Changed` is success and `4.04 Not Found` means the
//! accessory dropped the session and the caller must re-run Pair Verify.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use coap_lite::block_handler::BlockValue;
use coap_lite::{CoapOption, MessageClass, MessageType, Packet, RequestType};
use tokio::net::UdpSocket;

use crate::error::{Result, ThreadError};

/// CoAP resource paths (single Uri-Path segment; the root is the empty string).
pub(crate) const PATH_IDENTIFY: &str = "0";
pub(crate) const PATH_PAIR_SETUP: &str = "1";
pub(crate) const PATH_PAIR_VERIFY: &str = "2";
pub(crate) const PATH_SECURE: &str = "";

/// Per-attempt wait for a Confirmable POST's acknowledgement before retrying.
const ACK_TIMEOUT: Duration = Duration::from_secs(2);
/// After an *empty* ACK, how long to wait for the accessory's separate response
/// (RFC 7252 §5.2.2) before giving up. The CON is not retransmitted meanwhile.
const SEPARATE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum Confirmable transmissions before giving up (RFC 7252 default is 4).
const MAX_TRANSMISSIONS: u32 = 4;
/// Safety cap on Block2 fragments reassembled for one response (RFC 7959), so a
/// misbehaving accessory cannot drive an unbounded request loop.
const MAX_BLOCKS: u32 = 1024;
/// Receive buffer for a single CoAP datagram. Sized for one Block2 block plus
/// CoAP framing; large responses arrive block-wise (RFC 7959), not in one datagram.
const RECV_BUF: usize = 1500;

/// A CoAP response: the two-part code (`class.detail`, e.g. `2.04`) and payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CoapResponse {
    /// `(class, detail)` — `(2, 4)` = Changed (success), `(4, 4)` = Not Found.
    pub code: (u8, u8),
    /// The raw response payload (a HAP PDU or TLV8, decrypted by higher layers).
    pub payload: Vec<u8>,
}

impl CoapResponse {
    /// Whether the code is `2.04 Changed` (the HAP success code).
    pub(crate) fn is_changed(&self) -> bool {
        self.code == (2, 4)
    }

    /// Whether the code is `4.04 Not Found` (session/accessory gone).
    pub(crate) fn is_not_found(&self) -> bool {
        self.code == (4, 4)
    }

    /// Return the payload if the code is `2.04 Changed`, else the appropriate
    /// error ([`ThreadError::SessionExpired`] on `4.04`, otherwise
    /// [`ThreadError::CoapCode`]).
    ///
    /// # Errors
    /// See above.
    pub(crate) fn changed_payload(self) -> Result<Vec<u8>> {
        if self.is_changed() {
            Ok(self.payload)
        } else if self.is_not_found() {
            Err(ThreadError::SessionExpired)
        } else {
            Err(ThreadError::CoapCode(format!(
                "{}.{:02}",
                self.code.0, self.code.1
            )))
        }
    }
}

/// A single CoAP request/response seam. Implementations POST `payload` to the
/// resource `path` (one of `"0"`, `"1"`, `"2"`, or `""` for the root) and return
/// the accessory's response.
#[async_trait]
pub(crate) trait CoapTransport: Send + Sync {
    /// POST `payload` to `path` and await the response.
    ///
    /// # Errors
    /// Transport, timeout, or malformed-response failures.
    async fn post(&self, path: &str, payload: &[u8]) -> Result<CoapResponse>;
}

/// A real CoAP client over a connected UDP/IPv6 socket.
///
/// Performs Confirmable exchanges correlated by **token** (RFC 7252), so it
/// tolerates the two things a real accessory does that a fast one does not:
/// *separate responses* — an empty ACK followed by a later CON carrying the
/// payload (§5.2.2) — and *block-wise transfer* — a large response delivered as
/// Block2 fragments (RFC 7959), reassembled here before it is handed up.
pub(crate) struct UdpCoapTransport {
    socket: UdpSocket,
    message_id: AtomicU16,
}

impl UdpCoapTransport {
    /// Connect a UDP socket to the accessory's `[ipv6]:port`.
    ///
    /// # Errors
    /// [`ThreadError::Io`] if the socket cannot be bound or connected.
    pub(crate) async fn connect(addr: SocketAddr) -> Result<Self> {
        // Bind an ephemeral local endpoint of the same family as the target.
        let bind: SocketAddr = if addr.is_ipv6() {
            "[::]:0".parse().map_err(|_| {
                ThreadError::Coap("could not parse the IPv6 wildcard bind address".into())
            })?
        } else {
            "0.0.0.0:0".parse().map_err(|_| {
                ThreadError::Coap("could not parse the IPv4 wildcard bind address".into())
            })?
        };
        let socket = UdpSocket::bind(bind).await?;
        socket.connect(addr).await?;
        Ok(Self {
            socket,
            message_id: AtomicU16::new(1),
        })
    }

    fn next_message_id(&self) -> u16 {
        self.message_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Frame a Confirmable POST to `path` with a fresh message-id but the given
    /// `token`. All block-wise requests of one transfer share a token so the
    /// accessory can correlate them (RFC 7959 §2.4); the message-id still changes
    /// per datagram.
    fn frame(&self, path: &str, payload: &[u8], token: &[u8]) -> Packet {
        let mut packet = Packet::new();
        packet.header.set_type(MessageType::Confirmable);
        packet.header.code = MessageClass::Request(RequestType::Post);
        packet.header.message_id = self.next_message_id();
        packet.set_token(token.to_vec());
        // HAP uses single-segment resource paths; the root ("") carries no
        // Uri-Path option.
        if !path.is_empty() {
            packet.add_option(CoapOption::UriPath, path.as_bytes().to_vec());
        }
        packet.payload = payload.to_vec();
        packet
    }

    /// Build the first Confirmable POST to `path`, returning it and a fresh token
    /// to correlate the whole (possibly block-wise) exchange.
    fn build_post(&self, path: &str, payload: &[u8]) -> (Packet, Vec<u8>) {
        let token = self.next_message_id().to_be_bytes().to_vec();
        let packet = self.frame(path, payload, &token);
        (packet, token)
    }

    /// Send an empty ACK (`0.00`) for a separately-delivered CON response.
    async fn send_empty_ack(&self, message_id: u16) -> Result<()> {
        let mut ack = Packet::new();
        ack.header.set_type(MessageType::Acknowledgement);
        ack.header.code = MessageClass::Empty;
        ack.header.message_id = message_id;
        let bytes = ack
            .to_bytes()
            .map_err(|e| ThreadError::Coap(format!("could not encode CoAP ACK: {e}")))?;
        self.socket.send(&bytes).await?;
        Ok(())
    }

    /// Perform one Confirmable request/response exchange, correlating strictly by
    /// `token`.
    ///
    /// Retransmits the CON up to [`MAX_TRANSMISSIONS`] until it is answered. An
    /// *empty* ACK (RFC 7252 §5.2.2) means the accessory will answer later with a
    /// **separate** CON carrying the same token: retransmission stops and this
    /// waits [`SEPARATE_RESPONSE_TIMEOUT`] for that CON, then ACKs it. Matching on
    /// the token (not the message-id) also discards a stray/duplicate response
    /// left over from an earlier exchange. Returns the decoded response packet.
    async fn exchange(&self, request: &Packet, token: &[u8]) -> Result<Packet> {
        let bytes = request
            .to_bytes()
            .map_err(|e| ThreadError::Coap(format!("could not encode CoAP request: {e}")))?;
        let mut buf = vec![0u8; RECV_BUF];

        let mut acknowledged = false;
        'transmit: for _ in 0..MAX_TRANSMISSIONS {
            self.socket.send(&bytes).await?;
            loop {
                match tokio::time::timeout(ACK_TIMEOUT, self.socket.recv(&mut buf)).await {
                    Ok(Ok(n)) => {
                        let resp = decode(&buf[..n])?;
                        if resp.get_token() != token {
                            continue; // not ours — a late/stray packet
                        }
                        if is_empty(&resp) {
                            acknowledged = true; // a separate response is coming
                            break 'transmit;
                        }
                        return self.accept(resp).await;
                    }
                    Ok(Err(e)) => return Err(ThreadError::Io(e)),
                    Err(_elapsed) => break, // ack timeout — retransmit
                }
            }
        }

        if !acknowledged {
            return Err(ThreadError::Coap(
                "no CoAP response after maximum retransmissions".into(),
            ));
        }

        // Empty-ACKed: await the separate response without retransmitting.
        loop {
            match tokio::time::timeout(SEPARATE_RESPONSE_TIMEOUT, self.socket.recv(&mut buf)).await
            {
                Ok(Ok(n)) => {
                    let resp = decode(&buf[..n])?;
                    if resp.get_token() != token || is_empty(&resp) {
                        continue; // duplicate empty ACK or an unrelated packet
                    }
                    return self.accept(resp).await;
                }
                Ok(Err(e)) => return Err(ThreadError::Io(e)),
                Err(_elapsed) => {
                    return Err(ThreadError::Coap(
                        "no separate CoAP response after the empty ACK".into(),
                    ))
                }
            }
        }
    }

    /// Accept a token-matched response: ACK it if it arrived as its own CON
    /// (a separate response), then hand the packet back.
    async fn accept(&self, resp: Packet) -> Result<Packet> {
        if resp.header.get_type() == MessageType::Confirmable {
            self.send_empty_ack(resp.header.message_id).await?;
        }
        Ok(resp)
    }
}

/// Decode a CoAP datagram, mapping a parse failure to [`ThreadError::Coap`].
fn decode(bytes: &[u8]) -> Result<Packet> {
    Packet::from_bytes(bytes)
        .map_err(|e| ThreadError::Coap(format!("could not decode CoAP response: {e}")))
}

/// Whether a packet carries the empty code `0.00` (an ACK-only, no payload).
fn is_empty(packet: &Packet) -> bool {
    packet.header.code == MessageClass::Empty
}

/// Split `(class, detail)` out of a CoAP response code byte (`class<<5|detail`).
fn split_code(packet: &Packet) -> (u8, u8) {
    let code_byte = u8::from(packet.header.code);
    (code_byte >> 5, code_byte & 0x1f)
}

/// The parsed Block2 option of a response, if present and well-formed.
fn block2_of(packet: &Packet) -> Option<BlockValue> {
    packet
        .get_first_option_as::<BlockValue>(CoapOption::Block2)
        .and_then(std::result::Result::ok)
}

#[async_trait]
impl CoapTransport for UdpCoapTransport {
    async fn post(&self, path: &str, payload: &[u8]) -> Result<CoapResponse> {
        let (request, token) = self.build_post(path, payload);
        let resp = self.exchange(&request, &token).await?;
        let mut code = split_code(&resp);

        // Fast path: the response is not block-wise.
        let Some(mut block) = block2_of(&resp) else {
            return Ok(CoapResponse {
                code,
                payload: resp.payload,
            });
        };

        // Block-wise response (RFC 7959): re-POST the same request with a Block2
        // option naming the next block until the accessory clears the more-bit,
        // concatenating the fragment payloads in order.
        let mut full = resp.payload;
        let block_size = block.size();
        let mut fetched = 1u32;
        while block.more {
            if fetched >= MAX_BLOCKS {
                return Err(ThreadError::Coap(
                    "too many Block2 fragments in one response".into(),
                ));
            }
            let next_num = usize::from(block.num) + 1;
            let request_block2 = BlockValue::new(next_num, false, block_size)
                .map_err(|e| ThreadError::Coap(format!("invalid Block2 request: {e}")))?;
            let mut req = self.frame(path, payload, &token);
            req.add_option_as(CoapOption::Block2, request_block2);

            let r = self.exchange(&req, &token).await?;
            code = split_code(&r);
            full.extend_from_slice(&r.payload);
            fetched += 1;
            match block2_of(&r) {
                Some(next) => block = next,
                None => break, // accessory stopped chunking — take what arrived
            }
        }
        Ok(CoapResponse {
            code,
            payload: full,
        })
    }
}

/// A queue-driven [`CoapTransport`] test double: pre-load the responses the
/// accessory would return, drive a flow, then inspect the recorded requests.
#[cfg(any(test, feature = "test-support"))]
pub(crate) struct MockCoapTransport {
    responses: std::sync::Mutex<std::collections::VecDeque<CoapResponse>>,
    requests: std::sync::Mutex<Vec<(String, Vec<u8>)>>,
}

#[cfg(any(test, feature = "test-support"))]
impl MockCoapTransport {
    /// A mock with no queued responses.
    pub(crate) fn new() -> Self {
        Self {
            responses: std::sync::Mutex::new(std::collections::VecDeque::new()),
            requests: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Queue a `2.04 Changed` response carrying `payload`.
    pub(crate) fn queue_changed(&self, payload: Vec<u8>) {
        self.queue(CoapResponse {
            code: (2, 4),
            payload,
        });
    }

    /// Queue an arbitrary response.
    pub(crate) fn queue(&self, resp: CoapResponse) {
        // A poisoned mutex in test scaffolding is not a recoverable condition.
        if let Ok(mut q) = self.responses.lock() {
            q.push_back(resp);
        }
    }

    /// The `(path, payload)` of every request posted so far, in order.
    pub(crate) fn requests(&self) -> Vec<(String, Vec<u8>)> {
        self.requests.lock().map(|r| r.clone()).unwrap_or_default()
    }
}

#[cfg(any(test, feature = "test-support"))]
#[async_trait]
impl CoapTransport for MockCoapTransport {
    async fn post(&self, path: &str, payload: &[u8]) -> Result<CoapResponse> {
        if let Ok(mut r) = self.requests.lock() {
            r.push((path.to_string(), payload.to_vec()));
        }
        self.responses
            .lock()
            .ok()
            .and_then(|mut q| q.pop_front())
            .ok_or_else(|| ThreadError::Coap("mock: no queued response".into()))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use coap_lite::ResponseType;
    use tokio::net::UdpSocket;

    /// Build an empty CoAP ACK (`0.00`) echoing `message_id`, carrying no token.
    fn empty_ack(message_id: u16) -> Vec<u8> {
        let mut ack = Packet::new();
        ack.header.set_type(MessageType::Acknowledgement);
        ack.header.code = MessageClass::Empty;
        ack.header.message_id = message_id;
        ack.to_bytes().unwrap()
    }

    #[tokio::test]
    async fn post_handles_empty_ack_then_separate_response() {
        // A slow accessory: empty-ACK the request, then deliver the real response
        // as a *separate* CON with a fresh message-id but the SAME token.
        let responder = UdpSocket::bind("[::1]:0").await.unwrap();
        let responder_addr = responder.local_addr().unwrap();

        let task = tokio::spawn(async move {
            let mut buf = vec![0u8; 1500];
            let (n, peer) = responder.recv_from(&mut buf).await.unwrap();
            let req = Packet::from_bytes(&buf[..n]).unwrap();
            let token = req.get_token().to_vec();

            // 1) empty ACK (same message-id, no token).
            responder
                .send_to(&empty_ack(req.header.message_id), peer)
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;

            // 2) separate CON: new message-id, same token, 2.04 + payload.
            let mut con = Packet::new();
            con.header.set_type(MessageType::Confirmable);
            con.header.code = MessageClass::Response(ResponseType::Changed);
            con.header.message_id = req.header.message_id.wrapping_add(4242);
            con.set_token(token);
            con.payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
            responder
                .send_to(&con.to_bytes().unwrap(), peer)
                .await
                .unwrap();

            // 3) the client must ACK that separate CON (empty ACK, its mid).
            let (n2, _) = responder.recv_from(&mut buf).await.unwrap();
            let cack = Packet::from_bytes(&buf[..n2]).unwrap();
            (
                cack.header.get_type(),
                cack.header.message_id,
                u8::from(cack.header.code),
                con.header.message_id,
            )
        });

        let transport = UdpCoapTransport::connect(responder_addr).await.unwrap();
        let resp = transport.post(PATH_IDENTIFY, &[0x01]).await.unwrap();
        assert_eq!(resp.code, (2, 4));
        assert_eq!(resp.payload, vec![0xDE, 0xAD, 0xBE, 0xEF]);

        let (ack_type, ack_mid, ack_code, con_mid) = task.await.unwrap();
        assert_eq!(ack_type, MessageType::Acknowledgement);
        assert_eq!(ack_code, 0, "client must *empty*-ACK the separate CON");
        assert_eq!(ack_mid, con_mid, "the ACK must echo the separate CON's mid");
    }

    #[tokio::test]
    async fn post_reassembles_block2_response() {
        use coap_lite::block_handler::BlockValue;

        // A large response the accessory delivers as Block2 fragments (RFC 7959).
        let total: Vec<u8> = (0..700u32)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        let block_size = 256usize;
        let responder = UdpSocket::bind("[::1]:0").await.unwrap();
        let responder_addr = responder.local_addr().unwrap();
        let expected = total.clone();

        let task = tokio::spawn(async move {
            let mut buf = vec![0u8; 1500];
            let mut blocks_served = 0u32;
            loop {
                let (n, peer) = responder.recv_from(&mut buf).await.unwrap();
                let req = Packet::from_bytes(&buf[..n]).unwrap();
                // Which block the client is asking for (0 when no Block2 option).
                let num = req
                    .get_first_option_as::<BlockValue>(CoapOption::Block2)
                    .and_then(std::result::Result::ok)
                    .map_or(0usize, |b| b.num as usize);
                blocks_served += 1;
                let start = num * block_size;
                let end = (start + block_size).min(total.len());
                let more = end < total.len();

                let mut resp = Packet::new();
                resp.header.set_type(MessageType::Acknowledgement);
                resp.header.code = MessageClass::Response(ResponseType::Changed);
                resp.header.message_id = req.header.message_id;
                resp.set_token(req.get_token().to_vec());
                resp.add_option_as(
                    CoapOption::Block2,
                    BlockValue::new(num, more, block_size).unwrap(),
                );
                resp.payload = total[start..end].to_vec();
                responder
                    .send_to(&resp.to_bytes().unwrap(), peer)
                    .await
                    .unwrap();
                if !more {
                    break blocks_served;
                }
            }
        });

        let transport = UdpCoapTransport::connect(responder_addr).await.unwrap();
        let resp = transport.post(PATH_SECURE, &[0x09]).await.unwrap();
        assert_eq!(resp.code, (2, 4));
        assert_eq!(
            resp.payload, expected,
            "Block2 fragments must reassemble in order"
        );
        let blocks_served = task.await.unwrap();
        assert_eq!(blocks_served, 3, "700 bytes / 256 = 3 blocks requested");
    }

    #[test]
    fn code_classification() {
        let changed = CoapResponse {
            code: (2, 4),
            payload: vec![1, 2],
        };
        assert!(changed.is_changed() && !changed.is_not_found());
        assert_eq!(changed.clone().changed_payload().unwrap(), vec![1, 2]);

        let nf = CoapResponse {
            code: (4, 4),
            payload: vec![],
        };
        assert!(nf.is_not_found());
        assert!(matches!(
            nf.changed_payload(),
            Err(ThreadError::SessionExpired)
        ));

        let other = CoapResponse {
            code: (4, 0),
            payload: vec![],
        };
        assert!(matches!(
            other.changed_payload(),
            Err(ThreadError::CoapCode(_))
        ));
    }

    #[tokio::test]
    async fn mock_records_requests_and_returns_queued_responses() {
        let mock = MockCoapTransport::new();
        mock.queue_changed(vec![0xAA]);
        mock.queue(CoapResponse {
            code: (4, 4),
            payload: vec![],
        });

        let r1 = mock.post(PATH_PAIR_SETUP, &[0x01]).await.unwrap();
        assert!(r1.is_changed());
        assert_eq!(r1.payload, vec![0xAA]);

        let r2 = mock.post(PATH_SECURE, &[0x02, 0x03]).await.unwrap();
        assert!(r2.is_not_found());

        let reqs = mock.requests();
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0], ("1".to_string(), vec![0x01]));
        assert_eq!(reqs[1], (String::new(), vec![0x02, 0x03]));

        // Queue drained → next post errors rather than blocking.
        assert!(mock.post(PATH_SECURE, &[]).await.is_err());
    }
}
