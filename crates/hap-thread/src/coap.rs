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
/// Maximum Confirmable transmissions before giving up (RFC 7252 default is 4).
const MAX_TRANSMISSIONS: u32 = 4;
/// Receive buffer for a single CoAP datagram.
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
/// This performs a basic Confirmable exchange (retransmit-until-ack, matching on
/// message id). It does **not** yet implement CoAP block-wise transfer (RFC
/// 7959); a large `0x09` database response that the accessory delivers in
/// blocks will need Block2 reassembly added at hardware bring-up.
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
}

#[async_trait]
impl CoapTransport for UdpCoapTransport {
    async fn post(&self, path: &str, payload: &[u8]) -> Result<CoapResponse> {
        let mid = self.next_message_id();
        let mut packet = Packet::new();
        packet.header.set_type(MessageType::Confirmable);
        packet.header.code = MessageClass::Request(RequestType::Post);
        packet.header.message_id = mid;
        packet.set_token(mid.to_be_bytes().to_vec());
        // HAP uses single-segment resource paths; the root ("") carries no
        // Uri-Path option.
        if !path.is_empty() {
            packet.add_option(CoapOption::UriPath, path.as_bytes().to_vec());
        }
        packet.payload = payload.to_vec();
        let bytes = packet
            .to_bytes()
            .map_err(|e| ThreadError::Coap(format!("could not encode CoAP request: {e}")))?;

        let mut buf = vec![0u8; RECV_BUF];
        for _ in 0..MAX_TRANSMISSIONS {
            self.socket.send(&bytes).await?;
            match tokio::time::timeout(ACK_TIMEOUT, self.socket.recv(&mut buf)).await {
                Ok(Ok(n)) => {
                    let resp = Packet::from_bytes(&buf[..n]).map_err(|e| {
                        ThreadError::Coap(format!("could not decode CoAP response: {e}"))
                    })?;
                    // Piggy-backed ACK echoes the request message id.
                    if resp.header.message_id != mid {
                        continue;
                    }
                    let code_byte = u8::from(resp.header.code);
                    return Ok(CoapResponse {
                        code: (code_byte >> 5, code_byte & 0x1f),
                        payload: resp.payload,
                    });
                }
                Ok(Err(e)) => return Err(ThreadError::Io(e)),
                Err(_elapsed) => {} // ack timeout — fall through to retransmit
            }
        }
        Err(ThreadError::Coap(
            "no CoAP response after maximum retransmissions".into(),
        ))
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
