//! The connected-accessory handle: secure characteristic I/O over CoAP.
//!
//! After Pair Verify, all traffic is HAP PDUs encrypted by the `CoapSession`
//! and POSTed to the root resource `/`. `SecureCoapConnection::post_secure`
//! is the single choke point (seal → POST → open); [`ThreadAccessory`] layers
//! characteristic reads/writes and the raw database read on top.
//!
//! Decoding the `0x09` database response into a typed [`hap_model`] tree is
//! deferred to hardware bring-up (it needs a captured accessory body to
//! cross-verify against — see the crate design doc); [`ThreadAccessory::read_database_raw`]
//! returns the decrypted `0x09` response bytes in the meantime, and reads/writes
//! address characteristics by instance id directly.

use std::sync::Arc;

use tokio::sync::Mutex;

use crate::coap::{CoapTransport, PATH_SECURE};
use crate::error::{Result, ThreadError};
use crate::pdu::{self, OpCode};
use crate::session::CoapSession;

/// A verified CoAP session bound to its transport: encrypt a request PDU, POST
/// it to `/`, decrypt the response.
pub(crate) struct SecureCoapConnection {
    transport: Arc<dyn CoapTransport>,
    session: Mutex<CoapSession>,
}

impl SecureCoapConnection {
    /// Wrap a transport and a freshly-verified session.
    pub(crate) fn new(transport: Arc<dyn CoapTransport>, session: CoapSession) -> Self {
        Self {
            transport,
            session: Mutex::new(session),
        }
    }

    /// Encrypt `pdu`, POST it to the root resource, and return the decrypted
    /// response PDU bytes.
    ///
    /// # Errors
    /// [`ThreadError::SessionExpired`] on a `4.04` (re-verify required), plus
    /// transport and AEAD failures.
    pub(crate) async fn post_secure(&self, pdu: &[u8]) -> Result<Vec<u8>> {
        let mut session = self.session.lock().await;
        let sealed = session.seal_request(pdu)?;
        let response = self
            .transport
            .post(PATH_SECURE, &sealed)
            .await?
            .changed_payload()?;
        session.open_response(&response)
    }

    /// Await one accessory-pushed event: receive its encrypted PUT, decrypt it on
    /// the event channel, and return the `(iid, value)` records it carries.
    ///
    /// # Errors
    /// Transport failures; [`ThreadError::Crypto`] if the event fails to
    /// authenticate (an event-counter desync); [`ThreadError`] if the record
    /// stream is malformed.
    pub(crate) async fn next_event(&self) -> Result<Vec<(u16, Vec<u8>)>> {
        let encrypted = self.transport.recv_event().await?;
        let plaintext = {
            let mut session = self.session.lock().await;
            session.open_event(&encrypted)?
        };
        pdu::decode_events(&plaintext)
    }
}

/// A connected HAP-over-Thread accessory: read and write its characteristics.
pub struct ThreadAccessory {
    conn: SecureCoapConnection,
}

impl ThreadAccessory {
    pub(crate) fn new(conn: SecureCoapConnection) -> Self {
        Self { conn }
    }

    /// Read one characteristic's raw value bytes by instance id.
    ///
    /// # Errors
    /// [`ThreadError::PduStatus`] if the accessory rejects the read, plus
    /// transport/crypto/PDU failures.
    pub async fn read_characteristic(&self, iid: u16) -> Result<Vec<u8>> {
        let values = self.read_characteristics(&[iid]).await?;
        values
            .into_iter()
            .next()
            .ok_or(ThreadError::MalformedPdu("empty read response"))?
    }

    /// Read several characteristics in one batched request. Each result is the
    /// characteristic's raw value bytes, or an error for that characteristic;
    /// results align with `iids` by position.
    ///
    /// # Errors
    /// Transport/crypto/PDU failures for the batch as a whole (per-characteristic
    /// HAP-status failures are reported in the returned `Vec`).
    pub async fn read_characteristics(&self, iids: &[u16]) -> Result<Vec<Result<Vec<u8>>>> {
        let entries: Vec<(u16, Vec<u8>)> = iids.iter().map(|&iid| (iid, Vec::new())).collect();
        let req = pdu::encode_all(OpCode::CharRead, &entries);
        let resp = self.conn.post_secure(&req).await?;
        let responses = pdu::decode_all(&resp)?;
        Ok(responses
            .into_iter()
            .map(|r| {
                if r.status == 0 {
                    r.value()
                } else {
                    Err(ThreadError::PduStatus(r.status))
                }
            })
            .collect())
    }

    /// Write one characteristic's raw value bytes by instance id.
    ///
    /// # Errors
    /// [`ThreadError::PduStatus`] if the accessory rejects the write, plus
    /// transport/crypto/PDU failures.
    pub async fn write_characteristic(&self, iid: u16, value: &[u8]) -> Result<()> {
        let body = pdu::encode_value_body(value);
        let req = pdu::encode_all(OpCode::CharWrite, &[(iid, body)]);
        let resp = self.conn.post_secure(&req).await?;
        let responses = pdu::decode_all(&resp)?;
        let first = responses
            .into_iter()
            .next()
            .ok_or(ThreadError::MalformedPdu("empty write response"))?;
        if first.status == 0 {
            Ok(())
        } else {
            Err(ThreadError::PduStatus(first.status))
        }
    }

    /// Read the accessory's entire attribute database (`0x09`), returning the
    /// decrypted response bytes. Decoding these into a typed [`hap_model`] tree
    /// is deferred to hardware bring-up (a captured body is needed to
    /// cross-verify the container nesting).
    ///
    /// # Errors
    /// Transport/crypto/PDU failures.
    pub async fn read_database_raw(&self) -> Result<Vec<u8>> {
        let req = pdu::encode_all(OpCode::ReadDatabase, &[(0x0000, Vec::new())]);
        let resp = self.conn.post_secure(&req).await?;
        let first = pdu::decode_all(&resp)?
            .into_iter()
            .next()
            .ok_or(ThreadError::MalformedPdu("empty database response"))?;
        if first.status == 0 {
            Ok(first.body)
        } else {
            Err(ThreadError::PduStatus(first.status))
        }
    }

    /// Read the accessory's attribute database and decode it into a typed
    /// [`hap_model`] tree ([`Accessory`](hap_model::Accessory) →
    /// [`Service`](hap_model::Service) →
    /// [`Characteristic`](hap_model::Characteristic)), giving each
    /// characteristic's instance id, HAP type, format, and permissions.
    ///
    /// # Errors
    /// Transport/crypto/PDU failures, or a malformed `0x09` structure.
    pub async fn read_database(&self) -> Result<Vec<hap_model::Accessory>> {
        let raw = self.read_database_raw().await?;
        crate::database::decode_database(&raw)
    }

    /// Subscribe to a characteristic's event notifications (a `0x0B` PDU). After
    /// this, the accessory pushes an encrypted PUT whenever the value changes;
    /// collect them with [`next_event`](Self::next_event).
    ///
    /// # Errors
    /// [`ThreadError::PduStatus`] if the accessory rejects the subscription, plus
    /// transport/crypto/PDU failures.
    pub async fn subscribe(&self, iid: u16) -> Result<()> {
        let req = pdu::encode_all(OpCode::Subscribe, &[(iid, Vec::new())]);
        let resp = self.conn.post_secure(&req).await?;
        let first = pdu::decode_all(&resp)?
            .into_iter()
            .next()
            .ok_or(ThreadError::MalformedPdu("empty subscribe response"))?;
        if first.status == 0 {
            Ok(())
        } else {
            Err(ThreadError::PduStatus(first.status))
        }
    }

    /// Unsubscribe from a characteristic's events (a `0x0C` PDU).
    ///
    /// # Errors
    /// [`ThreadError::PduStatus`] if the accessory rejects it, plus
    /// transport/crypto/PDU failures.
    pub async fn unsubscribe(&self, iid: u16) -> Result<()> {
        let req = pdu::encode_all(OpCode::Unsubscribe, &[(iid, Vec::new())]);
        let resp = self.conn.post_secure(&req).await?;
        let first = pdu::decode_all(&resp)?
            .into_iter()
            .next()
            .ok_or(ThreadError::MalformedPdu("empty unsubscribe response"))?;
        if first.status == 0 {
            Ok(())
        } else {
            Err(ThreadError::PduStatus(first.status))
        }
    }

    /// Await the next event the accessory pushes, returning `(iid, value)` for
    /// each characteristic that changed. Blocks until an event arrives.
    ///
    /// # Errors
    /// Transport/crypto failures, or a malformed event record stream.
    pub async fn next_event(&self) -> Result<Vec<(u16, Vec<u8>)>> {
        self.conn.next_event().await
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::items_after_statements)]
    use super::*;
    use crate::coap::{CoapResponse, CoapTransport};
    use crate::pdu::Response;
    use crate::session::CoapSession;
    use hap_crypto::SessionKeys;
    use std::sync::Mutex as StdMutex;

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap_or(0);
        }
        out
    }

    fn control_keys() -> SessionKeys {
        SessionKeys {
            read_key: hex32("c09403ef8aa6c5045cbd8cf9bf3e665b2caed623af2be0e87c8f80f519914d3d"),
            write_key: hex32("c3ca130c7033dbe5e7ff7f91d117ead869bac476994c7a48ca170c111136ed96"),
        }
    }

    /// A transport that answers each request by decrypting it with a mirrored
    /// "accessory" session, invoking a responder to build a response PDU, then
    /// encrypting that response back. Models a conformant accessory end-to-end.
    struct LoopbackTransport {
        acc: StdMutex<CoapSession>,
        responder: fn(&[u8]) -> Vec<u8>,
    }

    #[async_trait::async_trait]
    impl CoapTransport for LoopbackTransport {
        async fn post(&self, path: &str, payload: &[u8]) -> Result<CoapResponse> {
            assert_eq!(path, ""); // secure traffic goes to the root resource
            let mut acc = self.acc.lock().unwrap();
            let request_pdu = acc.open_response(payload).unwrap();
            let response_pdu = (self.responder)(&request_pdu);
            let sealed = acc.seal_request(&response_pdu).unwrap();
            Ok(CoapResponse {
                code: (2, 4),
                payload: sealed,
            })
        }

        async fn recv_event(&self) -> Result<Vec<u8>> {
            // This loopback models request/response only; event delivery is tested
            // separately via MockCoapTransport::queue_event.
            Err(ThreadError::Coap("loopback: no events".into()))
        }
    }

    /// Build a controller connection plus a loopback "accessory" using swapped
    /// keys (the accessory's write key is the controller's read key).
    fn connected(responder: fn(&[u8]) -> Vec<u8>) -> ThreadAccessory {
        let ctrl = CoapSession::new(&control_keys(), [0u8; 32]);
        let acc_keys = SessionKeys {
            read_key: control_keys().write_key,
            write_key: control_keys().read_key,
        };
        let transport = Arc::new(LoopbackTransport {
            acc: StdMutex::new(CoapSession::new(&acc_keys, [0u8; 32])),
            responder,
        });
        ThreadAccessory::new(SecureCoapConnection::new(transport, ctrl))
    }

    #[tokio::test]
    async fn secure_read_round_trip() {
        // The "accessory" returns a single response carrying value 0x2A.
        fn respond(_req: &[u8]) -> Vec<u8> {
            encode_ok_response(0, &pdu::encode_value_body(&[0x2A]))
        }
        let acc = connected(respond);
        let v = acc.read_characteristic(0x0010).await.unwrap();
        assert_eq!(v, vec![0x2A]);
    }

    #[tokio::test]
    async fn secure_write_round_trip_and_status_error() {
        fn respond_ok(_req: &[u8]) -> Vec<u8> {
            encode_ok_response(0, &[])
        }
        let acc = connected(respond_ok);
        assert!(acc.write_characteristic(0x0010, &[0x01]).await.is_ok());

        fn respond_err(_req: &[u8]) -> Vec<u8> {
            encode_status_response(0, 6) // invalid request
        }
        let acc = connected(respond_err);
        assert!(matches!(
            acc.write_characteristic(0x0010, &[0x01]).await,
            Err(ThreadError::PduStatus(6))
        ));
    }

    // --- small response-PDU builders for the loopback accessory ---
    fn encode_ok_response(tid: u8, body: &[u8]) -> Vec<u8> {
        encode_response(tid, 0, body)
    }
    fn encode_status_response(tid: u8, status: u8) -> Vec<u8> {
        encode_response(tid, status, &[])
    }
    fn encode_response(tid: u8, status: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![0x02, tid, status];
        let len = u16::try_from(body.len()).unwrap_or(0);
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(body);
        out
    }

    // Round-trip the Response builder through the decoder as a sanity anchor.
    #[test]
    fn response_builder_matches_decoder() {
        let bytes = encode_ok_response(3, &[0xEE]);
        let r: Response = pdu::decode_response(&bytes).unwrap();
        assert_eq!(r.tid, 3);
        assert_eq!(r.status, 0);
        assert_eq!(r.body, vec![0xEE]);
    }

    #[tokio::test]
    async fn subscribe_sends_a_0x0b_pdu_and_accepts_success() {
        fn respond(req: &[u8]) -> Vec<u8> {
            assert_eq!(req[1], 0x0B, "subscribe must use opcode 0x0B");
            encode_ok_response(0, &[])
        }
        let acc = connected(respond);
        assert!(acc.subscribe(3074).await.is_ok());
    }

    #[tokio::test]
    async fn next_event_decrypts_and_parses_records() {
        use crate::coap::MockCoapTransport;
        // The event key aiohomekit derives from shared secret 00..1f.
        let event_key = hex32("37c286d4ae336aeead7048a00b7762b642653d0e8aa691d4d3b7f0cf621db796");
        let session = CoapSession::new(&control_keys(), event_key);

        // One event record for iid 3074 (0x0C02): reserved, iid LE, len=3 LE,
        // body = a value TLV8 (type 0x01, len 1, value 0x01), sealed at event
        // counter 0 (nonce all-zero).
        let plaintext = vec![0x00, 0x02, 0x0c, 0x03, 0x00, 0x01, 0x01, 0x01];
        let sealed =
            hap_crypto::aead::chacha20poly1305_seal(&event_key, &[0u8; 12], &[], &plaintext)
                .unwrap();

        let mock = Arc::new(MockCoapTransport::new());
        mock.queue_event(sealed);
        let acc = ThreadAccessory::new(SecureCoapConnection::new(mock, session));

        let events = acc.next_event().await.unwrap();
        assert_eq!(events, vec![(3074u16, vec![0x01u8])]);
    }
}
