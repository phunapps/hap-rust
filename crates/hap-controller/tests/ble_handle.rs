//! Unified-handle behavior over the BLE variant, driven by hap-ble's mock.
#![allow(clippy::unwrap_used)] // test binary: failures are test failures

use hap_ble::test_support::{ble_accessory_with_db, MockGatt};
use hap_controller::{AccessoryHandle, HapError};
use hap_model::format::CharValue;
use std::sync::Arc;
use tokio_stream::StreamExt as _;

/// Seal `plain` exactly as the zero-key mock session expects, for the
/// `recv_counter`-th response the handle's `BleSession` will `open()`.
///
/// `BleSession::open` (crates/hap-ble/src/session.rs) derives the AEAD nonce
/// from a per-session receive counter that starts at 0 and advances by one on
/// every successful open — four zero bytes followed by the little-endian
/// counter. A handle that issues more than one encrypted request in a test
/// must seal each queued response at the matching counter, not a fixed
/// all-zero nonce.
fn sealed_at(counter: u64, plain: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    hap_crypto::aead::chacha20poly1305_seal(&[0u8; 32], &nonce, &[], plain).unwrap()
}

/// A sealed success PDU whose value param decodes to Bool(true), sealed for
/// the `recv_counter`-th response (see [`sealed_at`]).
///
/// The `vbody` bytes below are a TLV8 Value param (type 0x01, length 1,
/// payload 0x01) — matching `hap_ble::pdu::param::VALUE` and the layout
/// `encode_value_param` builds in hap-ble's own tests (verified against
/// `crates/hap-ble/src/pdu.rs`).
fn sealed_bool_true_read(counter: u64) -> Vec<u8> {
    let mut plain = vec![0x02, 0x01, 0x00];
    let vbody = {
        // TLV 0x01 (value param), length 1, payload 0x01 — matches the
        // encode_value_param layout hap-ble's own tests build.
        vec![0x01, 0x01, 0x01]
    };
    plain.extend_from_slice(&u16::try_from(vbody.len()).unwrap().to_le_bytes());
    plain.extend_from_slice(&vbody);
    sealed_at(counter, &plain)
}

async fn ble_handle() -> (AccessoryHandle, Arc<MockGatt>) {
    let (acc, gatt) = ble_accessory_with_db().await;
    (AccessoryHandle::from_ble_for_tests(acc), gatt)
}

#[tokio::test]
async fn read_and_write_dispatch_to_ble() {
    let (mut h, gatt) = ble_handle().await;
    gatt.queue_read(
        "00000025-0000-1000-8000-0026bb765291",
        sealed_bool_true_read(0),
    );
    assert_eq!(h.read(1, 11).await.unwrap(), CharValue::Bool(true));
    // The handle's BleSession recv_counter advanced to 1 after the read above;
    // this second response must be sealed at counter 1 (see `sealed_at`).
    gatt.queue_read(
        "00000025-0000-1000-8000-0026bb765291",
        sealed_at(1, &[0x02, 0x02, 0x00]),
    );
    h.write(1, 11, CharValue::Bool(false)).await.unwrap();
}

#[tokio::test]
async fn unsupported_ops_name_themselves() {
    let (mut h, _g) = ble_handle().await;
    for (name, err) in [
        ("unsubscribe", h.unsubscribe(1, 11).await.unwrap_err()),
        (
            "write_timed",
            h.write_timed(
                1,
                11,
                CharValue::Bool(true),
                std::time::Duration::from_secs(1),
            )
            .await
            .unwrap_err(),
        ),
    ] {
        match err {
            HapError::UnsupportedByTransport(op) => assert_eq!(op, name),
            other => panic!("expected UnsupportedByTransport, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn subscribe_then_notification_yields_unified_event() {
    let (mut h, gatt) = ble_handle().await;
    gatt.queue_read(
        "00000025-0000-1000-8000-0026bb765291",
        sealed_bool_true_read(0),
    );
    h.subscribe(1, 11).await.unwrap();
    let mut events = h.events();
    gatt.notifier("00000025-0000-1000-8000-0026bb765291")
        .unwrap()
        .send(Vec::new())
        .await
        .unwrap();
    let ev = events.next().await.unwrap();
    assert_eq!((ev.aid, ev.iid), (1, 11));
    assert_eq!(ev.value, CharValue::Bool(true));
}

#[tokio::test]
async fn read_many_loops_sequentially_over_ble() {
    let (mut h, gatt) = ble_handle().await;
    gatt.queue_read(
        "00000025-0000-1000-8000-0026bb765291",
        sealed_bool_true_read(0),
    );
    let out = h.read_many(&[(1, 11)]).await.unwrap();
    assert_eq!(out, vec![((1, 11), CharValue::Bool(true))]);
}
